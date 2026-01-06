package pipe

import (
	"errors"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/signal/done"
)

type state byte

const (
	open state = iota
	closed
	errord
)

type pipeOption struct {
	limit           int32 // maximum buffer size in bytes
	discardOverflow bool
}

func (o *pipeOption) isFull(curSize int32) bool {
	return o.limit >= 0 && curSize > o.limit
}

// pipe is the core data structure for bidirectional data transfer.
// Optimizations:
// - Atomic state for lock-free fast path checks
// - Spin-wait before blocking to reduce context switches
// - Object pooling for pipe instances
type pipe struct {
	sync.Mutex
	data        buf.MultiBuffer
	readSignal  *signal.Notifier
	writeSignal *signal.Notifier
	done        *done.Instance
	errChan     chan error
	option      pipeOption
	state       state
	dataLen     atomic.Int32 // cached data length for lock-free reads
	stateVal    atomic.Int32 // atomic state for lock-free checks: 0=open, 1=closed, 2=errord
}

var (
	errBufferFull = errors.New("buffer full")
	errSlowDown   = errors.New("slow down")
)

// pipePool pools pipe instances to reduce allocations
var pipePool = sync.Pool{
	New: func() interface{} {
		return &pipe{
			errChan: make(chan error, 1),
		}
	},
}

// errChanPool pools error channels
var errChanPool = sync.Pool{
	New: func() interface{} {
		return make(chan error, 1)
	},
}

// acquirePipe gets a pipe from the pool
func acquirePipe() *pipe {
	p := pipePool.Get().(*pipe)
	return p
}

// releasePipe returns a pipe to the pool after cleanup
func releasePipe(p *pipe) {
	// Release internal resources back to their pools
	if p.readSignal != nil {
		p.readSignal.Release()
		p.readSignal = nil
	}
	if p.writeSignal != nil {
		p.writeSignal.Release()
		p.writeSignal = nil
	}
	if p.done != nil {
		p.done.Release()
		p.done = nil
	}

	// Drain and reuse errChan
	select {
	case <-p.errChan:
	default:
	}

	// Clear data
	if p.data != nil {
		buf.ReleaseMulti(p.data)
		p.data = nil
	}

	// Reset state
	p.state = open
	p.stateVal.Store(0)
	p.dataLen.Store(0)
	p.option = pipeOption{limit: -1}

	pipePool.Put(p)
}

// Len returns the current data length without acquiring the lock.
// This is an optimization for frequent length checks.
func (p *pipe) Len() int32 {
	return p.dataLen.Load()
}

// hasData returns true if there's data available without acquiring the lock.
// This is used for fast-path optimization in read operations.
func (p *pipe) hasData() bool {
	return p.dataLen.Load() > 0
}

// isClosed returns true if pipe is closed or errored (lock-free check)
func (p *pipe) isClosed() bool {
	return p.stateVal.Load() != 0
}

func (p *pipe) getState(forRead bool) error {
	switch p.state {
	case open:
		if !forRead && p.option.isFull(p.data.Len()) {
			return errBufferFull
		}
		return nil
	case closed:
		if !forRead {
			return io.ErrClosedPipe
		}
		if !p.data.IsEmpty() {
			return nil
		}
		return io.EOF
	case errord:
		return io.ErrClosedPipe
	default:
		panic("impossible case")
	}
}

// spinWait performs a brief spin-wait before blocking.
// This reduces context switches for short waits.
const spinIterations = 4

func spinWait() {
	for i := 0; i < spinIterations; i++ {
		runtime.Gosched()
	}
}

func (p *pipe) readMultiBufferInternal() (buf.MultiBuffer, error) {
	p.Lock()
	defer p.Unlock()

	if err := p.getState(true); err != nil {
		return nil, err
	}

	data := p.data
	p.data = nil
	p.dataLen.Store(0)
	return data, nil
}

// tryReadFast attempts a lock-free fast-path read check.
// Returns true if data might be available and a full read should be attempted.
func (p *pipe) tryReadFast() bool {
	// Fast path: check if there's data without lock
	if p.hasData() {
		return true
	}
	// Check if pipe is closed (might have EOF)
	if p.isClosed() {
		return true
	}
	return false
}

func (p *pipe) ReadMultiBuffer() (buf.MultiBuffer, error) {
	// Fast path: try immediate read if data available
	if p.tryReadFast() {
		data, err := p.readMultiBufferInternal()
		if data != nil || err != nil {
			p.writeSignal.Signal()
			return data, err
		}
	}

	for {
		data, err := p.readMultiBufferInternal()
		if data != nil || err != nil {
			p.writeSignal.Signal()
			return data, err
		}

		// Spin-wait before blocking to reduce context switches
		spinWait()

		// Check again after spin
		if p.tryReadFast() {
			continue
		}

		select {
		case <-p.readSignal.Wait():
		case <-p.done.Wait():
		case err = <-p.errChan:
			return nil, err
		}
	}
}

func (p *pipe) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	// Fast path: try immediate read if data available
	if p.tryReadFast() {
		data, err := p.readMultiBufferInternal()
		if data != nil || err != nil {
			p.writeSignal.Signal()
			return data, err
		}
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	for {
		data, err := p.readMultiBufferInternal()
		if data != nil || err != nil {
			p.writeSignal.Signal()
			return data, err
		}

		// Spin-wait before blocking
		spinWait()

		// Check again after spin
		if p.tryReadFast() {
			continue
		}

		select {
		case <-p.readSignal.Wait():
		case <-p.done.Wait():
		case <-timer.C:
			return nil, buf.ErrReadTimeout
		}
	}
}

func (p *pipe) writeMultiBufferInternal(mb buf.MultiBuffer) error {
	p.Lock()
	defer p.Unlock()

	if err := p.getState(false); err != nil {
		return err
	}

	if p.data == nil {
		p.data = mb
		p.dataLen.Store(mb.Len())
		return nil
	}

	p.data, _ = buf.MergeMulti(p.data, mb)
	p.dataLen.Store(p.data.Len())
	return errSlowDown
}

// tryWriteFast checks if a write can proceed without blocking (lock-free check)
func (p *pipe) tryWriteFast() bool {
	// Fast check: if closed, don't bother
	if p.isClosed() {
		return true // Will return error in writeMultiBufferInternal
	}
	// If no limit or under limit, can write
	if p.option.limit < 0 {
		return true
	}
	return p.dataLen.Load() <= p.option.limit
}

func (p *pipe) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}

	// Fast path: try immediate write
	if p.tryWriteFast() {
		err := p.writeMultiBufferInternal(mb)
		if err == nil {
			p.readSignal.Signal()
			return nil
		}

		if err == errSlowDown {
			p.readSignal.Signal()
			runtime.Gosched()
			return nil
		}

		if err == errBufferFull && p.option.discardOverflow {
			buf.ReleaseMulti(mb)
			return nil
		}

		if err != errBufferFull {
			buf.ReleaseMulti(mb)
			p.readSignal.Signal()
			return err
		}
	}

	for {
		err := p.writeMultiBufferInternal(mb)
		if err == nil {
			p.readSignal.Signal()
			return nil
		}

		if err == errSlowDown {
			p.readSignal.Signal()

			// Yield current goroutine. Hopefully the reading counterpart can pick up the payload.
			runtime.Gosched()
			return nil
		}

		if err == errBufferFull && p.option.discardOverflow {
			buf.ReleaseMulti(mb)
			return nil
		}

		if err != errBufferFull {
			buf.ReleaseMulti(mb)
			p.readSignal.Signal()
			return err
		}

		// Spin-wait before blocking
		spinWait()

		// Check again after spin
		if p.tryWriteFast() {
			continue
		}

		select {
		case <-p.writeSignal.Wait():
		case <-p.done.Wait():
			return io.ErrClosedPipe
		}
	}
}

func (p *pipe) Close() error {
	p.Lock()
	defer p.Unlock()

	if p.state == closed || p.state == errord {
		return nil
	}

	p.state = closed
	p.stateVal.Store(1) // Update atomic state
	common.Must(p.done.Close())
	return nil
}

// Interrupt implements common.Interruptible.
func (p *pipe) Interrupt() {
	p.Lock()
	defer p.Unlock()

	if !p.data.IsEmpty() {
		buf.ReleaseMulti(p.data)
		p.data = nil
		p.dataLen.Store(0)
		if p.state == closed {
			p.state = errord
			p.stateVal.Store(2)
		}
	}

	if p.state == closed || p.state == errord {
		return
	}

	p.state = errord
	p.stateVal.Store(2) // Update atomic state

	common.Must(p.done.Close())
}

// Release returns the pipe resources to pools.
// Should be called when the pipe is no longer needed.
func (p *pipe) Release() {
	releasePipe(p)
}
