package pipe

import (
	"sync/atomic"

	"github.com/xtls/xray-core/common/buf"
)

// Writer is a buf.Writer that writes data into a pipe.
type Writer struct {
	pipe     *pipe
	released atomic.Bool
}

// WriteMultiBuffer implements buf.Writer.
func (w *Writer) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return w.pipe.WriteMultiBuffer(mb)
}

// Close implements io.Closer. After the pipe is closed, writing to the pipe will return io.ErrClosedPipe, while reading will return io.EOF.
func (w *Writer) Close() error {
	return w.pipe.Close()
}

func (w *Writer) Len() int32 {
	return w.pipe.Len()
}

// Interrupt implements common.Interruptible.
func (w *Writer) Interrupt() {
	w.pipe.Interrupt()
}

// Release returns the underlying pipe to the pool.
// This should only be called when both Reader and Writer are done.
// After calling Release, the Writer should not be used anymore.
func (w *Writer) Release() {
	if w.released.CompareAndSwap(false, true) {
		w.pipe.Release()
	}
}
