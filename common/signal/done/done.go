package done

import (
	"sync"
)

// Instance is a utility for notifications of something being done.
type Instance struct {
	access sync.Mutex
	c      chan struct{}
	closed bool
}

// instancePool pools Instance objects to reduce allocations
var instancePool = sync.Pool{
	New: func() interface{} {
		return &Instance{
			c: make(chan struct{}),
		}
	},
}

// New returns a new Done.
func New() *Instance {
	d := instancePool.Get().(*Instance)
	// Reset instance if it was previously used
	if d.closed {
		d.c = make(chan struct{})
		d.closed = false
	}
	return d
}

// Release returns the Instance to the pool for reuse.
// This should only be called after Close() has been called.
// After calling Release, the Instance should not be used anymore.
func (d *Instance) Release() {
	// Only return to pool if closed
	if d.closed {
		instancePool.Put(d)
	}
}

// Done returns true if Close() is called.
func (d *Instance) Done() bool {
	select {
	case <-d.Wait():
		return true
	default:
		return false
	}
}

// Wait returns a channel for waiting for done.
func (d *Instance) Wait() <-chan struct{} {
	return d.c
}

// Close marks this Done 'done'. This method may be called multiple times. All calls after first call will have no effect on its status.
func (d *Instance) Close() error {
	d.access.Lock()
	defer d.access.Unlock()

	if d.closed {
		return nil
	}

	d.closed = true
	close(d.c)

	return nil
}
