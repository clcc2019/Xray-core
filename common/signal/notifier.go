package signal

import "sync"

// Notifier is a utility for notifying changes. The change producer may notify changes multiple time, and the consumer may get notified asynchronously.
type Notifier struct {
	c chan struct{}
}

// notifierPool pools Notifier instances to reduce allocations.
var notifierPool = sync.Pool{
	New: func() interface{} {
		return &Notifier{
			c: make(chan struct{}, 1),
		}
	},
}

// NewNotifier creates a new Notifier.
func NewNotifier() *Notifier {
	return notifierPool.Get().(*Notifier)
}

// Release returns the Notifier to the pool for reuse.
// After calling Release, the Notifier should not be used anymore.
func (n *Notifier) Release() {
	// Drain the channel before returning to pool
	select {
	case <-n.c:
	default:
	}
	notifierPool.Put(n)
}

// Signal signals a change, usually by producer. This method never blocks.
func (n *Notifier) Signal() {
	select {
	case n.c <- struct{}{}:
	default:
	}
}

// Wait returns a channel for waiting for changes. The returned channel never gets closed.
func (n *Notifier) Wait() <-chan struct{} {
	return n.c
}
