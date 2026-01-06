//go:build !linux || !amd64
// +build !linux !amd64

package buf

import (
	"io"
	"syscall"

	"github.com/xtls/xray-core/common/errors"
)

// IoUring is not available on non-Linux platforms
type IoUring struct{}

// IoUringConfig stub
type IoUringConfig struct {
	Entries      uint32
	Flags        uint32
	SQThreadCPU  uint32
	SQThreadIdle uint32
}

// DefaultIoUringConfig returns default configuration
func DefaultIoUringConfig() IoUringConfig {
	return IoUringConfig{}
}

// SQPollConfig returns SQPOLL configuration
func SQPollConfig() IoUringConfig {
	return IoUringConfig{}
}

// IsIoUringAvailable returns false on non-Linux platforms
func IsIoUringAvailable() bool {
	return false
}

// IsSQPollAvailable returns false on non-Linux platforms
func IsSQPollAvailable() bool {
	return false
}

// IoUringReaderOption stub
type IoUringReaderOption func(*IoUringReader)

// WithSQPoll stub
func WithSQPoll() IoUringReaderOption {
	return func(r *IoUringReader) {}
}

// WithFixedBuffers stub
func WithFixedBuffers() IoUringReaderOption {
	return func(r *IoUringReader) {}
}

// IoUringReader stub for non-Linux platforms
type IoUringReader struct {
	io.Reader
}

// NewIoUringReader returns an error on non-Linux platforms
func NewIoUringReader(reader io.Reader, rawConn syscall.RawConn, opts ...IoUringReaderOption) (*IoUringReader, error) {
	return nil, errors.New("io_uring not supported on this platform")
}

// ReadMultiBuffer is not implemented on non-Linux platforms
func (r *IoUringReader) ReadMultiBuffer() (MultiBuffer, error) {
	return nil, errors.New("io_uring not supported")
}

// Release is a no-op on non-Linux platforms
func (r *IoUringReader) Release() {}

// IoUringWriter stub for non-Linux platforms
type IoUringWriter struct {
	io.Writer
}

// NewIoUringWriter returns an error on non-Linux platforms
func NewIoUringWriter(writer io.Writer, rawConn syscall.RawConn, opts ...IoUringReaderOption) (*IoUringWriter, error) {
	return nil, errors.New("io_uring not supported on this platform")
}

// WriteMultiBuffer is not implemented on non-Linux platforms
func (w *IoUringWriter) WriteMultiBuffer(mb MultiBuffer) error {
	return errors.New("io_uring not supported")
}

// Release is a no-op on non-Linux platforms
func (w *IoUringWriter) Release() {}
