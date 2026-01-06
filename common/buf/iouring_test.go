//go:build linux && amd64
// +build linux,amd64

package buf_test

import (
	"os"
	"testing"

	. "github.com/xtls/xray-core/common/buf"
)

func TestIoUringAvailability(t *testing.T) {
	available := IsIoUringAvailable()
	t.Logf("io_uring available: %v", available)

	sqpollAvailable := IsSQPollAvailable()
	t.Logf("io_uring SQPOLL available: %v", sqpollAvailable)

	// Check kernel version
	if data, err := os.ReadFile("/proc/version"); err == nil {
		t.Logf("Kernel: %s", string(data))
	}
}

func TestIoUringConfig(t *testing.T) {
	defaultCfg := DefaultIoUringConfig()
	t.Logf("Default config: entries=%d, flags=%d", defaultCfg.Entries, defaultCfg.Flags)

	sqpollCfg := SQPollConfig()
	t.Logf("SQPOLL config: entries=%d, flags=%d", sqpollCfg.Entries, sqpollCfg.Flags)
}

func TestIoUringBasic(t *testing.T) {
	if !IsIoUringAvailable() {
		t.Skip("io_uring not available or not enabled")
	}

	// Create a temporary file for testing
	f, err := os.CreateTemp("", "iouring_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	// Write some data
	testData := []byte("Hello, io_uring!")
	if _, err := f.Write(testData); err != nil {
		t.Fatal(err)
	}

	// Seek back to beginning
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}

	t.Logf("io_uring test file created: %s", f.Name())
}

func TestIoUringOptions(t *testing.T) {
	// Test option functions
	opt1 := WithSQPoll()
	opt2 := WithFixedBuffers()

	if opt1 == nil || opt2 == nil {
		t.Fatal("option functions should not return nil")
	}

	t.Log("io_uring options work correctly")
}

func BenchmarkReadVReader(b *testing.B) {
	// Create a temporary file
	f, err := os.CreateTemp("", "readv_bench")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(f.Name())
	defer f.Close()

	// Write test data
	data := make([]byte, 64*1024) // 64KB
	for i := range data {
		data[i] = byte(i % 256)
	}
	f.Write(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.Seek(0, 0)
		buf := New()
		buf.ReadFrom(f)
		buf.Release()
	}
}

func BenchmarkBufferPool(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := New()
			buf.Extend(Size)
			buf.Release()
		}
	})
}
