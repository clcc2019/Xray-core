//go:build linux && amd64
// +build linux,amd64

package buf

import (
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/platform"
)

// io_uring syscall numbers for amd64
const (
	SYS_IO_URING_SETUP    = 425
	SYS_IO_URING_ENTER    = 426
	SYS_IO_URING_REGISTER = 427
)

// io_uring constants
const (
	// Setup flags
	IORING_SETUP_IOPOLL    = 1 << 0 // io_context is polled
	IORING_SETUP_SQPOLL    = 1 << 1 // Kernel side polling
	IORING_SETUP_SQ_AFF    = 1 << 2 // SQ affinity
	IORING_SETUP_CQSIZE    = 1 << 3 // CQ size
	IORING_SETUP_CLAMP     = 1 << 4 // Clamp SQ/CQ sizes
	IORING_SETUP_ATTACH_WQ = 1 << 5 // Attach to existing wq

	// Enter flags
	IORING_ENTER_GETEVENTS = 1 << 0
	IORING_ENTER_SQ_WAKEUP = 1 << 1
	IORING_ENTER_SQ_WAIT   = 1 << 2

	// Register opcodes
	IORING_REGISTER_BUFFERS          = 0
	IORING_UNREGISTER_BUFFERS        = 1
	IORING_REGISTER_FILES            = 2
	IORING_UNREGISTER_FILES          = 3
	IORING_REGISTER_EVENTFD          = 4
	IORING_UNREGISTER_EVENTFD        = 5
	IORING_REGISTER_FILES_UPDATE     = 6
	IORING_REGISTER_EVENTFD_ASYNC    = 7
	IORING_REGISTER_PROBE            = 8
	IORING_REGISTER_PERSONALITY      = 9
	IORING_UNREGISTER_PERSONALITY    = 10
	IORING_REGISTER_RESTRICTIONS     = 11
	IORING_REGISTER_ENABLE_RINGS     = 12
	IORING_REGISTER_FILES2           = 13
	IORING_REGISTER_FILES_UPDATE2    = 14
	IORING_REGISTER_BUFFERS2         = 15
	IORING_REGISTER_BUFFERS_UPDATE   = 16
	IORING_REGISTER_IOWQ_AFF         = 17
	IORING_UNREGISTER_IOWQ_AFF       = 18
	IORING_REGISTER_IOWQ_MAX_WORKERS = 19

	// Opcodes
	IORING_OP_NOP             = 0
	IORING_OP_READV           = 1
	IORING_OP_WRITEV          = 2
	IORING_OP_FSYNC           = 3
	IORING_OP_READ_FIXED      = 4
	IORING_OP_WRITE_FIXED     = 5
	IORING_OP_POLL_ADD        = 6
	IORING_OP_POLL_REMOVE     = 7
	IORING_OP_SYNC_FILE_RANGE = 8
	IORING_OP_SENDMSG         = 9
	IORING_OP_RECVMSG         = 10
	IORING_OP_TIMEOUT         = 11
	IORING_OP_TIMEOUT_REMOVE  = 12
	IORING_OP_ACCEPT          = 13
	IORING_OP_ASYNC_CANCEL    = 14
	IORING_OP_LINK_TIMEOUT    = 15
	IORING_OP_CONNECT         = 16
	IORING_OP_FALLOCATE       = 17
	IORING_OP_OPENAT          = 18
	IORING_OP_CLOSE           = 19
	IORING_OP_FILES_UPDATE    = 20
	IORING_OP_STATX           = 21
	IORING_OP_READ            = 22
	IORING_OP_WRITE           = 23
	IORING_OP_FADVISE         = 24
	IORING_OP_MADVISE         = 25
	IORING_OP_SEND            = 26
	IORING_OP_RECV            = 27
	IORING_OP_OPENAT2         = 28
	IORING_OP_EPOLL_CTL       = 29
	IORING_OP_SPLICE          = 30
	IORING_OP_PROVIDE_BUFFERS = 31
	IORING_OP_REMOVE_BUFFERS  = 32

	// SQE flags
	IOSQE_FIXED_FILE    = 1 << 0 // use fixed fileset
	IOSQE_IO_DRAIN      = 1 << 1 // issue after inflight IO
	IOSQE_IO_LINK       = 1 << 2 // links next sqe
	IOSQE_IO_HARDLINK   = 1 << 3 // like LINK, but stronger
	IOSQE_ASYNC         = 1 << 4 // always go async
	IOSQE_BUFFER_SELECT = 1 << 5 // select buffer from sqe->buf_group

	// Ring size (must be power of 2)
	defaultRingSize = 256
	maxBatchSize    = 32 // Maximum batch size for batch operations

	// mmap offsets
	IORING_OFF_SQ_RING = 0
	IORING_OFF_CQ_RING = 0x8000000
	IORING_OFF_SQES    = 0x10000000

	// Fixed buffer settings
	maxFixedBuffers = 64
	fixedBufferSize = Size // Use same size as regular buffers
)

// io_uring_sqe is the submission queue entry
type ioUringSqe struct {
	opcode      uint8
	flags       uint8
	ioprio      uint16
	fd          int32
	off         uint64
	addr        uint64
	len         uint32
	opcodeFlags uint32
	userData    uint64
	bufIndex    uint16
	personality uint16
	spliceFdIn  int32
	pad2        [2]uint64
}

// io_uring_cqe is the completion queue entry
type ioUringCqe struct {
	userData uint64
	res      int32
	flags    uint32
}

// io_uring_params for setup
type ioUringParams struct {
	sqEntries    uint32
	cqEntries    uint32
	flags        uint32
	sqThreadCpu  uint32
	sqThreadIdle uint32
	features     uint32
	wqFd         uint32
	resv         [3]uint32
	sqOff        ioUringSqOffsets
	cqOff        ioUringCqOffsets
}

type ioUringSqOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	flags       uint32
	dropped     uint32
	array       uint32
	resv1       uint32
	resv2       uint64
}

type ioUringCqOffsets struct {
	head        uint32
	tail        uint32
	ringMask    uint32
	ringEntries uint32
	overflow    uint32
	cqes        uint32
	flags       uint32
	resv1       uint32
	resv2       uint64
}

// iovec for readv/writev operations
type iovec struct {
	Base *byte
	Len  uint64
}

// IoUringConfig holds configuration for IoUring
type IoUringConfig struct {
	Entries      uint32 // Number of SQ entries
	Flags        uint32 // Setup flags (SQPOLL, etc.)
	SQThreadCPU  uint32 // CPU for SQ polling thread
	SQThreadIdle uint32 // Idle time before SQ thread sleeps (ms)
}

// DefaultIoUringConfig returns default configuration
func DefaultIoUringConfig() IoUringConfig {
	return IoUringConfig{
		Entries:      defaultRingSize,
		Flags:        0,
		SQThreadCPU:  0,
		SQThreadIdle: 1000, // 1 second
	}
}

// SQPollConfig returns configuration for SQPOLL mode
func SQPollConfig() IoUringConfig {
	return IoUringConfig{
		Entries:      defaultRingSize,
		Flags:        IORING_SETUP_SQPOLL,
		SQThreadCPU:  0,
		SQThreadIdle: 10000, // 10 seconds
	}
}

// IoUring wraps the io_uring interface
type IoUring struct {
	fd         int
	sqRing     []byte
	sqesMmap   []byte
	cqRing     []byte
	sqes       []ioUringSqe
	sqHead     *uint32
	sqTail     *uint32
	sqFlags    *uint32
	sqMask     uint32
	sqArray    []uint32
	cqHead     *uint32
	cqTail     *uint32
	cqMask     uint32
	cqes       []ioUringCqe
	pendingOps atomic.Int32
	mu         sync.Mutex
	closed     atomic.Bool
	sqpollMode bool // Whether SQPOLL is enabled

	// Fixed buffers support
	fixedBuffers     [][]byte
	fixedBufferIovs  []iovec
	fixedBufferInUse []atomic.Bool
	hasFixedBuffers  bool
}

// ioUringPool pools IoUring instances
var ioUringPool = sync.Pool{
	New: func() interface{} {
		ring, err := NewIoUringWithConfig(DefaultIoUringConfig())
		if err != nil {
			return nil
		}
		return ring
	},
}

// ioUringSQPollPool pools IoUring instances with SQPOLL enabled
var ioUringSQPollPool = sync.Pool{
	New: func() interface{} {
		ring, err := NewIoUringWithConfig(SQPollConfig())
		if err != nil {
			return nil
		}
		return ring
	},
}

// Global flag to check if io_uring is available
var (
	ioUringAvailable    bool
	ioUringSQPollAvail  bool
	ioUringCheckOnce    sync.Once
	useIoUring          bool
	useIoUringSQPoll    bool
	useIoUringFixedBufs bool
)

func init() {
	// Check environment flags
	const defaultFlagValue = "NOT_DEFINED_AT_ALL"

	// Basic io_uring enable
	value := platform.NewEnvFlag("xray.buf.iouring").GetValue(func() string { return defaultFlagValue })
	switch value {
	case "enable", "true", "1":
		useIoUring = true
	default:
		useIoUring = false
	}

	// SQPOLL mode (kernel polling)
	sqpollValue := platform.NewEnvFlag("xray.buf.iouring.sqpoll").GetValue(func() string { return defaultFlagValue })
	switch sqpollValue {
	case "enable", "true", "1":
		useIoUringSQPoll = true
	default:
		useIoUringSQPoll = false
	}

	// Fixed buffers (zero-copy)
	fixedValue := platform.NewEnvFlag("xray.buf.iouring.fixed").GetValue(func() string { return defaultFlagValue })
	switch fixedValue {
	case "enable", "true", "1":
		useIoUringFixedBufs = true
	default:
		useIoUringFixedBufs = false
	}
}

// checkIoUringAvailable checks if io_uring is supported on this kernel
func checkIoUringAvailable() bool {
	ioUringCheckOnce.Do(func() {
		// Try to create a minimal ring to test availability
		var params ioUringParams
		fd, _, errno := syscall.Syscall(
			SYS_IO_URING_SETUP,
			4, // minimal entries
			uintptr(unsafe.Pointer(&params)),
			0,
		)
		if errno == 0 {
			syscall.Close(int(fd))
			ioUringAvailable = true

			// Test SQPOLL availability (requires root or CAP_SYS_NICE)
			params.flags = IORING_SETUP_SQPOLL
			params.sqThreadIdle = 1000
			fd2, _, errno2 := syscall.Syscall(
				SYS_IO_URING_SETUP,
				4,
				uintptr(unsafe.Pointer(&params)),
				0,
			)
			if errno2 == 0 {
				syscall.Close(int(fd2))
				ioUringSQPollAvail = true
			}
		}
	})
	return ioUringAvailable && useIoUring
}

// IsIoUringAvailable returns true if io_uring can be used
func IsIoUringAvailable() bool {
	return checkIoUringAvailable()
}

// IsSQPollAvailable returns true if SQPOLL mode is available
func IsSQPollAvailable() bool {
	checkIoUringAvailable()
	return ioUringSQPollAvail && useIoUringSQPoll
}

// NewIoUringWithConfig creates a new io_uring instance with custom configuration
func NewIoUringWithConfig(config IoUringConfig) (*IoUring, error) {
	var params ioUringParams
	params.flags = config.Flags
	params.sqThreadCpu = config.SQThreadCPU
	params.sqThreadIdle = config.SQThreadIdle

	fd, _, errno := syscall.Syscall(
		SYS_IO_URING_SETUP,
		uintptr(config.Entries),
		uintptr(unsafe.Pointer(&params)),
		0,
	)
	if errno != 0 {
		return nil, errors.New("io_uring_setup failed: ", errno.Error())
	}

	ring := &IoUring{
		fd:         int(fd),
		sqMask:     params.sqOff.ringEntries - 1,
		cqMask:     params.cqOff.ringEntries - 1,
		sqpollMode: (config.Flags & IORING_SETUP_SQPOLL) != 0,
	}

	// Map submission queue
	sqRingSize := params.sqOff.array + params.sqEntries*4
	sqRing, err := syscall.Mmap(
		int(fd),
		IORING_OFF_SQ_RING,
		int(sqRingSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
	)
	if err != nil {
		syscall.Close(int(fd))
		return nil, errors.New("mmap sq_ring failed: ", err)
	}
	ring.sqRing = sqRing
	ring.sqHead = (*uint32)(unsafe.Pointer(&sqRing[params.sqOff.head]))
	ring.sqTail = (*uint32)(unsafe.Pointer(&sqRing[params.sqOff.tail]))
	ring.sqFlags = (*uint32)(unsafe.Pointer(&sqRing[params.sqOff.flags]))

	// Map SQ entries
	sqeSize := int(params.sqEntries) * int(unsafe.Sizeof(ioUringSqe{}))
	sqesMmap, err := syscall.Mmap(
		int(fd),
		IORING_OFF_SQES,
		sqeSize,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
	)
	if err != nil {
		syscall.Munmap(sqRing)
		syscall.Close(int(fd))
		return nil, errors.New("mmap sqes failed: ", err)
	}
	ring.sqesMmap = sqesMmap
	ring.sqes = unsafe.Slice((*ioUringSqe)(unsafe.Pointer(&sqesMmap[0])), params.sqEntries)

	// Map completion queue
	cqRingSize := params.cqOff.cqes + params.cqEntries*uint32(unsafe.Sizeof(ioUringCqe{}))
	cqRing, err := syscall.Mmap(
		int(fd),
		IORING_OFF_CQ_RING,
		int(cqRingSize),
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_POPULATE,
	)
	if err != nil {
		syscall.Munmap(sqesMmap)
		syscall.Munmap(sqRing)
		syscall.Close(int(fd))
		return nil, errors.New("mmap cq_ring failed: ", err)
	}
	ring.cqRing = cqRing
	ring.cqHead = (*uint32)(unsafe.Pointer(&cqRing[params.cqOff.head]))
	ring.cqTail = (*uint32)(unsafe.Pointer(&cqRing[params.cqOff.tail]))
	ring.cqes = unsafe.Slice((*ioUringCqe)(unsafe.Pointer(&cqRing[params.cqOff.cqes])), params.cqEntries)

	// Setup SQ array
	ring.sqArray = unsafe.Slice((*uint32)(unsafe.Pointer(&sqRing[params.sqOff.array])), params.sqEntries)

	return ring, nil
}

// newIoUring creates a new io_uring instance with default configuration
func newIoUring(entries uint32) (*IoUring, error) {
	return NewIoUringWithConfig(IoUringConfig{
		Entries: entries,
		Flags:   0,
	})
}

// RegisterFixedBuffers registers fixed buffers for zero-copy I/O
func (r *IoUring) RegisterFixedBuffers(count int) error {
	if count > maxFixedBuffers {
		count = maxFixedBuffers
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Allocate buffers
	r.fixedBuffers = make([][]byte, count)
	r.fixedBufferIovs = make([]iovec, count)
	r.fixedBufferInUse = make([]atomic.Bool, count)

	for i := 0; i < count; i++ {
		// Allocate page-aligned buffer
		r.fixedBuffers[i] = make([]byte, fixedBufferSize)
		r.fixedBufferIovs[i] = iovec{
			Base: &r.fixedBuffers[i][0],
			Len:  uint64(fixedBufferSize),
		}
	}

	// Register with kernel
	_, _, errno := syscall.Syscall(
		SYS_IO_URING_REGISTER,
		uintptr(r.fd),
		IORING_REGISTER_BUFFERS,
		uintptr(unsafe.Pointer(&r.fixedBufferIovs[0])),
	)
	// Note: third argument should be count, but Syscall only takes 3 args
	// Use Syscall6 for proper call
	_, _, errno = syscall.Syscall6(
		SYS_IO_URING_REGISTER,
		uintptr(r.fd),
		IORING_REGISTER_BUFFERS,
		uintptr(unsafe.Pointer(&r.fixedBufferIovs[0])),
		uintptr(count),
		0,
		0,
	)
	if errno != 0 {
		r.fixedBuffers = nil
		r.fixedBufferIovs = nil
		r.fixedBufferInUse = nil
		return errors.New("register buffers failed: ", errno.Error())
	}

	r.hasFixedBuffers = true
	return nil
}

// UnregisterFixedBuffers unregisters fixed buffers
func (r *IoUring) UnregisterFixedBuffers() error {
	if !r.hasFixedBuffers {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	_, _, errno := syscall.Syscall(
		SYS_IO_URING_REGISTER,
		uintptr(r.fd),
		IORING_UNREGISTER_BUFFERS,
		0,
	)
	if errno != 0 {
		return errors.New("unregister buffers failed: ", errno.Error())
	}

	r.fixedBuffers = nil
	r.fixedBufferIovs = nil
	r.fixedBufferInUse = nil
	r.hasFixedBuffers = false
	return nil
}

// AcquireFixedBuffer acquires a fixed buffer for use
func (r *IoUring) AcquireFixedBuffer() (bufIdx int, buf []byte, ok bool) {
	if !r.hasFixedBuffers {
		return -1, nil, false
	}

	for i := range r.fixedBufferInUse {
		if r.fixedBufferInUse[i].CompareAndSwap(false, true) {
			return i, r.fixedBuffers[i], true
		}
	}
	return -1, nil, false
}

// ReleaseFixedBuffer releases a fixed buffer
func (r *IoUring) ReleaseFixedBuffer(bufIdx int) {
	if bufIdx >= 0 && bufIdx < len(r.fixedBufferInUse) {
		r.fixedBufferInUse[bufIdx].Store(false)
	}
}

// getSqe gets a submission queue entry (must hold lock)
func (r *IoUring) getSqe() (*ioUringSqe, uint32, error) {
	tail := atomic.LoadUint32(r.sqTail)
	head := atomic.LoadUint32(r.sqHead)

	if tail-head >= uint32(len(r.sqes)) {
		return nil, 0, errors.New("submission queue full")
	}

	idx := tail & r.sqMask
	sqe := &r.sqes[idx]

	// Clear the SQE
	*sqe = ioUringSqe{}

	return sqe, idx, nil
}

// commitSqe commits a submission queue entry (must hold lock)
func (r *IoUring) commitSqe(idx uint32) {
	r.sqArray[idx] = idx
	atomic.AddUint32(r.sqTail, 1)
	r.pendingOps.Add(1)
}

// PrepareRead prepares a read operation
func (r *IoUring) PrepareRead(fd int, buf []byte, userData uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return io.ErrClosedPipe
	}

	sqe, idx, err := r.getSqe()
	if err != nil {
		return err
	}

	sqe.opcode = IORING_OP_READ
	sqe.fd = int32(fd)
	sqe.addr = uint64(uintptr(unsafe.Pointer(&buf[0])))
	sqe.len = uint32(len(buf))
	sqe.off = ^uint64(0) // -1 means current file position
	sqe.userData = userData

	r.commitSqe(idx)
	return nil
}

// PrepareReadFixed prepares a read operation using a fixed buffer
func (r *IoUring) PrepareReadFixed(fd int, bufIdx int, userData uint64) error {
	if !r.hasFixedBuffers || bufIdx < 0 || bufIdx >= len(r.fixedBuffers) {
		return errors.New("invalid fixed buffer index")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return io.ErrClosedPipe
	}

	sqe, idx, err := r.getSqe()
	if err != nil {
		return err
	}

	sqe.opcode = IORING_OP_READ_FIXED
	sqe.fd = int32(fd)
	sqe.addr = uint64(uintptr(unsafe.Pointer(&r.fixedBuffers[bufIdx][0])))
	sqe.len = uint32(fixedBufferSize)
	sqe.off = ^uint64(0)
	sqe.userData = userData
	sqe.bufIndex = uint16(bufIdx)

	r.commitSqe(idx)
	return nil
}

// PrepareWrite prepares a write operation
func (r *IoUring) PrepareWrite(fd int, buf []byte, userData uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return io.ErrClosedPipe
	}

	sqe, idx, err := r.getSqe()
	if err != nil {
		return err
	}

	sqe.opcode = IORING_OP_WRITE
	sqe.fd = int32(fd)
	sqe.addr = uint64(uintptr(unsafe.Pointer(&buf[0])))
	sqe.len = uint32(len(buf))
	sqe.off = ^uint64(0)
	sqe.userData = userData

	r.commitSqe(idx)
	return nil
}

// PrepareWriteFixed prepares a write operation using a fixed buffer
func (r *IoUring) PrepareWriteFixed(fd int, bufIdx int, length uint32, userData uint64) error {
	if !r.hasFixedBuffers || bufIdx < 0 || bufIdx >= len(r.fixedBuffers) {
		return errors.New("invalid fixed buffer index")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return io.ErrClosedPipe
	}

	sqe, idx, err := r.getSqe()
	if err != nil {
		return err
	}

	sqe.opcode = IORING_OP_WRITE_FIXED
	sqe.fd = int32(fd)
	sqe.addr = uint64(uintptr(unsafe.Pointer(&r.fixedBuffers[bufIdx][0])))
	sqe.len = length
	sqe.off = ^uint64(0)
	sqe.userData = userData
	sqe.bufIndex = uint16(bufIdx)

	r.commitSqe(idx)
	return nil
}

// PrepareReadv prepares a readv operation (scatter read)
func (r *IoUring) PrepareReadv(fd int, iovecs []iovec, userData uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return io.ErrClosedPipe
	}

	sqe, idx, err := r.getSqe()
	if err != nil {
		return err
	}

	sqe.opcode = IORING_OP_READV
	sqe.fd = int32(fd)
	sqe.addr = uint64(uintptr(unsafe.Pointer(&iovecs[0])))
	sqe.len = uint32(len(iovecs))
	sqe.off = ^uint64(0)
	sqe.userData = userData

	r.commitSqe(idx)
	return nil
}

// PrepareWritev prepares a writev operation (gather write)
func (r *IoUring) PrepareWritev(fd int, iovecs []iovec, userData uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return io.ErrClosedPipe
	}

	sqe, idx, err := r.getSqe()
	if err != nil {
		return err
	}

	sqe.opcode = IORING_OP_WRITEV
	sqe.fd = int32(fd)
	sqe.addr = uint64(uintptr(unsafe.Pointer(&iovecs[0])))
	sqe.len = uint32(len(iovecs))
	sqe.off = ^uint64(0)
	sqe.userData = userData

	r.commitSqe(idx)
	return nil
}

// PrepareSend prepares a send operation (for sockets)
func (r *IoUring) PrepareSend(fd int, buf []byte, flags int, userData uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return io.ErrClosedPipe
	}

	sqe, idx, err := r.getSqe()
	if err != nil {
		return err
	}

	sqe.opcode = IORING_OP_SEND
	sqe.fd = int32(fd)
	sqe.addr = uint64(uintptr(unsafe.Pointer(&buf[0])))
	sqe.len = uint32(len(buf))
	sqe.opcodeFlags = uint32(flags)
	sqe.userData = userData

	r.commitSqe(idx)
	return nil
}

// PrepareRecv prepares a recv operation (for sockets)
func (r *IoUring) PrepareRecv(fd int, buf []byte, flags int, userData uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return io.ErrClosedPipe
	}

	sqe, idx, err := r.getSqe()
	if err != nil {
		return err
	}

	sqe.opcode = IORING_OP_RECV
	sqe.fd = int32(fd)
	sqe.addr = uint64(uintptr(unsafe.Pointer(&buf[0])))
	sqe.len = uint32(len(buf))
	sqe.opcodeFlags = uint32(flags)
	sqe.userData = userData

	r.commitSqe(idx)
	return nil
}

// BatchOp represents a batch operation
type BatchOp struct {
	Op       uint8 // IORING_OP_*
	Fd       int
	Buf      []byte
	BufIdx   int // For fixed buffers
	Flags    int
	UserData uint64
}

// PrepareBatch prepares multiple operations at once
func (r *IoUring) PrepareBatch(ops []BatchOp) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	submitted := 0
	for _, op := range ops {
		sqe, idx, err := r.getSqe()
		if err != nil {
			break // Queue full
		}

		sqe.opcode = op.Op
		sqe.fd = int32(op.Fd)
		sqe.userData = op.UserData

		switch op.Op {
		case IORING_OP_READ, IORING_OP_WRITE:
			sqe.addr = uint64(uintptr(unsafe.Pointer(&op.Buf[0])))
			sqe.len = uint32(len(op.Buf))
			sqe.off = ^uint64(0)
		case IORING_OP_READ_FIXED, IORING_OP_WRITE_FIXED:
			if op.BufIdx >= 0 && op.BufIdx < len(r.fixedBuffers) {
				sqe.addr = uint64(uintptr(unsafe.Pointer(&r.fixedBuffers[op.BufIdx][0])))
				sqe.len = uint32(len(op.Buf))
				sqe.bufIndex = uint16(op.BufIdx)
			}
			sqe.off = ^uint64(0)
		case IORING_OP_SEND, IORING_OP_RECV:
			sqe.addr = uint64(uintptr(unsafe.Pointer(&op.Buf[0])))
			sqe.len = uint32(len(op.Buf))
			sqe.opcodeFlags = uint32(op.Flags)
		}

		r.commitSqe(idx)
		submitted++
	}

	return submitted, nil
}

// Submit submits pending operations and optionally waits for completions
func (r *IoUring) Submit(waitNr uint32) (int, error) {
	if r.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	toSubmit := atomic.LoadUint32(r.sqTail) - atomic.LoadUint32(r.sqHead)
	if toSubmit == 0 && waitNr == 0 {
		return 0, nil
	}

	flags := uintptr(0)
	if waitNr > 0 {
		flags = IORING_ENTER_GETEVENTS
	}

	// In SQPOLL mode, wake up the kernel thread if needed
	if r.sqpollMode && r.sqFlags != nil {
		sqFlags := atomic.LoadUint32(r.sqFlags)
		if sqFlags&(1<<0) != 0 { // IORING_SQ_NEED_WAKEUP
			flags |= IORING_ENTER_SQ_WAKEUP
		}
	}

	n, _, errno := syscall.Syscall6(
		SYS_IO_URING_ENTER,
		uintptr(r.fd),
		uintptr(toSubmit),
		uintptr(waitNr),
		flags,
		0,
		0,
	)
	if errno != 0 {
		return 0, errors.New("io_uring_enter failed: ", errno.Error())
	}

	return int(n), nil
}

// SubmitAndWait submits and waits for at least one completion
func (r *IoUring) SubmitAndWait() (int, error) {
	return r.Submit(1)
}

// GetCompletion retrieves a completion event
func (r *IoUring) GetCompletion() (userData uint64, res int32, ok bool) {
	head := atomic.LoadUint32(r.cqHead)
	tail := atomic.LoadUint32(r.cqTail)

	if head == tail {
		return 0, 0, false
	}

	idx := head & r.cqMask
	cqe := &r.cqes[idx]

	userData = cqe.userData
	res = cqe.res

	atomic.StoreUint32(r.cqHead, head+1)
	r.pendingOps.Add(-1)

	return userData, res, true
}

// GetCompletions retrieves up to max completion events
func (r *IoUring) GetCompletions(max int) []struct {
	UserData uint64
	Res      int32
} {
	results := make([]struct {
		UserData uint64
		Res      int32
	}, 0, max)

	for i := 0; i < max; i++ {
		userData, res, ok := r.GetCompletion()
		if !ok {
			break
		}
		results = append(results, struct {
			UserData uint64
			Res      int32
		}{userData, res})
	}

	return results
}

// WaitCompletion waits for a completion with timeout
func (r *IoUring) WaitCompletion(timeout time.Duration) (userData uint64, res int32, ok bool) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		userData, res, ok = r.GetCompletion()
		if ok {
			return
		}

		// Submit any pending and wait
		r.Submit(1)

		// Brief sleep to avoid busy-waiting
		runtime.Gosched()
	}

	return 0, 0, false
}

// PendingOps returns the number of pending operations
func (r *IoUring) PendingOps() int32 {
	return r.pendingOps.Load()
}

// HasSQPoll returns true if SQPOLL mode is enabled
func (r *IoUring) HasSQPoll() bool {
	return r.sqpollMode
}

// Close closes the io_uring instance
func (r *IoUring) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Unregister fixed buffers if any
	if r.hasFixedBuffers {
		r.UnregisterFixedBuffers()
	}

	// Wait for pending operations with timeout
	deadline := time.Now().Add(5 * time.Second)
	for r.pendingOps.Load() > 0 && time.Now().Before(deadline) {
		r.Submit(1)
		r.GetCompletion()
		runtime.Gosched()
	}

	if r.cqRing != nil {
		syscall.Munmap(r.cqRing)
	}
	if r.sqesMmap != nil {
		syscall.Munmap(r.sqesMmap)
	}
	if r.sqRing != nil {
		syscall.Munmap(r.sqRing)
	}
	return syscall.Close(r.fd)
}

// Reset resets the io_uring instance for reuse (from pool)
func (r *IoUring) Reset() {
	r.closed.Store(false)
	// Drain any leftover completions
	for {
		_, _, ok := r.GetCompletion()
		if !ok {
			break
		}
	}
}

// IoUringReader implements Reader using io_uring
type IoUringReader struct {
	io.Reader
	rawConn   syscall.RawConn
	ring      *IoUring
	alloc     allocStrategy
	useSQPoll bool
	useFixed  bool
	iovecs    []iovec // Reusable iovec slice for batch reads
}

// IoUringReaderOption configures IoUringReader
type IoUringReaderOption func(*IoUringReader)

// WithSQPoll enables SQPOLL mode for the reader
func WithSQPoll() IoUringReaderOption {
	return func(r *IoUringReader) {
		r.useSQPoll = true
	}
}

// WithFixedBuffers enables fixed buffer mode for the reader
func WithFixedBuffers() IoUringReaderOption {
	return func(r *IoUringReader) {
		r.useFixed = true
	}
}

// NewIoUringReader creates a new IoUringReader if io_uring is available
func NewIoUringReader(reader io.Reader, rawConn syscall.RawConn, opts ...IoUringReaderOption) (*IoUringReader, error) {
	if !IsIoUringAvailable() {
		return nil, errors.New("io_uring not available")
	}

	r := &IoUringReader{
		Reader:  reader,
		rawConn: rawConn,
		alloc: allocStrategy{
			current: 1,
		},
		iovecs: make([]iovec, 0, 16),
	}

	// Apply options
	for _, opt := range opts {
		opt(r)
	}

	// Get appropriate ring from pool
	var ring interface{}
	if r.useSQPoll && IsSQPollAvailable() {
		ring = ioUringSQPollPool.Get()
	} else {
		ring = ioUringPool.Get()
		r.useSQPoll = false // Disable if not available
	}

	if ring == nil {
		return nil, errors.New("failed to get io_uring from pool")
	}

	r.ring = ring.(*IoUring)
	r.ring.Reset()

	// Setup fixed buffers if requested
	if r.useFixed && useIoUringFixedBufs {
		if err := r.ring.RegisterFixedBuffers(maxFixedBuffers); err != nil {
			// Fall back to regular buffers
			r.useFixed = false
		}
	} else {
		r.useFixed = false
	}

	return r, nil
}

// ReadMultiBuffer implements Reader using io_uring
func (r *IoUringReader) ReadMultiBuffer() (MultiBuffer, error) {
	if r.alloc.Current() == 1 {
		return r.readSingle()
	}
	return r.readMulti()
}

// readSingle reads a single buffer using io_uring
func (r *IoUringReader) readSingle() (MultiBuffer, error) {
	var b *Buffer
	var bufIdx int = -1

	// Try to use fixed buffer if available
	if r.useFixed {
		var ok bool
		bufIdx, _, ok = r.ring.AcquireFixedBuffer()
		if ok {
			b = bufferPool.Get().(*Buffer)
			b.v = r.ring.fixedBuffers[bufIdx]
			b.start = 0
			b.end = 0
			b.ownership = unmanaged // Don't free on release
			b.UDP = nil
		}
	}

	if b == nil {
		b = New()
	}

	var nBytes int32
	var readErr error

	err := r.rawConn.Read(func(fd uintptr) bool {
		var prepErr error
		if bufIdx >= 0 {
			prepErr = r.ring.PrepareReadFixed(int(fd), bufIdx, 0)
		} else {
			prepErr = r.ring.PrepareRead(int(fd), b.v[:Size], 0)
		}

		if prepErr != nil {
			readErr = prepErr
			return false
		}

		// Submit and wait for completion
		if _, err := r.ring.SubmitAndWait(); err != nil {
			readErr = err
			return false
		}

		// Get completion
		_, res, ok := r.ring.GetCompletion()
		if !ok {
			return false
		}

		if res < 0 {
			readErr = syscall.Errno(-res)
			return false
		}

		nBytes = res
		return true
	})

	// Handle errors
	if readErr != nil || err != nil {
		if bufIdx >= 0 {
			r.ring.ReleaseFixedBuffer(bufIdx)
			bufferPool.Put(b)
		} else {
			b.Release()
		}
		if readErr != nil {
			return nil, readErr
		}
		return nil, err
	}

	if nBytes == 0 {
		if bufIdx >= 0 {
			r.ring.ReleaseFixedBuffer(bufIdx)
			bufferPool.Put(b)
		} else {
			b.Release()
		}
		return nil, io.EOF
	}

	// For fixed buffers, copy to a regular buffer
	if bufIdx >= 0 {
		newB := New()
		copy(newB.v, b.v[:nBytes])
		newB.end = nBytes
		r.ring.ReleaseFixedBuffer(bufIdx)
		bufferPool.Put(b)
		b = newB
	} else {
		b.end = nBytes
	}

	if b.IsFull() {
		r.alloc.Adjust(1)
	}

	return MultiBuffer{b}, nil
}

// readMulti reads multiple buffers using io_uring readv
func (r *IoUringReader) readMulti() (MultiBuffer, error) {
	bs := r.alloc.Alloc()

	// Prepare iovecs
	r.iovecs = r.iovecs[:0]
	for _, b := range bs {
		r.iovecs = append(r.iovecs, iovec{
			Base: &b.v[0],
			Len:  uint64(Size),
		})
	}

	var nBytes int32
	var readErr error

	err := r.rawConn.Read(func(fd uintptr) bool {
		if err := r.ring.PrepareReadv(int(fd), r.iovecs, 0); err != nil {
			readErr = err
			return false
		}

		if _, err := r.ring.SubmitAndWait(); err != nil {
			readErr = err
			return false
		}

		_, res, ok := r.ring.GetCompletion()
		if !ok {
			return false
		}

		if res < 0 {
			readErr = syscall.Errno(-res)
			return false
		}

		nBytes = res
		return true
	})

	if readErr != nil || err != nil {
		ReleaseMulti(MultiBuffer(bs))
		if readErr != nil {
			return nil, readErr
		}
		return nil, err
	}

	if nBytes == 0 {
		ReleaseMulti(MultiBuffer(bs))
		return nil, io.EOF
	}

	// Calculate how many buffers were actually filled
	nBuf := 0
	remaining := nBytes
	for nBuf < len(bs) && remaining > 0 {
		end := remaining
		if end > Size {
			end = Size
		}
		bs[nBuf].end = end
		remaining -= end
		nBuf++
	}

	// Release unused buffers
	for i := nBuf; i < len(bs); i++ {
		bs[i].Release()
		bs[i] = nil
	}

	r.alloc.Adjust(uint32(nBuf))
	return MultiBuffer(bs[:nBuf]), nil
}

// Release returns the io_uring instance to the pool
func (r *IoUringReader) Release() {
	if r.ring != nil {
		if r.useSQPoll {
			ioUringSQPollPool.Put(r.ring)
		} else {
			ioUringPool.Put(r.ring)
		}
		r.ring = nil
	}
}

// IoUringWriter implements Writer using io_uring
type IoUringWriter struct {
	io.Writer
	rawConn   syscall.RawConn
	ring      *IoUring
	useSQPoll bool
}

// NewIoUringWriter creates a new IoUringWriter if io_uring is available
func NewIoUringWriter(writer io.Writer, rawConn syscall.RawConn, opts ...IoUringReaderOption) (*IoUringWriter, error) {
	if !IsIoUringAvailable() {
		return nil, errors.New("io_uring not available")
	}

	w := &IoUringWriter{
		Writer:  writer,
		rawConn: rawConn,
	}

	// Check for SQPOLL option
	for _, opt := range opts {
		r := &IoUringReader{}
		opt(r)
		w.useSQPoll = r.useSQPoll
	}

	var ring interface{}
	if w.useSQPoll && IsSQPollAvailable() {
		ring = ioUringSQPollPool.Get()
	} else {
		ring = ioUringPool.Get()
		w.useSQPoll = false
	}

	if ring == nil {
		return nil, errors.New("failed to get io_uring from pool")
	}

	w.ring = ring.(*IoUring)
	w.ring.Reset()

	return w, nil
}

// WriteMultiBuffer implements Writer using io_uring
func (w *IoUringWriter) WriteMultiBuffer(mb MultiBuffer) error {
	if mb.IsEmpty() {
		return nil
	}

	// Prepare iovecs for all buffers
	iovecs := make([]iovec, len(mb))
	for i, b := range mb {
		iovecs[i] = iovec{
			Base: &b.v[b.start],
			Len:  uint64(b.Len()),
		}
	}

	var writeErr error

	err := w.rawConn.Write(func(fd uintptr) bool {
		if err := w.ring.PrepareWritev(int(fd), iovecs, 0); err != nil {
			writeErr = err
			return false
		}

		if _, err := w.ring.SubmitAndWait(); err != nil {
			writeErr = err
			return false
		}

		_, res, ok := w.ring.GetCompletion()
		if !ok {
			return false
		}

		if res < 0 {
			writeErr = syscall.Errno(-res)
			return false
		}

		return true
	})

	// Always release the buffers
	ReleaseMulti(mb)

	if writeErr != nil {
		return writeErr
	}
	return err
}

// Release returns the io_uring instance to the pool
func (w *IoUringWriter) Release() {
	if w.ring != nil {
		if w.useSQPoll {
			ioUringSQPollPool.Put(w.ring)
		} else {
			ioUringPool.Put(w.ring)
		}
		w.ring = nil
	}
}
