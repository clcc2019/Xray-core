package encoding

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy"
	"github.com/xtls/xray-core/proxy/vless"
	"google.golang.org/protobuf/proto"
)

// Addons 结构体池，减少内存分配
var addonsPool = sync.Pool{
	New: func() interface{} {
		return new(Addons)
	},
}

// AcquireAddons 从池中获取 Addons 结构体
func AcquireAddons() *Addons {
	return addonsPool.Get().(*Addons)
}

// ReleaseAddons 将 Addons 结构体归还到池中
func ReleaseAddons(addons *Addons) {
	if addons == nil {
		return
	}
	// 重置字段
	addons.Flow = ""
	addons.Seed = nil
	addonsPool.Put(addons)
}

// protobuf 序列化缓冲区池
var protoBufferPool = sync.Pool{
	New: func() interface{} {
		// 预分配 64 字节，足够大多数 Addons 序列化
		b := make([]byte, 0, 64)
		return &b
	},
}

func EncodeHeaderAddons(buffer *buf.Buffer, addons *Addons) error {
	switch addons.Flow {
	case vless.XRV:
		// 使用池化缓冲区进行 protobuf 序列化
		bufPtr := protoBufferPool.Get().(*[]byte)
		protoBytes := *bufPtr
		protoBytes = protoBytes[:0]

		var err error
		protoBytes, err = proto.MarshalOptions{}.MarshalAppend(protoBytes, addons)
		if err != nil {
			*bufPtr = protoBytes
			protoBufferPool.Put(bufPtr)
			return errors.New("failed to marshal addons protobuf value").Base(err)
		}
		if err := buffer.WriteByte(byte(len(protoBytes))); err != nil {
			*bufPtr = protoBytes
			protoBufferPool.Put(bufPtr)
			return errors.New("failed to write addons protobuf length").Base(err)
		}
		if _, err := buffer.Write(protoBytes); err != nil {
			*bufPtr = protoBytes
			protoBufferPool.Put(bufPtr)
			return errors.New("failed to write addons protobuf value").Base(err)
		}
		*bufPtr = protoBytes
		protoBufferPool.Put(bufPtr)
	default:
		if err := buffer.WriteByte(0); err != nil {
			return errors.New("failed to write addons protobuf length").Base(err)
		}
	}

	return nil
}

func DecodeHeaderAddons(buffer *buf.Buffer, reader io.Reader) (*Addons, error) {
	// 使用池化的 Addons 结构体
	addons := AcquireAddons()
	buffer.Clear()
	if _, err := buffer.ReadFullFrom(reader, 1); err != nil {
		ReleaseAddons(addons)
		return nil, errors.New("failed to read addons protobuf length").Base(err)
	}

	if length := int32(buffer.Byte(0)); length != 0 {
		buffer.Clear()
		if _, err := buffer.ReadFullFrom(reader, length); err != nil {
			ReleaseAddons(addons)
			return nil, errors.New("failed to read addons protobuf value").Base(err)
		}

		if err := proto.Unmarshal(buffer.Bytes(), addons); err != nil {
			ReleaseAddons(addons)
			return nil, errors.New("failed to unmarshal addons protobuf value").Base(err)
		}

		// Verification.
		switch addons.Flow {
		default:
		}
	}

	return addons, nil
}

// EncodeBodyAddons returns a Writer that auto-encrypt content written by caller.
func EncodeBodyAddons(writer buf.Writer, request *protocol.RequestHeader, requestAddons *Addons, state *proxy.TrafficState, isUplink bool, context context.Context, conn net.Conn, ob *session.Outbound) buf.Writer {
	if request.Command == protocol.RequestCommandUDP {
		return NewMultiLengthPacketWriter(writer)
	}
	if requestAddons.Flow == vless.XRV {
		return proxy.NewVisionWriter(writer, state, isUplink, context, conn, ob, request.User.Account.(*vless.MemoryAccount).Testseed)
	}
	return writer
}

// DecodeBodyAddons returns a Reader from which caller can fetch decrypted body.
func DecodeBodyAddons(reader io.Reader, request *protocol.RequestHeader, addons *Addons) buf.Reader {
	switch addons.Flow {
	default:
		if request.Command == protocol.RequestCommandUDP {
			return NewLengthPacketReader(reader)
		}
	}
	return buf.NewReader(reader)
}

// MultiLengthPacketWriter 池
var multiLengthPacketWriterPool = sync.Pool{
	New: func() interface{} {
		return &MultiLengthPacketWriter{}
	},
}

func NewMultiLengthPacketWriter(writer buf.Writer) *MultiLengthPacketWriter {
	w := multiLengthPacketWriterPool.Get().(*MultiLengthPacketWriter)
	w.Writer = writer
	return w
}

// Release 将 MultiLengthPacketWriter 归还到池中
func (w *MultiLengthPacketWriter) Release() {
	w.Writer = nil
	multiLengthPacketWriterPool.Put(w)
}

type MultiLengthPacketWriter struct {
	buf.Writer
}

// multiBufferSmallPool 用于 MultiLengthPacketWriter 的 MultiBuffer 切片池
var multiBufferSmallPool = sync.Pool{
	New: func() interface{} {
		mb := make(buf.MultiBuffer, 0, 8) // 预分配 8 个元素，适合大多数情况
		return &mb
	},
}

func (w *MultiLengthPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)

	// 从池中获取 MultiBuffer 切片
	mb2WritePtr := multiBufferSmallPool.Get().(*buf.MultiBuffer)
	mb2Write := (*mb2WritePtr)[:0]

	for _, b := range mb {
		length := b.Len()
		if length == 0 || length+2 > buf.Size {
			continue
		}
		eb := buf.New()
		if err := eb.WriteByte(byte(length >> 8)); err != nil {
			eb.Release()
			continue
		}
		if err := eb.WriteByte(byte(length)); err != nil {
			eb.Release()
			continue
		}
		if _, err := eb.Write(b.Bytes()); err != nil {
			eb.Release()
			continue
		}
		mb2Write = append(mb2Write, eb)
	}

	if len(mb2Write) == 0 {
		// 归还到池中
		*mb2WritePtr = mb2Write
		multiBufferSmallPool.Put(mb2WritePtr)
		return nil
	}

	err := w.Writer.WriteMultiBuffer(mb2Write)

	// 注意：WriteMultiBuffer 会消费 mb2Write，所以这里只需要重置切片
	*mb2WritePtr = (*mb2WritePtr)[:0]
	multiBufferSmallPool.Put(mb2WritePtr)

	return err
}

// LengthPacketWriter 池
var lengthPacketWriterPool = sync.Pool{
	New: func() interface{} {
		return &LengthPacketWriter{
			cache: make([]byte, 0, 65536),
		}
	},
}

func NewLengthPacketWriter(writer io.Writer) *LengthPacketWriter {
	w := lengthPacketWriterPool.Get().(*LengthPacketWriter)
	w.Writer = writer
	w.cache = w.cache[:0]
	return w
}

// Release 将 LengthPacketWriter 归还到池中
func (w *LengthPacketWriter) Release() {
	w.Writer = nil
	w.cache = w.cache[:0]
	lengthPacketWriterPool.Put(w)
}

type LengthPacketWriter struct {
	io.Writer
	cache []byte
}

func (w *LengthPacketWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	length := mb.Len() // none of mb is nil
	// fmt.Println("Write", length)
	if length == 0 {
		return nil
	}
	defer func() {
		w.cache = w.cache[:0]
	}()
	w.cache = append(w.cache, byte(length>>8), byte(length))
	for i, b := range mb {
		w.cache = append(w.cache, b.Bytes()...)
		b.Release()
		mb[i] = nil
	}
	if _, err := w.Write(w.cache); err != nil {
		return errors.New("failed to write a packet").Base(err)
	}
	return nil
}

// LengthPacketReader 池
var lengthPacketReaderPool = sync.Pool{
	New: func() interface{} {
		return &LengthPacketReader{
			cache: make([]byte, 2),
		}
	},
}

func NewLengthPacketReader(reader io.Reader) *LengthPacketReader {
	r := lengthPacketReaderPool.Get().(*LengthPacketReader)
	r.Reader = reader
	return r
}

// Release 将 LengthPacketReader 归还到池中
func (r *LengthPacketReader) Release() {
	r.Reader = nil
	lengthPacketReaderPool.Put(r)
}

type LengthPacketReader struct {
	io.Reader
	cache []byte
}

func (r *LengthPacketReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if _, err := io.ReadFull(r.Reader, r.cache); err != nil { // maybe EOF
		return nil, errors.New("failed to read packet length").Base(err)
	}
	length := int32(r.cache[0])<<8 | int32(r.cache[1])
	// fmt.Println("Read", length)
	mb := make(buf.MultiBuffer, 0, length/buf.Size+1)
	for length > 0 {
		size := length
		if size > buf.Size {
			size = buf.Size
		}
		length -= size
		b := buf.New()
		if _, err := b.ReadFullFrom(r.Reader, size); err != nil {
			return nil, errors.New("failed to read packet payload").Base(err)
		}
		mb = append(mb, b)
	}
	return mb, nil
}
