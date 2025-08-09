//go:build linux

package ebpf

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/cilium/ebpf"
)

// EnableIPFastpath flips ip_fastpath_enable[0]
func EnableIPFastpath(enable bool) {
	mp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/ip_fastpath_enable", nil)
	if err != nil {
		return
	}
	var k uint32 = 0
	var v uint32
	if enable {
		v = 1
	} else {
		v = 0
	}
	_ = mp.Update(&k, &v, ebpf.UpdateAny)
}

// SetIPv4Mark writes route_ip_v4_hint[dst] = {mark, expire}
func SetIPv4Mark(ip net.IP, mark uint32, ttlSeconds uint32) {
	v4 := ip.To4()
	if v4 == nil {
		return
	}
	mp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/route_ip_v4_hint", nil)
	if err != nil {
		return
	}
	key := binary.BigEndian.Uint32(v4) // network order
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:4], mark)
	var exp uint64
	if ttlSeconds == 0 {
		exp = 0
	} else {
		exp = uint64(time.Now().Unix()) + uint64(ttlSeconds)
	}
	binary.LittleEndian.PutUint64(buf[4:12], exp)
	_ = mp.Update(&key, buf, ebpf.UpdateAny)
}

// SetIPv6Mark writes route_ip_v6_hint[dst] = {mark, expire}
func SetIPv6Mark(ip net.IP, mark uint32, ttlSeconds uint32) {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return
	}
	mp, err := ebpf.LoadPinnedMap("/sys/fs/bpf/xray/route_ip_v6_hint", nil)
	if err != nil {
		return
	}
	var key struct{ Hi, Lo uint64 }
	key.Hi = binary.BigEndian.Uint64(v6[0:8])
	key.Lo = binary.BigEndian.Uint64(v6[8:16])
	buf := make([]byte, 12)
	binary.LittleEndian.PutUint32(buf[0:4], mark)
	var exp uint64
	if ttlSeconds == 0 {
		exp = 0
	} else {
		exp = uint64(time.Now().Unix()) + uint64(ttlSeconds)
	}
	binary.LittleEndian.PutUint64(buf[4:12], exp)
	_ = mp.Update(&key, buf, ebpf.UpdateAny)
}
