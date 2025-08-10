package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func leU32Hex(q uint32) string {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], q)
	parts := make([]string, 0, 4)
	for _, b := range buf {
		parts = append(parts, fmt.Sprintf("%02x", b))
	}
	return strings.ToUpper(strings.Join(parts, " "))
}

func run(cmd string, args ...string) error {
	c := exec.Command(cmd, args...)
	var out bytes.Buffer
	var errb bytes.Buffer
	c.Stdout = &out
	c.Stderr = &errb
	if err := c.Run(); err != nil {
		return fmt.Errorf("%s %v failed: %v, stderr=%s", cmd, args, err, errb.String())
	}
	return nil
}

func main() {
	var (
		mapDir   = flag.String("mapdir", "/sys/fs/bpf/xray", "pinned maps 目录")
		queue    = flag.Int("queue", 0, "RX 队列号")
		xskfd    = flag.Int("xskfd", -1, "AF_XDP socket fd (可选，>=0 写入 xsk_udp_map)")
		enable   = flag.Bool("enable", false, "启用该队列的 XDP 重定向")
		disable  = flag.Bool("disable", false, "禁用该队列的 XDP 重定向")
		deleteFd = flag.Bool("delete-fd", false, "从 xsk_udp_map 删除该队列槽位")
		bpftool  = flag.String("bpftool", "bpftool", "bpftool 可执行路径")
	)
	flag.Parse()

	if *queue < 0 || *queue > 4095 {
		fmt.Fprintln(os.Stderr, "invalid queue")
		os.Exit(2)
	}

	keyHex := leU32Hex(uint32(*queue))
	xskMap := fmt.Sprintf("%s/xsk_udp_map", *mapDir)
	enMap := fmt.Sprintf("%s/udp_xdp_queues_enable", *mapDir)

	// 写入/删除 xsk_udp_map
	if *deleteFd {
		if err := run(*bpftool, "map", "delete", "pinned", xskMap, "key", "hex", keyHex); err != nil {
			fmt.Fprintln(os.Stderr, "delete xsk slot failed:", err)
			os.Exit(1)
		}
		fmt.Println("deleted xsk slot for queue", *queue)
	} else if *xskfd >= 0 {
		// value fd 模式
		if err := run(*bpftool, "map", "update", "pinned", xskMap, "key", "hex", keyHex, "value", "fd", fmt.Sprintf("%d", *xskfd)); err != nil {
			fmt.Fprintln(os.Stderr, "update xsk fd failed:", err)
			os.Exit(1)
		}
		fmt.Println("updated xsk fd for queue", *queue, "fd", *xskfd)
	}

	// 更新队列开关
	if *enable || *disable {
		valHex := "00 00 00 00"
		if *enable {
			valHex = "01 00 00 00"
		}
		if err := run(*bpftool, "map", "update", "pinned", enMap, "key", "hex", keyHex, "value", "hex", valHex); err != nil {
			fmt.Fprintln(os.Stderr, "update queue enable failed:", err)
			os.Exit(1)
		}
		if *enable {
			fmt.Println("queue", *queue, "enabled")
		} else {
			fmt.Println("queue", *queue, "disabled")
		}
	}
}
