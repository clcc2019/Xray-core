//go:build !linux

package ebpf

import (
	"context"
	"net"
)

type SockmapManager struct{}

func GetSockmapManager() *SockmapManager                                           { return &SockmapManager{} }
func (m *SockmapManager) Init(ctx context.Context) error                           { return nil }
func (m *SockmapManager) RegisterPair(conn net.Conn, sid uint64, dir uint32) error { return nil }
func (m *SockmapManager) Close() error                                             { return nil }
func (m *SockmapManager) IsEnabled() bool                                          { return false }
