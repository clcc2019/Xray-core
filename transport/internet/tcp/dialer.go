package tcp

import (
	"context"
	gotls "crypto/tls"
	"slices"
	"strings"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tcp/ebpf"
	"github.com/xtls/xray-core/transport/internet/tls"
)

// Dial dials a new TCP connection to the given destination.
func Dial(ctx context.Context, dest net.Destination, streamSettings *internet.MemoryStreamConfig) (stat.Connection, error) {
	errors.LogInfo(ctx, "dialing TCP to ", dest)
	conn, err := internet.DialSystem(ctx, dest, streamSettings.SocketSettings)
	if err != nil {
		return nil, err
	}

	if config := tls.ConfigFromStreamSettings(streamSettings); config != nil {
		mitmServerName := session.MitmServerNameFromContext(ctx)
		mitmAlpn11 := session.MitmAlpn11FromContext(ctx)
		var tlsConfig *gotls.Config
		if tls.IsFromMitm(config.ServerName) {
			tlsConfig = config.GetTLSConfig(tls.WithOverrideName(mitmServerName))
		} else {
			tlsConfig = config.GetTLSConfig(tls.WithDestination(dest))
		}

		isFromMitmVerify := false
		if r, ok := tlsConfig.Rand.(*tls.RandCarrier); ok && len(r.VerifyPeerCertInNames) > 0 {
			for i, name := range r.VerifyPeerCertInNames {
				if tls.IsFromMitm(name) {
					isFromMitmVerify = true
					r.VerifyPeerCertInNames[0], r.VerifyPeerCertInNames[i] = r.VerifyPeerCertInNames[i], r.VerifyPeerCertInNames[0]
					r.VerifyPeerCertInNames = r.VerifyPeerCertInNames[1:]
					after := mitmServerName
					for {
						if len(after) > 0 {
							r.VerifyPeerCertInNames = append(r.VerifyPeerCertInNames, after)
						}
						_, after, _ = strings.Cut(after, ".")
						if !strings.Contains(after, ".") {
							break
						}
					}
					slices.Reverse(r.VerifyPeerCertInNames)
					break
				}
			}
		}
		isFromMitmAlpn := len(tlsConfig.NextProtos) == 1 && tls.IsFromMitm(tlsConfig.NextProtos[0])
		if isFromMitmAlpn {
			if mitmAlpn11 {
				tlsConfig.NextProtos[0] = "http/1.1"
			} else {
				tlsConfig.NextProtos = []string{"h2", "http/1.1"}
			}
		}
		if fingerprint := tls.GetFingerprint(config.Fingerprint); fingerprint != nil {
			conn = tls.UClient(conn, tlsConfig, fingerprint)
			if len(tlsConfig.NextProtos) == 1 && tlsConfig.NextProtos[0] == "http/1.1" { // allow manually specify
				err = conn.(*tls.UConn).WebsocketHandshakeContext(ctx)
			} else {
				err = conn.(*tls.UConn).HandshakeContext(ctx)
			}
		} else {
			conn = tls.Client(conn, tlsConfig)
			err = conn.(*tls.Conn).HandshakeContext(ctx)
		}
		if err != nil {
			if isFromMitmVerify {
				return nil, errors.New("MITM freedom RAW TLS: failed to verify Domain Fronting certificate from " + mitmServerName).Base(err).AtWarning()
			}
			return nil, err
		}
		negotiatedProtocol := conn.(tls.Interface).NegotiatedProtocol()
		if isFromMitmAlpn && !mitmAlpn11 && negotiatedProtocol != "h2" {
			conn.Close()
			return nil, errors.New("MITM freedom RAW TLS: unexpected Negotiated Protocol (" + negotiatedProtocol + ") with " + mitmServerName).AtWarning()
		}
	} else if config := reality.ConfigFromStreamSettings(streamSettings); config != nil {
		// 🎯 尝试使用目标域名加速
		targetAccelerator := reality.GetGlobalTargetAccelerator()
		if acceleratedConn, err := targetAccelerator.AccelerateTargetDial(ctx, dest); err == nil {
			errors.LogDebug(ctx, "🚀 Using accelerated target connection for REALITY")
			conn.Close() // 关闭原连接
			conn = acceleratedConn
		}

		// 优化REALITY握手
		if err := ebpf.OptimizeRealityHandshake(ctx, conn, config); err != nil {
			errors.LogDebug(ctx, "Failed to optimize REALITY handshake: ", err)
		}

		if conn, err = reality.UClient(conn, config, ctx, dest); err != nil {
			return nil, err
		}

		// 🔒 REALITY握手成功，标记为已验证以启用eBPF快速路径
		if err := ebpf.MarkRealityHandshakeComplete(ctx, conn); err != nil {
			errors.LogDebug(ctx, "Failed to mark REALITY handshake complete: ", err)
			// 不影响正常连接，继续执行
		}
	}

	tcpSettings := streamSettings.ProtocolSettings.(*Config)
	if tcpSettings.HeaderSettings != nil {
		headerConfig, err := tcpSettings.HeaderSettings.GetInstance()
		if err != nil {
			return nil, errors.New("failed to get header settings").Base(err).AtError()
		}
		auth, err := internet.CreateConnectionAuthenticator(headerConfig)
		if err != nil {
			return nil, errors.New("failed to create header authenticator").Base(err).AtError()
		}
		conn = auth.Client(conn)
	}

	// 为连接启用eBPF加速
	if err := ebpf.AccelerateDialedConnection(ctx, conn, streamSettings); err != nil {
		errors.LogDebug(ctx, "Failed to enable eBPF acceleration: ", err)
		// 不影响正常连接，继续执行
	}

	return stat.Connection(conn), nil
}

func init() {
	common.Must(internet.RegisterTransportDialer(protocolName, Dial))
}
