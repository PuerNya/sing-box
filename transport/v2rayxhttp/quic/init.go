package quic

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	aTLS "github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/transport/v2rayxhttp"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

func init() {
	v2rayxhttp.ConfigureH3Transport = func(dialer N.Dialer, destination M.Socksaddr, tlsConfig aTLS.Config, idleTimeout time.Duration) (v2rayxhttp.Transport, error) {
		tlsCfg, err := tlsConfig.STDConfig()
		if err != nil {
			return nil, err
		}
		tlsCfg = tlsCfg.Clone()
		tlsCfg.NextProtos = []string{http3.NextProtoH3}
		builder := func() *http3.Transport {
			return &http3.Transport{
				TLSClientConfig: tlsCfg,
				QUICConfig: &quic.Config{
					DisablePathMTUDiscovery: !C.IsLinux && !C.IsWindows && !C.IsAndroid && !C.IsDarwin,
					MaxIdleTimeout:          idleTimeout,
				},
				Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
					c, err := dialer.DialContext(ctx, N.NetworkUDP, destination)
					if err != nil {
						return nil, err
					}
					conn, err := quic.DialEarly(ctx, bufio.NewUnbindPacketConn(c), c.RemoteAddr(), tlsCfg, cfg)
					if err != nil {
						c.Close()
						return nil, err
					}
					return conn, nil
				},
			}
		}
		return &transportWrapper{
			Transport: builder(),
			builder:   builder,
		}, nil
	}
	v2rayxhttp.ConfigureH3Listener = func(handler http.Handler, tlsConfig aTLS.ServerConfig) (v2rayxhttp.HTTPServer, error) {
		tlsCfg, err := tlsConfig.STDConfig()
		if err != nil {
			return nil, err
		}
		tlsCfg = tlsCfg.Clone()
		tlsCfg.NextProtos = []string{http3.NextProtoH3}
		return &http3.Server{
			Handler:   handler,
			TLSConfig: tlsCfg,
			QUICConfig: &quic.Config{
				MaxIncomingStreams: 1 << 60,
				Allow0RTT:          true,
			},
			ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
				return log.ContextWithNewID(ctx)
			},
		}, nil
	}
}
