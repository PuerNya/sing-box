package quic

import (
	"context"
	"crypto/tls"
	"net/http"
	"runtime"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	sTLS "github.com/sagernet/sing-box/common/tls"
	sHTTP "github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
)

func init() {
	sHTTP.ConfigureHTTP3RoundTripper = func(dialer network.Dialer, serverAddress M.Socksaddr, tlsConfig sTLS.Config) (http.RoundTripper, error) {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http3.NextProtoH3})
		}
		return &http3.Transport{
			QUICConfig: &quic.Config{
				DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
				MaxIncomingUniStreams:   1 << 60,
			},
			Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlyConnection, error) {
				udpConn, err := dialer.DialContext(ctx, "udp", serverAddress)
				if err != nil {
					return nil, err
				}
				return qtls.DialEarly(ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), tlsConfig, cfg)
			},
		}, nil
	}
}
