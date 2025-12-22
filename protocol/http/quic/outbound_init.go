package quic

import (
	"runtime"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	sTLS "github.com/sagernet/sing-box/common/tls"
	sHTTP "github.com/sagernet/sing-box/protocol/http"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ N.Dialer = (*h3Dialer)(nil)

func init() {
	sHTTP.ConfigureHTTP3Dialer = func(dialer N.Dialer, serverAddress M.Socksaddr, tlsConfig sTLS.Config, factor sHTTP.RequsetFactor) (N.Dialer, error) {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http3.NextProtoH3})
		}
		return &h3Dialer{
			dialer:        dialer,
			serverAddress: serverAddress,
			tlsConfig:     tlsConfig,
			factor:        factor,
			quicConfig: &quic.Config{
				DisablePathMTUDiscovery: !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin"),
				MaxIncomingUniStreams:   1 << 60,
				EnableDatagrams:         true,
			},
		}, nil
	}
}
