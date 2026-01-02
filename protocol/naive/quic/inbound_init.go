package quic

import (
	"io"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/protocol/naive"
	qtls "github.com/sagernet/sing-quic"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
)

func init() {
	naive.ConfigureHTTP3ListenerFunc = func(logger logger.Logger, listener *listener.Listener, tlsConfig tls.ServerConfig, handler naive.Handler) (io.Closer, error) {
		err := qtls.ConfigureHTTP3(tlsConfig)
		if err != nil {
			return nil, err
		}

		udpConn, err := listener.ListenUDP()
		if err != nil {
			return nil, err
		}

		quicListener, err := qtls.ListenEarly(udpConn, tlsConfig, &quic.Config{
			MaxIncomingStreams: 1 << 60,
			Allow0RTT:          true,
			EnableDatagrams:    true,
		})
		if err != nil {
			udpConn.Close()
			return nil, err
		}

		h3Server := &http3.Server{
			Handler:         newHandler(handler, udpConn.LocalAddr()),
			EnableDatagrams: true,
		}

		go func() {
			sErr := h3Server.ServeListener(quicListener)
			udpConn.Close()
			if sErr != nil && !E.IsClosedOrCanceled(sErr) {
				logger.Error("http3 server closed: ", sErr)
			}
		}()

		return quicListener, nil
	}
}
