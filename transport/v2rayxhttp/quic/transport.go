package quic

import (
	"github.com/sagernet/quic-go/http3"
)

type transportWrapper struct {
	*http3.Transport
	builder func() *http3.Transport
}

func (w *transportWrapper) Reset() {
	w.Transport.CloseIdleConnections()
	w.Transport.Close()
	w.Transport = w.builder()
}
