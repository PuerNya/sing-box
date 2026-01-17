package v2rayxhttp

import "net/http"

type transportWrapper struct {
	*http.Transport
}

func newTransportWrapper(transport *http.Transport) *transportWrapper {
	return &transportWrapper{Transport: transport}
}

func (t *transportWrapper) Reset() {
	t.Transport.CloseIdleConnections()
	t.Transport = t.Transport.Clone()
}
