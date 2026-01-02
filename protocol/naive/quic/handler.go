package quic

import (
	"context"
	"net"
	"net/http"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/naive"
	E "github.com/sagernet/sing/common/exceptions"
)

type h3Handler struct {
	handler   naive.Handler
	localAddr net.Addr
}

func newHandler(handler naive.Handler, localAddr net.Addr) http.Handler {
	return &h3Handler{
		handler:   handler,
		localAddr: localAddr,
	}
}

func (h *h3Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	switch request.Method {
	case http.MethodConnect:
		h.newConnection(ctx, writer, request)
	case "CONNECT-UDP":
		h.newConnectPacketConn(ctx, writer, request)
	case "BIND-UDP":
		h.newBindPacketConn(ctx, writer, request)
	default:
		naive.RejectHTTP(writer, http.StatusBadRequest)
		h.handler.BadRequest(ctx, request, E.New("Unsupported request"))
		return
	}
}

func (h *h3Handler) newConnection(ctx context.Context, writer http.ResponseWriter, request *http.Request) {
	source, destination := naive.GetSrcDest(request)
	userName, noPadding, authOk := h.handler.Authorization(ctx, request)
	if !authOk {
		naive.RejectHTTP(writer, http.StatusProxyAuthRequired)
		h.handler.BadRequest(ctx, request, E.New("authorization failed"))
		return
	}
	naive.AcceptHTTP(writer, noPadding)
	stream := h.getStream(ctx, writer, request)
	if stream != nil {
		h.handler.NewConnection(ctx, false, newPaddingConn(stream, h.localAddr, destination, noPadding), userName, source, destination)
	}
}

func (h *h3Handler) newConnectPacketConn(ctx context.Context, writer http.ResponseWriter, request *http.Request) {
	stream := h.getStream(ctx, writer, request)
	if stream == nil {
		return
	}
	source, destination := naive.GetSrcDest(request)
	conn := newConnectPacketConn(ctx, h.localAddr, stream, destination)
	userName, noPadding, authOk := h.handler.Authorization(ctx, request)
	if !authOk {
		naive.RejectHTTP(writer, http.StatusProxyAuthRequired)
		h.handler.BadRequest(ctx, request, E.New("authorization failed"))
		stream.Close()
	} else {
		go naive.AcceptHTTP(writer, noPadding)
		h.handler.NewPacketConnection(ctx, conn, userName, source, destination)
	}
}

func (h *h3Handler) newBindPacketConn(ctx context.Context, writer http.ResponseWriter, request *http.Request) {
	stream := h.getStream(ctx, writer, request)
	if stream == nil {
		return
	}
	source, destination := naive.GetSrcDest(request)
	conn := newBindPacketConn(ctx, h.localAddr, stream)
	userName, noPadding, authOk := h.handler.Authorization(ctx, request)
	if !authOk {
		naive.RejectHTTP(writer, http.StatusProxyAuthRequired)
		h.handler.BadRequest(ctx, request, E.New("authorization failed"))
		stream.Close()
	} else {
		go naive.AcceptHTTP(writer, noPadding)
		h.handler.NewPacketConnection(ctx, conn, userName, source, destination)
	}
}

func (h *h3Handler) getStream(ctx context.Context, writer http.ResponseWriter, request *http.Request) *http3.Stream {
	streamer, isStreamer := writer.(http3.HTTPStreamer)
	if !isStreamer {
		naive.RejectHTTP(writer, http.StatusBadRequest)
		h.handler.BadRequest(ctx, request, E.New("not a http3 streamer"))
		return nil
	}
	return streamer.HTTPStream()
}
