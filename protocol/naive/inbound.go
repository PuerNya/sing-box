package naive

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHttp "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

var ConfigureHTTP3ListenerFunc func(
	logger logger.Logger,
	listener *listener.Listener,
	tlsConfig tls.ServerConfig,
	handler Handler,
) (io.Closer, error)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.NaiveInboundOptions](registry, C.TypeNaive, NewInbound)
}

type Handler interface {
	NewConnection(ctx context.Context, waitForClose bool, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr)
	NewPacketConnection(ctx context.Context, conn N.PacketConn, userName string, source M.Socksaddr, destination M.Socksaddr)
	Authorization(ctx context.Context, request *http.Request) (string, bool, bool)
	BadRequest(ctx context.Context, request *http.Request, err error)
}

type Inbound struct {
	inbound.Adapter
	ctx              context.Context
	router           adapter.ConnectionRouterEx
	logger           logger.ContextLogger
	listener         *listener.Listener
	network          []string
	networkIsDefault bool
	authenticator    *auth.Authenticator
	acceptH3         bool
	tlsConfig        tls.ServerConfig
	httpServer       *http.Server
	h3Server         io.Closer
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.NaiveInboundOptions) (adapter.Inbound, error) {
	inbound := &Inbound{
		Adapter: inbound.NewAdapter(C.TypeNaive, tag),
		ctx:     ctx,
		router:  uot.NewRouter(router, logger),
		logger:  logger,
		listener: listener.New(listener.Options{
			Context: ctx,
			Logger:  logger,
			Listen:  options.ListenOptions,
		}),
		networkIsDefault: options.Network == "",
		network:          options.Network.Build(),
	}
	inbound.acceptH3 = common.Contains(inbound.network, N.NetworkUDP) && options.TLS == nil && options.TLS.Enabled
	if len(options.Users) > 0 {
		inbound.authenticator = auth.NewAuthenticator(options.Users)
	}
	if options.TLS != nil {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
		inbound.acceptH3 = common.Contains(inbound.network, N.NetworkUDP) && tlsConfig != nil
	}
	return inbound, nil
}

func (n *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if n.tlsConfig != nil {
		err := n.tlsConfig.Start()
		if err != nil {
			return E.Cause(err, "create TLS config")
		}
	}
	if common.Contains(n.network, N.NetworkTCP) {
		tcpListener, err := n.listener.ListenTCP()
		if err != nil {
			return err
		}
		n.httpServer = &http.Server{
			Handler: h2c.NewHandler(n, &http2.Server{}),
			BaseContext: func(listener net.Listener) context.Context {
				return n.ctx
			},
		}
		go func() {
			listener := net.Listener(tcpListener)
			if n.tlsConfig != nil {
				if len(n.tlsConfig.NextProtos()) == 0 {
					n.tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
				} else if !common.Contains(n.tlsConfig.NextProtos(), http2.NextProtoTLS) {
					n.tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, n.tlsConfig.NextProtos()...))
				}
				listener = aTLS.NewListener(tcpListener, n.tlsConfig)
			}
			sErr := n.httpServer.Serve(listener)
			if sErr != nil && !errors.Is(sErr, http.ErrServerClosed) {
				n.logger.Error("http server serve error: ", sErr)
			}
		}()
	}

	if n.acceptH3 {
		http3Server, err := ConfigureHTTP3ListenerFunc(n.logger, n.listener, n.tlsConfig, n)
		if err == nil {
			n.h3Server = http3Server
		} else if len(n.network) > 1 {
			n.logger.Warn(E.Cause(err, "naive http3 disabled"))
		} else {
			return err
		}
	}

	return nil
}

func (n *Inbound) Close() error {
	return common.Close(
		&n.listener,
		common.PtrOrNil(n.httpServer),
		n.h3Server,
		n.tlsConfig,
	)
}

func (n *Inbound) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	ctx := log.ContextWithNewID(request.Context())
	if request.Method != http.MethodConnect {
		RejectHTTP(writer, http.StatusBadRequest)
		n.BadRequest(ctx, request, E.New("not CONNECT request"))
		return
	}
	userName, noPadding, authOk := n.Authorization(ctx, request)
	if !authOk {
		RejectHTTP(writer, http.StatusProxyAuthRequired)
		n.BadRequest(ctx, request, E.New("authorization failed"))
		return
	}

	AcceptHTTP(writer, noPadding)

	source, destination := GetSrcDest(request)

	var conn net.Conn
	hijacker, isHijacker := writer.(http.Hijacker)
	if isHijacker {
		var err error
		conn, _, err = hijacker.Hijack()
		if err != nil {
			n.BadRequest(ctx, request, E.New("hijack failed"))
			return
		}
		conn = NewPaddingConn(conn, noPadding)
	} else if noPadding {
		conn = &v2rayhttp.ServerHTTPConn{HTTP2Conn: v2rayhttp.NewHTTPConn(request.Body, writer), Flusher: writer.(http.Flusher)}
	} else {
		conn = &naiveH2Conn{
			reader:        request.Body,
			writer:        writer,
			flusher:       writer.(http.Flusher),
			remoteAddress: source,
		}
	}
	n.NewConnection(ctx, !isHijacker, conn, userName, source, destination)
}

func (n *Inbound) NewConnection(ctx context.Context, waitForClose bool, conn net.Conn, userName string, source M.Socksaddr, destination M.Socksaddr) {
	if userName != "" {
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection from ", source)
		n.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", destination)
	} else {
		n.logger.InfoContext(ctx, "inbound connection from ", source)
		n.logger.InfoContext(ctx, "inbound connection to ", destination)
	}
	var metadata adapter.InboundContext
	metadata.Inbound = n.Tag()
	metadata.InboundType = n.Type()
	//nolint:staticcheck
	metadata.InboundDetour = n.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.InboundOptions = n.listener.ListenOptions().InboundOptions
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName
	if !waitForClose {
		n.router.RouteConnectionEx(ctx, conn, metadata, nil)
	} else {
		done := make(chan struct{})
		wrapper := v2rayhttp.NewHTTP2Wrapper(conn)
		n.router.RouteConnectionEx(ctx, conn, metadata, N.OnceClose(func(it error) {
			close(done)
		}))
		<-done
		wrapper.CloseWrapper()
	}
}

func (n *Inbound) NewPacketConnection(ctx context.Context, conn N.PacketConn, userName string, source M.Socksaddr, destination M.Socksaddr) {
	if userName != "" {
		n.logger.InfoContext(ctx, "[", userName, "] inbound packet connection from ", source)
		n.logger.InfoContext(ctx, "[", userName, "] inbound packet connection to ", destination)
	} else {
		n.logger.InfoContext(ctx, "inbound packet connection from ", source)
		n.logger.InfoContext(ctx, "inbound packet connection to ", destination)
	}
	var metadata adapter.InboundContext
	metadata.Inbound = n.Tag()
	metadata.InboundType = n.Type()
	//nolint:staticcheck
	metadata.InboundDetour = n.listener.ListenOptions().Detour
	//nolint:staticcheck
	metadata.InboundOptions = n.listener.ListenOptions().InboundOptions
	metadata.Source = source
	metadata.Destination = destination
	metadata.OriginDestination = M.SocksaddrFromNet(conn.LocalAddr()).Unwrap()
	metadata.User = userName
	n.router.RoutePacketConnectionEx(ctx, conn, metadata, nil)
}

func (n *Inbound) Authorization(ctx context.Context, request *http.Request) (string, bool, bool) {
	noPadding := request.Header.Get("Padding") == ""
	if n.authenticator == nil {
		return "", noPadding, true
	}
	userName, password, authOk := sHttp.ParseBasicAuth(request.Header.Get("Proxy-Authorization"))
	return userName, noPadding, authOk && n.authenticator.Verify(userName, password)
}

func (n *Inbound) BadRequest(ctx context.Context, request *http.Request, err error) {
	n.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", request.RemoteAddr))
}

func AcceptHTTP(writer http.ResponseWriter, noPadding bool) {
	if !noPadding {
		writer.Header().Set("Padding", generatePaddingHeader())
	}
	writer.WriteHeader(http.StatusOK)
	writer.(http.Flusher).Flush()
}

func RejectHTTP(writer http.ResponseWriter, statusCode int) {
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writer.WriteHeader(statusCode)
		return
	}
	conn, _, err := hijacker.Hijack()
	if err != nil {
		writer.WriteHeader(statusCode)
		return
	}
	if tcpConn, isTCP := common.Cast[*net.TCPConn](conn); isTCP {
		tcpConn.SetLinger(0)
	}
	conn.Close()
}

func GetSrcDest(request *http.Request) (M.Socksaddr, M.Socksaddr) {
	hostPort := request.Header.Get("-connect-authority")
	if hostPort == "" {
		hostPort = request.URL.Host
		if hostPort == "" {
			hostPort = request.Host
		}
	}
	return sHttp.SourceAddress(request), M.ParseSocksaddr(hostPort).Unwrap()
}
