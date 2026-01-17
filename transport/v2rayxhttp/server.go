package v2rayxhttp

import (
	"context"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	sHttp "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
)

var _ adapter.V2RayServerTransport = (*Server)(nil)

var ConfigureH3Listener func(handler http.Handler, tlsConfig tls.ServerConfig) (HTTPServer, error)

type HTTPServer interface {
	Serve(conn net.PacketConn) error
	Close() error
}

type Server struct {
	ctx         context.Context
	logger      logger.ContextLogger
	tlsConfig   tls.ServerConfig
	handler     adapter.V2RayServerTransportHandler
	httpServer  *http.Server
	h2Server    *http2.Server
	h3Server    HTTPServer
	h2cHandler  http.Handler
	path        string
	headers     http.Header
	noSSEHeader bool
	connStore   map[string]*ExpireConn
	connAccess  sync.Mutex
	newBuffer   func() *buffer
}

func NewServer(ctx context.Context, logger logger.ContextLogger, options option.V2RayXHTTPOptions, tlsConfig tls.ServerConfig, handler adapter.V2RayServerTransportHandler) (*Server, error) {
	var unknownOption string
	switch {
	case options.UploadMode != "":
		unknownOption = "upload_mode"
	case options.NoGRPCHeader:
		unknownOption = "no_grpc_header"
	case options.ClientHost != "":
		unknownOption = "client_host"
	case options.DownloadServer != "":
		unknownOption = "download_server"
	case options.DownloadServerPort > 0:
		unknownOption = "download_server_port"
	case options.DownloadServerPort > 0:
		unknownOption = "download_server_port"
	}
	if unknownOption != "" {
		return nil, E.New("unsupported option: ", unknownOption)
	}
	maxEachPostBytes := options.MaxEachPostBytes
	if maxEachPostBytes == 0 {
		maxEachPostBytes = C.XHTTPDefaultMaxEachPostBytes
	}
	server := &Server{
		ctx:         ctx,
		tlsConfig:   tlsConfig,
		logger:      logger,
		handler:     handler,
		path:        options.Path,
		noSSEHeader: options.NoSSEHeader,
		headers:     options.Headers.Build(),
		connStore:   make(map[string]*ExpireConn),
		newBuffer: func() *buffer {
			return newBuffer(maxEachPostBytes)
		},
	}
	if !strings.HasPrefix(server.path, "/") {
		server.path = "/" + server.path
	}
	if !strings.HasSuffix(server.path, "/") {
		server.path = server.path + "/"
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(true)
	server.httpServer = &http.Server{
		Handler:           server,
		ReadHeaderTimeout: C.TCPTimeout,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return log.ContextWithNewID(ctx)
		},
		Protocols: protocols,
		HTTP2: &http.HTTP2Config{
			SendPingTimeout: time.Duration(options.PingTimeout),
			PingTimeout:     time.Duration(options.PingTimeout),
		},
	}
	if tlsConfig != nil {
		if len(tlsConfig.NextProtos()) == 0 {
			tlsConfig.SetNextProtos([]string{http3.NextProtoH3, http2.NextProtoTLS, "http/1.1"})
		} else if !common.Contains(tlsConfig.NextProtos(), http2.NextProtoTLS) {
			tlsConfig.SetNextProtos(append([]string{http2.NextProtoTLS}, tlsConfig.NextProtos()...))
		}
		if common.Contains(tlsConfig.NextProtos(), http3.NextProtoH3) {
			h3Server, err := ConfigureH3Listener(server, tlsConfig)
			if err != nil {
				return nil, err
			}
			server.h3Server = h3Server
			tlsConfig.SetNextProtos(common.Filter(tlsConfig.NextProtos(), func(alpn string) bool {
				return alpn != http3.NextProtoH3
			}))
		}
	}
	return server, nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if !common.Contains([]string{http.MethodGet, http.MethodPost}, request.Method) {
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("bad method: ", request.Method))
		return
	}
	if !strings.HasPrefix(request.URL.Path, s.path) {
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("bad path: ", request.URL.Path))
		return
	}

	for key, values := range s.headers {
		for _, value := range values {
			writer.Header().Set(key, value)
		}
	}

	suffix, hasSuffix := strings.CutPrefix(request.URL.Path, s.path)
	switch request.Method {
	case http.MethodGet:
		if !hasSuffix || len(suffix) == 0 {
			s.invalidRequest(writer, request, http.StatusNotFound, E.New("empty uuid"))
		} else {
			if strings.HasSuffix(suffix, "/") {
				suffix = strings.TrimRight(suffix, "/")
			}
			if strings.Contains(suffix, "/") {
				s.invalidRequest(writer, request, http.StatusNotFound, E.New("invalid uuid: ", suffix))
			} else {
				request.Body.Close()
				s.logger.TraceContext(request.Context(), "[v2rayxhttp] inbound download request, uuid: ", suffix)
				s.handleDownloadConn(writer, request, suffix)
			}
		}
	case http.MethodPost:
		if !hasSuffix || len(suffix) == 0 {
			s.logger.TraceContext(request.Context(), "[v2rayxhttp] inbound stream one connection")
			s.handleStreamOneConn(writer, request)
		} else if uuid, rawPacketId, hasPacketId := strings.Cut(suffix, "/"); !hasPacketId || len(rawPacketId) == 0 {
			s.logger.TraceContext(request.Context(), "[v2rayxhttp] inbound stream up request, uuid: ", uuid)
			s.handleStreamUpConn(writer, request, uuid)
		} else if packetId, err := strconv.Atoi(rawPacketId); err != nil || packetId < 0 {
			s.invalidRequest(writer, request, http.StatusNotFound, E.New("invalid packet id"))
		} else {
			s.logger.TraceContext(request.Context(), "[v2rayxhttp] inbound packet up request, uuid: ", uuid, " packet id: ", packetId)
			s.handlePacketUpConn(writer, request, uuid, uint64(packetId))
		}
	}
}

func (s *Server) handleStreamOneConn(writer http.ResponseWriter, request *http.Request) {
	s.acceptRequest(writer, request, true)

	conn := NewConnWrapper(NewSplitConn(request.Body, writer))
	s.handler.NewConnectionEx(request.Context(), conn, sHttp.SourceAddress(request), M.Socksaddr{}, N.OnceClose(func(it error) {
		conn.CloseWrapper()
	}))
	conn.Wait()
}

func (s *Server) handleDownloadConn(writer http.ResponseWriter, request *http.Request, uuid string) {
	s.connAccess.Lock()
	conn, exists := s.connStore[uuid]
	if !exists {
		conn = &ExpireConn{
			ConnWrapper: NewConnWrapper(NewLateReadSplitConn(writer)),
			expire:      time.Now().Add(time.Second * 30),
		}
		s.connStore[uuid] = conn
		s.connAccess.Unlock()
		go s.handler.NewConnectionEx(request.Context(), conn, sHttp.SourceAddress(request), M.Socksaddr{}, N.OnceClose(func(it error) {
			conn.CloseWrapper()
		}))
	} else if conn.RawConn.writer != nil || conn.RawConn.wErr != nil {
		s.connAccess.Unlock()
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("writer already set"))
		return
	} else if conn.expire.Before(time.Now()) {
		s.connAccess.Unlock()
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("match conn expire"))
		conn.Close()
		return
	} else {
		conn.RawConn.SetupWriter(writer, nil)
		s.connAccess.Unlock()
	}

	s.acceptRequest(writer, request, true)

	conn.Wait()
}

func (s *Server) handleStreamUpConn(writer http.ResponseWriter, request *http.Request, uuid string) {
	s.connAccess.Lock()
	conn, exists := s.connStore[uuid]
	if !exists {
		conn = &ExpireConn{
			ConnWrapper: NewConnWrapper(NewLateWriteSplitConn(request.Body)),
			expire:      time.Now().Add(time.Second * 30),
		}
		s.connStore[uuid] = conn
		s.connAccess.Unlock()
		go s.handler.NewConnectionEx(request.Context(), conn, sHttp.SourceAddress(request), M.Socksaddr{}, N.OnceClose(func(it error) {
			conn.CloseWrapper()
		}))
	} else if conn.RawConn.reader != nil || conn.RawConn.rErr != nil {
		s.connAccess.Unlock()
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("reader already set"))
		return
	} else if conn.expire.Before(time.Now()) {
		s.connAccess.Unlock()
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("match conn expire"))
		conn.Close()
		return
	} else {
		conn.RawConn.SetupReader(request.Body, nil)
		s.connAccess.Unlock()
	}

	s.acceptRequest(writer, request, false)

	conn.Wait()
}

func (s *Server) handlePacketUpConn(writer http.ResponseWriter, request *http.Request, uuid string, id uint64) {
	var pipe *LimitPacketPipe
	s.connAccess.Lock()
	conn, exists := s.connStore[uuid]
	if !exists {
		pipe = NewLimitPacketPipe(s.newBuffer)
		conn = &ExpireConn{
			ConnWrapper: NewConnWrapper(NewLateWriteSplitConn(pipe)),
			expire:      time.Now().Add(time.Second * 30),
		}
		s.connStore[uuid] = conn
		s.connAccess.Unlock()
		go s.handler.NewConnectionEx(request.Context(), conn, sHttp.SourceAddress(request), M.Socksaddr{}, N.OnceClose(func(it error) {
			conn.CloseWrapper()
		}))
	} else if conn.RawConn.reader != nil {
		s.connAccess.Unlock()
		var isPipe bool
		pipe, isPipe = conn.RawConn.reader.(*LimitPacketPipe)
		if !isPipe {
			s.invalidRequest(writer, request, http.StatusNotFound, E.New("invalid reader type"))
			return
		}
	} else if conn.RawConn.rErr != nil {
		s.connAccess.Unlock()
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("reader already set"))
		return
	} else if conn.expire.Before(time.Now()) {
		s.connAccess.Unlock()
		s.invalidRequest(writer, request, http.StatusNotFound, E.New("match conn expire"))
		conn.Close()
		return
	} else {
		pipe = NewLimitPacketPipe(s.newBuffer)
		conn.RawConn.SetupReader(pipe, nil)
		s.connAccess.Unlock()
	}

	conn.RawConn.OnClose(runtime.GC)

	err := pipe.Push(request.Body, id)
	request.Body.Close()
	runtime.GC()
	if err != nil {
		s.invalidRequest(writer, request, http.StatusNotFound, err)
		return
	}

	s.acceptRequest(writer, request, false)
}

func (s *Server) acceptRequest(writer http.ResponseWriter, request *http.Request, isStreamReply bool) {
	writer.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	writer.Header().Set("Access-Control-Allow-Origin", "*")
	writer.Header().Set("X-Padding", "XXX"+"aaa")
	if isStreamReply {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Accel-Buffering", "no")
		if !s.noSSEHeader {
			writer.Header().Set("Content-Type", "text/event-stream")
		} else if contentType := request.Header.Get("Content-Type"); contentType != "" {
			writer.Header().Set("Content-Type", contentType)
		}
		if request.ProtoMajor == 1 && request.ProtoMinor == 1 {
			writer.Header().Set("Transfer-Encoding", "chunked")
		}
	}
	writer.WriteHeader(http.StatusOK)
	if flusher, isFlusher := writer.(http.Flusher); isFlusher {
		flusher.Flush()
	}
}

func (s *Server) invalidRequest(writer http.ResponseWriter, request *http.Request, statusCode int, err error) {
	if statusCode > 0 {
		writer.WriteHeader(statusCode)
	}
	s.logger.ErrorContext(request.Context(), E.Cause(err, "process connection from ", request.RemoteAddr))
}

func (s *Server) Network() []string {
	if s.h3Server != nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	} else {
		return []string{N.NetworkTCP}
	}
}

func (s *Server) Serve(listener net.Listener) error {
	if s.tlsConfig != nil {
		listener = aTLS.NewListener(listener, s.tlsConfig)
	}
	return s.httpServer.Serve(listener)
}

func (s *Server) ServePacket(listener net.PacketConn) error {
	if s.h3Server == nil {
		return E.New("no h3 server support")
	}
	return s.h3Server.Serve(listener)
}

func (s *Server) Close() error {
	return common.Close(common.PtrOrNil(s.httpServer), s.h3Server)
}
