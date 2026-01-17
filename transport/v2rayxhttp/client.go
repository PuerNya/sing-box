package v2rayxhttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	sHTTP "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
)

var _ adapter.V2RayClientTransport = (*Client)(nil)

type Transport interface {
	http.RoundTripper
	CloseIdleConnections()
	Reset()
}

var ConfigureH3Transport func(N.Dialer, M.Socksaddr, tls.Config, time.Duration) (Transport, error)

type Client struct {
	ctx             context.Context
	uploader        Transport
	downloader      Transport
	uploadAddress   M.Socksaddr
	downloadAddress M.Socksaddr
	scheme          string
	host            string
	path            string
	uploadMode      string
	headers         http.Header
	noGRPCHeader    bool
	newBuffer       func() *buffer
}

func NewClient(ctx context.Context, dialer N.Dialer, serverAddr M.Socksaddr, options option.V2RayXHTTPOptions, tlsConfig tls.Config) (adapter.V2RayClientTransport, error) {
	if options.NoSSEHeader {
		return nil, E.New("unsupported option: no_sse_header")
	}
	var uploadMode string
	if options.UploadMode == "" {
		uploadMode = C.XHTTPUploadModeStreamUp
	} else {
		uploadMode = options.UploadMode
	}
	var newBufferFunc func() *buffer
	if uploadMode == C.XHTTPUploadModePacketUp {
		if options.MaxEachPostBytes == 0 {
			newBufferFunc = func() *buffer {
				return newBuffer(C.XHTTPDefaultMaxEachPostBytes)
			}
		} else {
			newBufferFunc = func() *buffer {
				return newBuffer(options.MaxEachPostBytes)
			}
		}
	}
	var uploader, downloader Transport
	var downloadAddress M.Socksaddr
	if downloadServer := options.DownloadServer; downloadServer == "" {
		downloadAddress = serverAddr
	} else {
		downloadAddress = M.ParseSocksaddrHostPort(downloadServer, serverAddr.Port)
	}
	if options.DownloadServerPort != 0 {
		downloadAddress.Port = options.DownloadServerPort
	}
	scheme := "http"
	if tlsConfig == nil {
		if options.PingTimeout > 0 {
			return nil, E.New("unsupported option: ping_timeout")
		}
		if options.IdleTimeout > 0 {
			return nil, E.New("unsupported option: idle_timeout")
		}
		uploader = newTransportWrapper(&http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, serverAddr)
			},
		})
		if options.UploadMode != C.XHTTPUploadModeStreamOne {
			downloader = newTransportWrapper(&http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, downloadAddress)
				},
			})
		}
	} else {
		if alpn := tlsConfig.NextProtos(); len(alpn) == 1 && alpn[0] == http3.NextProtoH3 {
			scheme = "https"
			if options.PingTimeout > 0 {
				return nil, E.New("unsupported option: ping_timeout")
			}
			var err error
			uploader, err = ConfigureH3Transport(dialer, serverAddr, tlsConfig, time.Duration(options.IdleTimeout))
			if err != nil {
				return nil, err
			}

			if options.UploadMode != C.XHTTPUploadModeStreamOne {
				uploader, err = ConfigureH3Transport(dialer, downloadAddress, tlsConfig, time.Duration(options.IdleTimeout))
				if err != nil {
					return nil, err
				}
			}
		} else {
			if options.IdleTimeout > 0 {
				return nil, E.New("unsupported option: idle_timeout")
			}
			tlsConfig.SetNextProtos([]string{http2.NextProtoTLS, "http/1.1"})
			tlsDialer := tls.NewDialer(dialer, tlsConfig)
			builder := func(destination M.Socksaddr) Transport {
				protocols := new(http.Protocols)
				protocols.SetHTTP1(true)
				protocols.SetUnencryptedHTTP2(true)
				return newTransportWrapper(&http.Transport{
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						conn, err := tlsDialer.DialTLSContext(ctx, destination)
						if err != nil {
							return nil, err
						}
						err = conn.HandshakeContext(ctx)
						if err != nil {
							conn.Close()
							return nil, err
						}
						if conn.ConnectionState().NegotiatedProtocol == http2.NextProtoTLS {
							protocols.SetHTTP1(false)
						} else {
							protocols.SetHTTP1(true)
						}
						return conn, nil
					},
					HTTP2: &http.HTTP2Config{
						SendPingTimeout: time.Duration(options.PingTimeout),
						PingTimeout:     time.Duration(options.PingTimeout),
					},
					Protocols: protocols,
				})
			}
			uploader = builder(serverAddr)
			if options.UploadMode != C.XHTTPUploadModeStreamOne {
				downloader = builder(downloadAddress)
			}
		}
	}
	testUrl := url.URL{
		Host: "www.baidu.com",
		Path: options.Path,
	}
	err := sHTTP.URLSetPath(&testUrl, options.Path)
	if err != nil {
		return nil, E.Cause(err, "parse path")
	}
	if !strings.HasPrefix(testUrl.Path, "/") {
		testUrl.Path = "/" + testUrl.Path
	}
	if !strings.HasSuffix(testUrl.Path, "/") {
		testUrl.Path = testUrl.Path + "/"
	}
	return &Client{
		ctx:             ctx,
		uploadMode:      uploadMode,
		uploadAddress:   serverAddr,
		downloadAddress: downloadAddress,
		scheme:          scheme,
		host:            options.ClientHost,
		path:            testUrl.Path,
		headers:         options.Headers.Build(),
		uploader:        uploader,
		downloader:      downloader,
		noGRPCHeader:    options.NoGRPCHeader,
		newBuffer:       newBufferFunc,
	}, nil
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	switch c.uploadMode {
	case C.XHTTPUploadModeStreamUp:
		return c.establishStreamUpConn(ctx)
	case C.XHTTPUploadModePacketUp:
		return c.establishPacketUpConn(ctx)
	case C.XHTTPUploadModeStreamOne:
		return c.establishStreamOneConn(ctx)
	default:
		return nil, E.New("v2ray-xhttp: unexpected mode: ", c.uploadMode)
	}
}

func (c *Client) establishPacketUpConn(ctx context.Context) (net.Conn, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	pipeReader, pipeWriter := io.Pipe()
	conn := NewLateReadSplitConn(pipeWriter)
	closed := NewCloser()
	pool := newPool(c.newBuffer, 30)
	closed.OnClose(pool.Close)
	conn.OnClose(pool.Close)
	go func() {
		var packetId uint64
		var notInit bool
		for {
			access := make(chan struct{})
			if !notInit {
				close(access)
				notInit = true
			} else {
				time.AfterFunc(30*time.Microsecond, func() {
					close(access)
				})
			}
			buffer := pool.get()
			_, err := buffer.readFrom(pipeReader)
			if err != nil && err != io.EOF {
				closed.Close()
				pipeWriter.CloseWithError(err)
				break
			}
			ctx, cancel := context.WithCancel(ctx)
			request := c.newRequestWithContext(ctx, buffer)
			request.URL.Path = fmt.Sprintf("%s%s/%d", request.URL.Path, id, packetId)
			packetId++
			go func() {
				select {
				case <-closed.Done():
					cancel()
					return
				case <-access:
				}
				var response *http.Response
				var err error
				done := make(chan struct{})
				go func() {
					response, err = c.uploader.RoundTrip(request)
					close(done)
				}()
				select {
				case <-closed.Done():
					cancel()
					return
				case <-done:
				}
				cancel()
				if err != nil {
					closed.Close()
					pipeWriter.CloseWithError(err)
					return
				}
				response.Body.Close()
				if response.StatusCode != 200 {
					closed.Close()
					pipeWriter.CloseWithError(E.New("v2ray-xhttp[packet-up/upload]: unexpected status: ", response.Status))
				}
			}()
			if errors.Is(err, io.EOF) {
				break
			}
		}
	}()
	go func() {
		request := c.newRequestWithContext(ctx, nil)
		request.URL.Path = request.URL.Path + id.String()
		response, err := c.downloader.RoundTrip(request)
		if err != nil {
			closed.Close()
			conn.SetupReader(nil, err)
		} else if response.StatusCode != 200 {
			closed.Close()
			response.Body.Close()
			conn.SetupReader(nil, E.New("v2ray-xhttp[packet-up/download]: unexpected status: ", response.Status))
		} else {
			conn.SetupReader(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) establishStreamUpConn(ctx context.Context) (net.Conn, error) {
	id, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}
	pipeReader, pipeWriter := io.Pipe()
	conn := NewLateSplitConn()
	go func() {
		request := c.newRequestWithContext(ctx, pipeReader)
		request.URL.Path = request.URL.Path + id.String()
		response, err := c.uploader.RoundTrip(request)
		if err != nil {
			conn.SetupWriter(nil, err)
		} else if response.StatusCode != 200 {
			response.Body.Close()
			conn.SetupWriter(nil, E.New("v2ray-xhttp[stream-one/upload]: unexpected status: ", response.Status))
		} else {
			conn.OnClose(func() {
				response.Body.Close()
			})
			conn.SetupWriter(pipeWriter, nil)
		}
	}()
	go func() {
		request := c.newRequestWithContext(ctx, nil)
		request.URL.Path = request.URL.Path + id.String()
		response, err := c.downloader.RoundTrip(request)
		if err != nil {
			conn.SetupReader(nil, err)
		} else if response.StatusCode != 200 {
			response.Body.Close()
			conn.SetupReader(nil, E.New("v2ray-xhttp[stream-one/downolad]: unexpected status: ", response.Status))
		} else {
			conn.SetupReader(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) establishStreamOneConn(ctx context.Context) (net.Conn, error) {
	pipeInReader, pipeInWriter := io.Pipe()
	conn := NewLateReadSplitConn(pipeInWriter)
	go func() {
		request := c.newRequestWithContext(ctx, pipeInReader)
		response, err := c.uploader.RoundTrip(request)
		if err != nil {
			conn.SetupReader(nil, err)
		} else if response.StatusCode != 200 {
			response.Body.Close()
			conn.SetupReader(nil, E.New("v2ray-xhttp[stream-one]: unexpected status: ", response.Status))
		} else {
			conn.SetupReader(response.Body, nil)
		}
	}()
	return conn, nil
}

func (c *Client) newRequestWithContext(ctx context.Context, body io.Reader) *http.Request {
	request := &http.Request{
		Header: c.headers.Clone(),
	}
	var host string
	if body == nil {
		request.Method = http.MethodGet
		host = c.downloadAddress.String()
	} else {
		request.Method = http.MethodPost
		host = c.uploadAddress.String()
		if closer, isCloser := body.(io.ReadCloser); !isCloser {
			request.Body = io.NopCloser(body)
		} else {
			request.Body = closer
			if !c.noGRPCHeader {
				request.Header.Set("Content-Type", "application/grpc")
			}
		}
	}
	if c.host != "" {
		host = c.host
	}
	request.URL = &url.URL{
		Host:   host,
		Scheme: c.scheme,
		Path:   c.path,
	}
	sHTTP.URLSetPath(request.URL, c.path)
	refererUrl := *request.URL
	values := refererUrl.Query()
	values.Set("x_padding", "XXX"+generateRandomPaddingString())
	refererUrl.RawQuery = values.Encode()
	request.Header.Set("Referer", refererUrl.String())
	return request.WithContext(ctx)
}

func (c *Client) Close() error {
	c.uploader.Reset()
	if c.downloader != nil {
		c.downloader.Reset()
	}
	return nil
}
