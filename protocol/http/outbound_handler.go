package http

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/transport/v2rayhttp"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	sHTTP "github.com/sagernet/sing/protocol/http"

	"golang.org/x/net/http2"
)

func (h *httpDialer) newRequest(destination M.Socksaddr) (*http.Request, error) {
	request := &http.Request{
		Method: http.MethodConnect,
		Header: http.Header{},
	}
	if h.host != "" && h.host != destination.Fqdn {
		if h.path != "" {
			return nil, E.New("Host header and path are not allowed at the same time")
		}
		request.Host = h.host
		request.URL = &url.URL{Opaque: destination.String()}
	} else {
		request.URL = &url.URL{Host: destination.String()}
	}
	if h.path != "" {
		err := sHTTP.URLSetPath(request.URL, h.path)
		if err != nil {
			return nil, err
		}
	}
	for key, valueList := range h.headers {
		request.Header.Set(key, valueList[0])
		for _, value := range valueList[1:] {
			request.Header.Add(key, value)
		}
	}
	if h.username != "" {
		request.Header.Add("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(h.username+":"+h.password)))
	}
	if h.haveFun {
		request.Header.Set("Padding", generateNaivePaddingHeader())
	}
	return request, nil
}

func (h *httpDialer) handleHTTP1(conn net.Conn, destination M.Socksaddr) (net.Conn, error) {
	request, err := h.newRequest(destination)
	request.URL.Scheme = "http"
	if err != nil {
		conn.Close()
		return nil, err
	}
	request.Header.Set("Proxy-Connection", "Keep-Alive")
	err = request.Write(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		conn.Close()
		return nil, err
	}
	response.Body.Close()
	if statusCode := response.StatusCode; statusCode != http.StatusOK {
		conn.Close()
		return nil, E.New("Unexpected status: ", statusCode)
	}
	if h.haveFun {
		return &funnyConn{Conn: conn}, nil
	} else {
		return conn, nil
	}
}

func (h *httpDialer) dialHTTP1(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := h.dialer.DialContext(ctx, network, h.server)
	if err != nil {
		return nil, err
	}
	return h.handleHTTP1(conn, destination)
}

type client struct {
	checked   bool
	transport *http2.Transport
	sync.Mutex
}

func (h *httpDialer) dialTLSContext(ctx context.Context, network string) (tls.Conn, error) {
	conn, err := h.dialer.DialContext(ctx, network, h.server)
	if err != nil {
		return nil, err
	}
	return tls.ClientHandshake(ctx, conn, h.tlsConfig)
}

func (h *httpDialer) handleH2(ctx context.Context, roundTripper http.RoundTripper, destination M.Socksaddr) (net.Conn, error) {
	pipeInReader, pipeInWriter := io.Pipe()
	request, err := h.newRequest(destination)
	request.URL.Scheme = "https"
	if err != nil {
		return nil, E.Cause(err, "new request")
	}
	request.Body = pipeInReader
	conn := v2rayhttp.NewLateHTTPConn(pipeInWriter)
	go func() {
		response, err := roundTripper.RoundTrip(request.WithContext(ctx))
		if err != nil {
			conn.Setup(nil, err)
		} else if response.StatusCode != 200 {
			response.Body.Close()
			conn.Setup(nil, E.New("Unexpected status: ", response.Status))
		} else {
			conn.Setup(response.Body, nil)
		}
	}()
	if h.haveFun {
		return &funnyConn{Conn: conn}, nil
	} else {
		return conn, nil
	}
}

func (h *httpDialer) dialH2(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	h.h2.Lock()
	if !h.h2.checked {
		conn, err := h.dialTLSContext(ctx, network)
		if err != nil {
			return nil, err
		}
		h.h2.checked = true
		if conn.ConnectionState().NegotiatedProtocol != http2.NextProtoTLS {
			h.h2.Unlock()
			return h.handleHTTP1(conn, destination)
		}
		h.h2.transport = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.STDConfig) (net.Conn, error) {
				return h.dialTLSContext(ctx, network)
			},
		}
		_, err = h.h2.transport.NewClientConn(conn)
		h.h2.Unlock()
		if err != nil {
			conn.Close()
		}
		return h.handleH2(ctx, h.h2.transport, destination)
	}
	h.h2.Unlock()
	if h.h2.transport != nil {
		return h.handleH2(ctx, h.h2.transport, destination)
	}
	conn, err := h.dialTLSContext(ctx, network)
	if err != nil {
		return nil, err
	}
	return h.handleHTTP1(conn, destination)
}

func generateNaivePaddingHeader() string {
	paddingLen := rand.Intn(32) + 30
	padding := make([]byte, paddingLen)
	bits := rand.Uint64()
	for i := 0; i < 16; i++ {
		// Codes that won't be Huffman coded.
		padding[i] = "!#$()+<>?@[]^`{}"[bits&15]
		bits >>= 4
	}
	for i := 16; i < paddingLen; i++ {
		padding[i] = '~'
	}
	return string(padding)
}
