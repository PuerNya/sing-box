package quic

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	sTLS "github.com/sagernet/sing-box/common/tls"
	sHTTP "github.com/sagernet/sing-box/protocol/http"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type clientConn struct {
	*http3.ClientConn
	quicConn  *quic.Conn
	rawConn   io.Closer
	closeOnce sync.Once
	connDone  chan struct{}
	connErr   error
}

func (c *clientConn) active() bool {
	select {
	case <-c.quicConn.Context().Done():
		return false
	default:
	}
	select {
	case <-c.connDone:
		return false
	default:
	}
	return true
}

func (c *clientConn) closeWithError(err error) {
	c.closeOnce.Do(func() {
		c.connErr = err
		close(c.connDone)
		_ = c.quicConn.CloseWithError(0, "")
		_ = c.rawConn.Close()
	})
}

type h3Dialer struct {
	serverAddress M.Socksaddr
	dialer        N.Dialer
	quicConfig    *quic.Config
	tlsConfig     sTLS.Config
	factor        sHTTP.RequsetFactor
	conn          *clientConn
	connAccess    sync.Mutex
}

func (d *h3Dialer) offer(ctx context.Context) (*clientConn, error) {
	d.connAccess.Lock()
	defer d.connAccess.Unlock()
	conn := d.conn
	if conn != nil && conn.active() {
		return conn, nil
	}
	conn, err := d.offerNew(ctx)
	if err != nil {
		return nil, err
	}
	d.conn = conn
	return conn, nil
}

func (d *h3Dialer) offerNew(ctx context.Context) (*clientConn, error) {
	udpConn, err := d.dialer.DialContext(ctx, "udp", d.serverAddress)
	if err != nil {
		return nil, err
	}
	quicConn, err := qtls.DialEarly(ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), d.tlsConfig, d.quicConfig)
	if err != nil {
		udpConn.Close()
		return nil, err
	}
	transport := &http3.Transport{
		EnableDatagrams: true,
	}
	return &clientConn{
		ClientConn: transport.NewClientConn(quicConn),
		quicConn:   quicConn,
		rawConn:    udpConn,
		connDone:   make(chan struct{}),
	}, nil
}

func (d *h3Dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	c, err := d.offer(ctx)
	if err != nil {
		return nil, err
	}
	request, err := d.factor.NewRequest(destination)
	if err != nil {
		return nil, err
	}
	request.URL.Scheme = "https"
	var connFactor func(stream *http3.RequestStream) lateConn
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		connFactor = func(stream *http3.RequestStream) lateConn { return newLateNetConn(stream, destination) }
	case N.NetworkUDP:
		request.Method = "CONNECT-UDP"
		connFactor = func(stream *http3.RequestStream) lateConn { return newLateConnectPacketConn(ctx, stream, destination) }
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	stream, err := c.OpenRequestStream(ctx)
	if err != nil {
		c.closeWithError(err)
		c, err = d.offer(ctx)
		if err != nil {
			return nil, err
		}
		stream, err = c.OpenRequestStream(ctx)
		if err != nil {
			c.closeWithError(err)
			return nil, err
		}
	}
	err = stream.SendRequestHeader(request)
	if err != nil {
		stream.Close()
		return nil, err
	}
	conn := connFactor(stream)
	go func() {
		if response, err := stream.ReadResponse(); err != nil {
			conn.Setup(err)
			conn.Close()
		} else if statusCode := response.StatusCode; statusCode != http.StatusOK {
			conn.Setup(E.New("Unexpected status: ", statusCode))
			conn.Close()
		} else {
			conn.Setup(nil)
		}
	}()
	return conn, nil
}

func (d *h3Dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	c, err := d.offer(ctx)
	if err != nil {
		return nil, err
	}
	request, err := d.factor.NewRequest(destination)
	if err != nil {
		return nil, err
	}
	request.URL.Scheme = "https"
	request.Method = "BIND-UDP"
	stream, err := c.OpenRequestStream(ctx)
	if err != nil {
		c.closeWithError(err)
		c, err = d.offer(ctx)
		if err != nil {
			return nil, err
		}
		stream, err = c.OpenRequestStream(ctx)
		if err != nil {
			c.closeWithError(err)
			return nil, err
		}
	}
	err = stream.SendRequestHeader(request)
	if err != nil {
		stream.Close()
		return nil, err
	}
	conn := newLateBindPacketConn(ctx, stream)
	go func() {
		if response, err := stream.ReadResponse(); err != nil {
			conn.Setup(err)
			conn.Close()
		} else if statusCode := response.StatusCode; statusCode != http.StatusOK {
			conn.Setup(E.New("Unexpected status: ", statusCode))
			conn.Close()
		} else {
			conn.Setup(nil)
		}
	}()
	return conn, nil
}
