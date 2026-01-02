package quic

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const MaxUDPSize = 4096

const (
	TypeIPv4 = 1
	TypeFqdn = 3
	TypeIPv6 = 4
)

type streamConn struct {
	*http3.Stream
	localAddr   net.Addr
	destination M.Socksaddr
}

func newPaddingConn(stream *http3.Stream, localAddr net.Addr, destination M.Socksaddr, noPadding bool) net.Conn {
	return naive.NewPaddingConn(&streamConn{
		Stream:      stream,
		localAddr:   localAddr,
		destination: destination,
	}, noPadding)
}

func (c *streamConn) LocalAddr() net.Addr  { return c.localAddr }
func (c *streamConn) RemoteAddr() net.Addr { return c.destination }

type connectPacketConn struct {
	*http3.Stream
	ctx         context.Context
	data        chan []byte
	localAddr   net.Addr
	destination M.Socksaddr
}

func newConnectPacketConn(ctx context.Context, localAddr net.Addr, stream *http3.Stream, destination M.Socksaddr) *connectPacketConn {
	conn := &connectPacketConn{
		Stream:      stream,
		ctx:         ctx,
		data:        make(chan []byte, 64),
		localAddr:   localAddr,
		destination: destination,
	}
	go func() {
		for {
			data, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				stream.Close()
				return
			}
			conn.data <- data
		}
	}()
	return conn
}

func (c *connectPacketConn) LocalAddr() net.Addr { return c.localAddr }

func (c *connectPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case p := <-c.data:
		_, err := buffer.Write(p)
		return c.destination, err
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *connectPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.data:
		n := copy(p, pkt)
		if c.destination.IsFqdn() {
			return n, c.destination, nil
		} else {
			return n, c.destination.UDPAddr(), nil
		}
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	}
}

func (c *connectPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if destination.String() != c.destination.String() {
		return nil
	}
	if buffer.Len() > MaxUDPSize {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: MaxUDPSize}
	}
	return c.SendDatagram(buffer.Bytes())
}

func (c *connectPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if c.destination.String() != addr.String() {
		return 0, nil
	}
	if len(p) > MaxUDPSize {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: MaxUDPSize}
	}
	err := c.SendDatagram(p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

type udpMessage struct {
	destination M.Socksaddr
	data        []byte
}

func fromBuffer(buffer *buf.Buffer, destination M.Socksaddr) *udpMessage {
	return &udpMessage{
		destination: destination,
		data:        buffer.Bytes(),
	}
}

func fromBytes(p []byte, addr net.Addr) *udpMessage {
	return &udpMessage{
		destination: M.SocksaddrFromNet(addr),
		data:        p,
	}
}

func (s *udpMessage) unpack(b []byte) error {
	if len(b) < 1 {
		return E.New("empty data")
	}
	switch b[0] {
	case TypeIPv4:
		if len(b) < 7 {
			return E.New("ipv4 address incomplete")
		}
		addr, ok := netip.AddrFromSlice(b[1:5])
		if !ok {
			return E.New("invalid ipv4 address")
		}
		s.destination.Addr = addr
		s.destination.Port = binary.BigEndian.Uint16(b[5:7])
		s.data = b[7:]
		return nil
	case TypeFqdn:
		addrLen := uint8(b[1])
		if len(b) < int(addrLen+1) {
			return E.New("fqdn address incomplete")
		}
		s.destination.Fqdn = string(b[2 : 2+addrLen])
		s.destination.Port = binary.BigEndian.Uint16(b[2+addrLen : 4+addrLen])
		s.data = b[7+addrLen:]
		return nil
	case TypeIPv6:
		if len(b) < 19 {
			return E.New("ipv6 address incomplete")
		}
		addr, ok := netip.AddrFromSlice(b[1:17])
		if !ok {
			return E.New("invalid ipv6 address")
		}
		s.destination.Addr = addr
		s.destination.Port = binary.BigEndian.Uint16(b[17:19])
		s.data = b[19:]
		return nil
	default:
		return E.New("invalid address type: %v", b[0])
	}
}

func (m *udpMessage) pack() []byte {
	var buffer *buf.Buffer
	defer buffer.Release()
	switch true {
	case m.destination.IsIPv4():
		buffer = buf.NewSize(7 + len(m.data))
		common.Must(
			binary.Write(buffer, binary.BigEndian, TypeIPv4),
			binary.Write(buffer, binary.BigEndian, m.destination.Addr.As4()),
			binary.Write(buffer, binary.BigEndian, m.destination.Port),
			common.Error(buffer.Write(m.data)),
		)
	case m.destination.IsFqdn():
		buffer = buf.NewSize(4 + len(m.destination.Fqdn) + len(m.data))
		common.Must(
			binary.Write(buffer, binary.BigEndian, TypeFqdn),
			binary.Write(buffer, binary.BigEndian, len(m.destination.Fqdn)),
			binary.Write(buffer, binary.BigEndian, m.destination.Fqdn),
			binary.Write(buffer, binary.BigEndian, m.destination.Port),
			common.Error(buffer.Write(m.data)),
		)
	case m.destination.IsIPv6():
		buffer = buf.NewSize(19 + len(m.data))
		common.Must(
			binary.Write(buffer, binary.BigEndian, TypeIPv6),
			binary.Write(buffer, binary.BigEndian, m.destination.Addr.As16()),
			binary.Write(buffer, binary.BigEndian, m.destination.Port),
			common.Error(buffer.Write(m.data)),
		)
	}
	return buffer.Bytes()
}

type bindPacketConn struct {
	*http3.Stream
	ctx       context.Context
	localAddr net.Addr
	data      chan *udpMessage
}

func newBindPacketConn(ctx context.Context, localAddr net.Addr, stream *http3.Stream) *bindPacketConn {
	conn := &bindPacketConn{
		Stream:    stream,
		ctx:       ctx,
		localAddr: localAddr,
		data:      make(chan *udpMessage, 64),
	}
	go func() {
		for {
			data, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				stream.Close()
				return
			}
			message := new(udpMessage)
			err = message.unpack(data)
			if err != nil {
				continue
			}
			conn.data <- message
		}
	}()
	return conn
}

func (c *bindPacketConn) LocalAddr() net.Addr { return c.localAddr }

func (c *bindPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case p := <-c.data:
		_, err := buffer.Write(p.data)
		return p.destination, err
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *bindPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.data:
		n := copy(p, pkt.data)
		if pkt.destination.IsFqdn() {
			return n, pkt.destination, nil
		} else {
			return n, pkt.destination.UDPAddr(), nil
		}
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	}
}

func (c *bindPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if buffer.Len() > MaxUDPSize {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: MaxUDPSize}
	}
	message := fromBuffer(buffer, destination)
	return c.SendDatagram(message.pack())
}

func (c *bindPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if len(p) > MaxUDPSize {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: MaxUDPSize}
	}
	message := fromBytes(p, addr)
	err := c.SendDatagram(message.pack())
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
