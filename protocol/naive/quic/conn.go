package quic

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/protocol/naive"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/cache"
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
	udpMTU      int
	localAddr   net.Addr
	destination M.Socksaddr
	packetId    atomic.Uint32
	defragger   *udpDefragger
	data        chan *buf.Buffer
	close       chan struct{}
	closeOnce   sync.Once
	closeErr    error
}

func newConnectPacketConn(ctx context.Context, stream *http3.Stream, localAddr net.Addr, destination M.Socksaddr) *connectPacketConn {
	c := &connectPacketConn{
		Stream:      stream,
		ctx:         ctx,
		udpMTU:      1197,
		localAddr:   localAddr,
		destination: destination,
		defragger:   newUDPDefragger(),
		data:        make(chan *buf.Buffer, 64),
		close:       make(chan struct{}),
	}
	go func() {
		for {
			select {
			case <-c.close:
				return
			default:
			}
			data, err := stream.ReceiveDatagram(ctx)
			fmt.Println("receive datagram")
			if err != nil {
				c.Close()
				return
			}
			go func() {
				message := allocMessage()
				err = decodeUDPMessage(message, data)
				if err != nil {
					message.release()
					return
				}
				if message.fragmentTotal <= 1 {
					select {
					case <-c.close:
					case c.data <- buf.As(message.data.Bytes()):
					}
					message.releaseMessage()
				} else {
					newMessage := c.defragger.feed(message)
					if newMessage != nil {
						select {
						case <-c.close:
						case c.data <- buf.As(newMessage.data.Bytes()):
						}
						newMessage.releaseMessage()
					}
				}
			}()
		}
	}()
	return c
}

func (c *connectPacketConn) LocalAddr() net.Addr { return c.localAddr }

func (c *connectPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Stream.Close()
		close(c.data)
	})
	return c.closeErr
}

func (c *connectPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	fmt.Println("read packet")
	select {
	case p := <-c.data:
		_, err := buffer.ReadOnceFrom(p)
		return c.destination, err
	case <-c.close:
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *connectPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	fmt.Println("read from")
	select {
	case pkt := <-c.data:
		n := copy(p, pkt.Bytes())
		if c.destination.IsFqdn() {
			return n, c.destination, nil
		} else {
			return n, c.destination.UDPAddr(), nil
		}
	case <-c.close:
		return 0, nil, io.ErrClosedPipe
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	}
}

func (c *connectPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	fmt.Println("write []byte to ", addr.String())
	select {
	case <-c.close:
		return 0, net.ErrClosed
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
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		packetID:      packetId,
		fragmentTotal: 1,
		data:          buf.As(p),
	}
	var err error
	if len(p) > c.udpMTU-4 {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
		if err == nil {
			return len(p), nil
		}
	} else {
		err = c.writePacket(message)
		if err == nil {
			return len(p), nil
		}
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return 0, err
	}
	err = c.writePackets(fragUDPMessage(message, int(tooLargeErr.MaxDatagramPayloadSize-3)))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *connectPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	fmt.Println("write packet to ", destination.String())
	defer buffer.Release()
	select {
	case <-c.close:
		return net.ErrClosed
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
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		packetID:      packetId,
		fragmentTotal: 1,
		data:          buffer,
	}
	defer message.releaseMessage()
	var err error
	if buffer.Len() > c.udpMTU-4 {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return err
	}
	return c.writePackets(fragUDPMessage(message, int(tooLargeErr.MaxDatagramPayloadSize-3)))
}

func (c *connectPacketConn) writePackets(messages []*udpMessage) error {
	defer releaseMessages(messages)
	for _, message := range messages {
		err := c.writePacket(message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *connectPacketConn) writePacket(message *udpMessage) error {
	buffer := message.pack()
	defer buffer.Release()
	select {
	case <-c.close:
		return net.ErrClosed
	default:
		return c.SendDatagram(buffer.Bytes())
	}
}

type bindPacketConn struct {
	*http3.Stream
	ctx       context.Context
	localAddr net.Addr
	udpMTU    int
	packetId  atomic.Uint32
	defragger *udpDefragger
	data      chan *dstData
	close     chan struct{}
	closeOnce sync.Once
	closeErr  error
}

func newBindPacketConn(ctx context.Context, localAddr net.Addr, stream *http3.Stream) *bindPacketConn {
	c := &bindPacketConn{
		Stream:    stream,
		ctx:       ctx,
		localAddr: localAddr,
		defragger: newUDPDefragger(),
		data:      make(chan *dstData, 64),
	}
	go func() {
		for {
			select {
			case <-c.close:
				return
			default:
			}
			data, err := stream.ReceiveDatagram(ctx)
			if err != nil {
				c.Close()
				return
			}
			go func() {
				message := allocMessage()
				err = decodeUDPMessage(message, data)
				if err != nil {
					message.release()
					return
				}
				dstData := new(dstData)
				if message.fragmentTotal <= 1 {
					decodeDstData(dstData, message.data)
					select {
					case <-c.close:
					case c.data <- dstData:
					}
					message.releaseMessage()
				} else {
					newMessage := c.defragger.feed(message)
					if newMessage != nil {
						decodeDstData(dstData, newMessage.data)
						select {
						case <-c.close:
						case c.data <- dstData:
						}
						newMessage.releaseMessage()
					}
				}
			}()
		}
	}()
	return c
}

func (c *bindPacketConn) LocalAddr() net.Addr { return c.localAddr }

func (c *bindPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.Stream.Close()
		close(c.data)
	})
	return c.closeErr
}

func (c *bindPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	select {
	case p := <-c.data:
		_, err := buffer.ReadOnceFrom(p.data)
		return p.destination, err
	case <-c.close:
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	}
}

func (c *bindPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt := <-c.data:
		n := copy(p, pkt.data.Bytes())
		if pkt.destination.IsFqdn() {
			return n, pkt.destination, nil
		} else {
			return n, pkt.destination.UDPAddr(), nil
		}
	case <-c.close:
		return 0, nil, io.ErrClosedPipe
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	}
}

func (c *bindPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.close:
		return 0, net.ErrClosed
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if len(p) > MaxUDPSize {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: MaxUDPSize}
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		packetID:      packetId,
		fragmentTotal: 1,
		data: (&dstData{
			destination: M.SocksaddrFromNet(addr),
			data:        buf.As(p),
		}).pack(),
	}
	defer message.releaseMessage()
	var err error
	if len(p) > c.udpMTU-4 {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
		if err == nil {
			return len(p), nil
		}
	} else {
		err = c.writePacket(message)
		if err == nil {
			return len(p), nil
		}
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return 0, err
	}
	err = c.writePackets(fragUDPMessage(message, int(tooLargeErr.MaxDatagramPayloadSize-3)))
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *bindPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.close:
		return net.ErrClosed
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if buffer.Len() > MaxUDPSize {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: MaxUDPSize}
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := allocMessage()
	*message = udpMessage{
		packetID:      packetId,
		fragmentTotal: 1,
		data: (&dstData{
			destination: destination,
			data:        buffer,
		}).pack(),
	}
	defer message.releaseMessage()
	var err error
	if buffer.Len() > c.udpMTU-4 {
		err = c.writePackets(fragUDPMessage(message, c.udpMTU))
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return err
	}
	return c.writePackets(fragUDPMessage(message, int(tooLargeErr.MaxDatagramPayloadSize-3)))
}

func (c *bindPacketConn) writePackets(messages []*udpMessage) error {
	defer releaseMessages(messages)
	for _, message := range messages {
		err := c.writePacket(message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *bindPacketConn) writePacket(message *udpMessage) error {
	buffer := message.pack()
	defer buffer.Release()
	select {
	case <-c.close:
		return net.ErrClosed
	default:
		return c.SendDatagram(buffer.Bytes())
	}
}

type udpDefragger struct {
	packetMap *cache.LruCache[uint16, *packetItem]
}

func newUDPDefragger() *udpDefragger {
	return &udpDefragger{
		packetMap: cache.New(
			cache.WithAge[uint16, *packetItem](10),
			cache.WithUpdateAgeOnGet[uint16, *packetItem](),
			cache.WithEvict[uint16, *packetItem](func(key uint16, value *packetItem) {
				releaseMessages(value.messages)
			}),
		),
	}
}

type packetItem struct {
	access   sync.Mutex
	messages []*udpMessage
	count    uint8
}

func (d *udpDefragger) feed(m *udpMessage) *udpMessage {
	if m.fragmentTotal <= 1 {
		return m
	}
	if m.fragmentID >= m.fragmentTotal {
		return nil
	}
	item, _ := d.packetMap.LoadOrStore(m.packetID, newPacketItem)
	item.access.Lock()
	defer item.access.Unlock()
	if int(m.fragmentTotal) != len(item.messages) {
		releaseMessages(item.messages)
		item.messages = make([]*udpMessage, m.fragmentTotal)
		item.count = 1
		item.messages[m.fragmentID] = m
		return nil
	}
	if item.messages[m.fragmentID] != nil {
		return nil
	}
	item.messages[m.fragmentID] = m
	item.count++
	if int(item.count) != len(item.messages) {
		return nil
	}
	newMessage := allocMessage()
	newMessage.packetID = m.packetID
	var finalLength int
	for _, message := range item.messages {
		finalLength += message.data.Len()
	}
	if finalLength > 0 {
		newMessage.data = buf.NewSize(finalLength)
		for _, message := range item.messages {
			newMessage.data.Write(message.data.Bytes())
			message.releaseMessage()
		}
		item.messages = nil
		return newMessage
	} else {
		newMessage.releaseMessage()
		for _, message := range item.messages {
			message.releaseMessage()
		}
	}
	item.messages = nil
	return nil
}

func newPacketItem() *packetItem {
	return new(packetItem)
}

func decodeUDPMessage(message *udpMessage, data []byte) error {
	reader := bytes.NewReader(data)
	err := binary.Read(reader, binary.BigEndian, &message.packetID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentID)
	if err != nil {
		return err
	}
	err = binary.Read(reader, binary.BigEndian, &message.fragmentTotal)
	if err != nil {
		return err
	}
	message.data = buf.As(data[len(data)-reader.Len():])
	return nil
}

type dstData struct {
	destination M.Socksaddr
	data        *buf.Buffer
}

func (m *dstData) pack() *buf.Buffer {
	var buffer *buf.Buffer
	switch true {
	case m.destination.IsIPv4():
		buffer = buf.NewSize(7 + m.data.Len())
		common.Must(
			binary.Write(buffer, binary.BigEndian, TypeIPv4),
			binary.Write(buffer, binary.BigEndian, m.destination.Addr.As4()),
		)
	case m.destination.IsFqdn():
		buffer = buf.NewSize(4 + len(m.destination.Fqdn) + m.data.Len())
		common.Must(
			binary.Write(buffer, binary.BigEndian, TypeFqdn),
			binary.Write(buffer, binary.BigEndian, len(m.destination.Fqdn)),
			binary.Write(buffer, binary.BigEndian, m.destination.Fqdn),
		)
	case m.destination.IsIPv6():
		buffer = buf.NewSize(19 + m.data.Len())
		common.Must(
			binary.Write(buffer, binary.BigEndian, TypeIPv6),
			binary.Write(buffer, binary.BigEndian, m.destination.Addr.As16()),
		)
	}
	common.Must(
		binary.Write(buffer, binary.BigEndian, m.destination.Port),
		common.Error(buffer.ReadOnceFrom(m.data)),
	)
	return buffer
}

func decodeDstData(dstData *dstData, data *buf.Buffer) error {
	var addrType uint8
	err := binary.Read(data, binary.BigEndian, &addrType)
	if err != nil {
		return err
	}
	switch addrType {
	case TypeIPv4:
		var addr [4]byte
		err := binary.Read(data, binary.BigEndian, &addr)
		if err != nil {
			return err
		}
		dstData.destination.Addr = netip.AddrFrom4(addr)
	case TypeIPv6:
		var addr [16]byte
		err := binary.Read(data, binary.BigEndian, &addr)
		if err != nil {
			return err
		}
		dstData.destination.Addr = netip.AddrFrom16(addr)
	case TypeFqdn:
		var addrLen uint8
		err := binary.Read(data, binary.BigEndian, &addrLen)
		if err != nil {
			return err
		}
		addr := make([]byte, addrLen)
		err = binary.Read(data, binary.BigEndian, &addr)
		if err != nil {
			return err
		}
		dstData.destination.Fqdn = string(addr)
	default:
		return E.New("Invalid addr type")
	}
	err = binary.Read(data, binary.BigEndian, &dstData.destination.Port)
	if err != nil {
		return err
	}
	dstData.data = buf.As(data.Bytes())
	return nil
}
