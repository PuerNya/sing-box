package v2rayxhttp

import (
	"context"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/baderror"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var safeURLChars = [84]rune{
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	'-', '_', '.', '~', '!', '*', '\'', '(', ')', ';', ':', '@', '=', '+', '$', ',', '/', '?', '[', ']',
}

func generateRandomPaddingString() string {
	paddingLen := rand.Intn(901) + 100
	padding := make([]rune, paddingLen)
	for i := range paddingLen {
		padding[i] = safeURLChars[rand.Intn(84)]
	}
	return string(padding)
}

type SplitConn struct {
	rCreate chan struct{}
	reader  io.Reader
	rErr    error
	wCreate chan struct{}
	writer  io.Writer
	wErr    error
	closed  bool
	onClose func()
}

func NewSplitConn(reader io.Reader, writer io.Writer) *SplitConn {
	return &SplitConn{
		reader:  reader,
		writer:  writer,
		onClose: func() {},
	}
}

func NewLateReadSplitConn(writer io.Writer) *SplitConn {
	return &SplitConn{
		rCreate: make(chan struct{}),
		writer:  writer,
		onClose: func() {},
	}
}

func NewLateWriteSplitConn(reader io.Reader) *SplitConn {
	return &SplitConn{
		reader:  reader,
		wCreate: make(chan struct{}),
		onClose: func() {},
	}
}

func NewLateSplitConn() *SplitConn {
	return &SplitConn{
		rCreate: make(chan struct{}),
		wCreate: make(chan struct{}),
		onClose: func() {},
	}
}

func (c *SplitConn) SetupReader(reader io.Reader, err error) {
	c.reader = reader
	c.rErr = err
	close(c.rCreate)
}

func (c *SplitConn) SetupWriter(writer io.Writer, err error) {
	c.writer = writer
	c.wErr = err
	close(c.wCreate)
}

func (c *SplitConn) Read(b []byte) (n int, err error) {
	if c.reader == nil {
		<-c.rCreate
		if c.rErr != nil {
			return 0, c.rErr
		}
	}
	n, err = c.reader.Read(b)
	return n, baderror.WrapH2(err)
}

func (c *SplitConn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		<-c.wCreate
		if c.wErr != nil {
			return 0, c.wErr
		}
	}
	n, err = c.writer.Write(b)
	if err == nil {
		if fluser, isFlusher := c.writer.(http.Flusher); isFlusher {
			fluser.Flush()
		}
	}
	return n, baderror.WrapH2(err)
}

func (c *SplitConn) OnClose(f func()) {
	if c.closed {
		return
	}
	c.onClose = func() {
		c.onClose()
		f()
	}
}

func (c *SplitConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	go c.onClose()
	return common.Close(c.reader, c.writer)
}

func (c *SplitConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *SplitConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *SplitConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *SplitConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *SplitConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *SplitConn) NeedAdditionalReadDeadline() bool {
	return true
}

type pool struct {
	slice     []*buffer
	channel   chan *buffer
	access    sync.Mutex
	newBuffer func() *buffer
	closed    bool
	close     chan struct{}
}

func newPool(newBuffer func() *buffer, capacity uint64) *pool {
	return &pool{
		slice:     make([]*buffer, 0, capacity),
		channel:   make(chan *buffer, capacity),
		newBuffer: newBuffer,
		close:     make(chan struct{}),
	}
}

func (p *pool) tryGet() (*buffer, error) {
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.channel) > 0 {
		return <-p.channel, nil
	}
	if len(p.slice) == cap(p.slice) {
		return nil, E.New("match max cache size")
	}
	buffer := p.newBuffer()
	p.slice = append(p.slice, buffer)
	return buffer, nil
}

func (p *pool) get() *buffer {
	p.access.Lock()
	defer p.access.Unlock()
	if len(p.channel) > 0 || len(p.slice) == cap(p.slice) {
		return <-p.channel
	}
	buffer := p.newBuffer()
	p.slice = append(p.slice, buffer)
	return buffer
}

func (p *pool) put(buffer *buffer) {
	p.access.Lock()
	defer p.access.Unlock()
	select {
	case <-p.close:
	default:
	}
	buffer.Release()
	p.channel <- buffer
}

func (p *pool) Close() {
	if p.closed {
		return
	}
	p.closed = true
	close(p.channel)
	p.access.Lock()
	slice := p.slice
	p.slice = nil
	p.access.Unlock()
	for _, buffer := range slice {
		buffer.Destroy()
	}
	slice = nil
}

type buffer struct {
	data []byte
	len  int
}

func newBuffer(len uint64) *buffer {
	if len == 0 {
		return &buffer{}
	} else {
		return &buffer{
			data: make([]byte, 0, len),
		}
	}
}

func (b *buffer) Read(p []byte) (int, error) {
	return copy(p, b.data[:b.len]), nil
}

func (b *buffer) readFrom(reader io.Reader) (int, error) {
	n, err := reader.Read(b.data)
	b.len = n
	return n, err
}

func (b *buffer) writeTo(writer io.Writer) (int, error) {
	return writer.Write(b.data[:b.len])
}

func (b *buffer) Release() {
	b.data = b.data[:0]
	b.len = 0
}

func (b *buffer) Destroy() {
	b.data = nil
	b.len = 0
}

type chainItem struct {
	id     uint64
	reader io.Reader
	next   *chainItem
	done   chan struct{}
	err    error
	closed bool
}

func newItem(id uint64, reader io.Reader) *chainItem {
	return &chainItem{
		id:     id,
		reader: reader,
		done:   make(chan struct{}),
	}
}

func (i *chainItem) CloseWithError(err error) {
	if i.closed {
		return
	}
	i.closed = true
	i.err = err
	close(i.done)
}

type LimitPacketPipe struct {
	pipeReader  *io.PipeReader
	pipeWriter  *io.PipeWriter
	ticker      *time.Ticker
	closed      bool
	close       chan struct{}
	closeAccess sync.Mutex
	err         error
	packetId    uint64
	bufAccess   sync.Mutex
	chain       *chainItem
	receive     chan struct{}
	newBuffer   func() *buffer
}

func NewLimitPacketPipe(newBuffer func() *buffer) *LimitPacketPipe {
	pipeReader, pipeWriter := io.Pipe()
	pipe := &LimitPacketPipe{
		pipeReader: pipeReader,
		pipeWriter: pipeWriter,
		ticker:     time.NewTicker(time.Second * 30),
		close:      make(chan struct{}),
		receive:    make(chan struct{}),
		newBuffer:  newBuffer,
	}
	go func() {
		select {
		case <-pipe.close:
		case <-pipe.ticker.C:
			pipe.Close()
		}
	}()
	go pipe.loopPipe()
	return pipe
}

func (p *LimitPacketPipe) loopPipe() {
	buffer := p.newBuffer()
	defer buffer.Destroy()
	for {
		select {
		case <-p.close:
			return
		case <-p.receive:
		}
		var item *chainItem
		p.bufAccess.Lock()
		select {
		case <-p.close:
			return
		default:
		}
		if p.chain.id != p.packetId {
			p.bufAccess.Unlock()
			continue
		}
		item = p.chain
		p.chain = p.chain.next
		p.packetId++
		p.bufAccess.Unlock()
		select {
		case <-p.close:
			item.CloseWithError(E.New("connection closed"))
			return
		default:
		}
		_, err := buffer.readFrom(item.reader)
		select {
		case <-p.close:
			buffer.Release()
			item.CloseWithError(E.New("connection closed"))
			return
		default:
		}
		_, err = buffer.writeTo(p.pipeWriter)
		buffer.Release()
		select {
		case <-p.close:
			item.CloseWithError(E.New("connection closed"))
			return
		default:
		}
		if err != nil {
			p.Close()
			item.CloseWithError(E.New("connection closed"))
			return
		}
		item.CloseWithError(nil)
	}
}

func (p *LimitPacketPipe) Push(body io.ReadCloser, id uint64) error {
	select {
	case <-p.close:
		return net.ErrClosed
	default:
	}
	p.bufAccess.Lock()
	defer p.bufAccess.Unlock()
	select {
	case <-p.close:
		return net.ErrClosed
	default:
	}
	if p.packetId > id {
		return E.New("invalid pakcet id")
	}
	var item *chainItem
	if p.chain == nil {
		item = newItem(id, body)
		p.chain = item
	} else if p.chain.id == id {
		return E.New("invalid pakcet id")
	} else if p.chain.id > id {
		item = newItem(id, body)
		item.next = p.chain
		p.chain = item
	} else {
		now := p.chain
		step := 1
		for {
			select {
			case <-p.close:
				return net.ErrClosed
			default:
			}
			if now.next == nil {
				item = newItem(id, body)
				now.next = item
			} else if now.next.id < id {
				now = now.next
				step++
				continue
			} else if now.next.id == id {
				return E.New("invalid pakcet id")
			} else {
				item = newItem(id, body)
				item.next = now.next
				now.next = item
			}
			break
		}
	}
	p.receive <- struct{}{}
	<-item.done
	return item.err
}

func (p *LimitPacketPipe) Read(b []byte) (n int, err error) {
	n, err = p.pipeReader.Read(b)
	return n, baderror.WrapH2(err)
}

func (p *LimitPacketPipe) Close() error {
	p.closeAccess.Lock()
	if p.closed {
		p.closeAccess.Unlock()
		return nil
	}
	p.closed = true
	p.closeAccess.Unlock()
	close(p.close)
	close(p.receive)
	p.bufAccess.Lock()
	item := p.chain
	p.chain = nil
	p.bufAccess.Unlock()
	for {
		if item == nil {
			break
		}
		item.CloseWithError(E.New("connection closed"))
		item = item.next
	}
	runtime.GC()
	return common.Close(p.pipeReader, p.pipeWriter)
}

type ServerPaketConn struct {
	pipeReader *io.PipeReader
	pipeWriter *io.PipeWriter
	writer     io.Writer
	create     chan struct{}
	closed     chan struct{}
	err        error
	packetId   uint64
	bufAccess  sync.Mutex
	buffers    map[uint64]*buf.Buffer
}

func NewServerPaketConn() *ServerPaketConn {
	pipeReader, pipeWriter := io.Pipe()
	return &ServerPaketConn{
		pipeReader: pipeReader,
		pipeWriter: pipeWriter,
		create:     make(chan struct{}),
		closed:     make(chan struct{}),
	}
}

func (c *ServerPaketConn) SetupWriter(writer io.Writer, err error) {
	c.writer = writer
	c.err = err
	close(c.create)
}

func (c *ServerPaketConn) Push(buffer *buf.Buffer, id uint64) error {
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	c.bufAccess.Lock()
	if c.packetId > id {
		c.bufAccess.Unlock()
		return E.New("invalid pakcet id")
	}
	if c.packetId < id {
		c.buffers[id] = buffer
		c.bufAccess.Unlock()
		return nil
	}
	_, err := buffer.WriteTo(c.pipeWriter)
	buffer.Release()
	if err != nil {
		c.bufAccess.Unlock()
		return err
	}
	c.packetId++
	c.bufAccess.Unlock()
	go func() {
		for {
			select {
			case <-c.closed:
				return
			default:
			}
			c.bufAccess.Lock()
			buffer, hasBuffer := c.buffers[c.packetId]
			if !hasBuffer {
				c.bufAccess.Unlock()
				return
			} else {
				delete(c.buffers, c.packetId)
				_, err := buffer.WriteTo(c.pipeWriter)
				buffer.Release()
				c.packetId++
				c.bufAccess.Unlock()
				if err != nil {
					c.Close()
					break
				}
			}
		}
	}()
	return nil
}

func (c *ServerPaketConn) Read(b []byte) (n int, err error) {
	n, err = c.pipeReader.Read(b)
	return n, baderror.WrapH2(err)
}

func (c *ServerPaketConn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		<-c.create
		if c.err != nil {
			return 0, c.err
		}
	}
	n, err = c.writer.Write(b)
	if err == nil {
		if fluser, isFlusher := c.writer.(http.Flusher); isFlusher {
			fluser.Flush()
		}
	}
	return n, baderror.WrapH2(err)
}

func (c *ServerPaketConn) Close() error {
	close(c.closed)
	return common.Close(c.pipeReader, c.pipeWriter, c.writer)
}

func (c *ServerPaketConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *ServerPaketConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *ServerPaketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *ServerPaketConn) SetReadDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *ServerPaketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *ServerPaketConn) NeedAdditionalReadDeadline() bool {
	return true
}

type ConnWrapper struct {
	N.ExtendedConn
	RawConn   *SplitConn
	closeOnce sync.Once
	closed    chan struct{}
}

func NewConnWrapper(conn *SplitConn) *ConnWrapper {
	return &ConnWrapper{
		ExtendedConn: bufio.NewExtendedConn(conn),
		RawConn:      conn,
		closed:       make(chan struct{}),
	}
}

func (w *ConnWrapper) Write(p []byte) (n int, err error) {
	select {
	case <-w.closed:
		return 0, net.ErrClosed
	default:
		return w.ExtendedConn.Write(p)
	}
}

func (w *ConnWrapper) WriteBuffer(buffer *buf.Buffer) error {
	select {
	case <-w.closed:
		return net.ErrClosed
	default:
		return w.ExtendedConn.WriteBuffer(buffer)
	}
}

func (w *ConnWrapper) Wait() {
	<-w.closed
}

func (w *ConnWrapper) CloseWrapper() {
	w.closeOnce.Do(func() {
		close(w.closed)
	})
}

func (w *ConnWrapper) Close() error {
	w.CloseWrapper()
	return w.ExtendedConn.Close()
}

func (w *ConnWrapper) Upstream() any {
	return w.ExtendedConn
}

type ExpireConn struct {
	*ConnWrapper
	expire time.Time
}

func DupContext(ctx context.Context) context.Context {
	id, loaded := log.IDFromContext(ctx)
	if !loaded {
		return context.Background()
	}
	return log.ContextWithID(context.Background(), id)
}
