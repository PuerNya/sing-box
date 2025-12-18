package http

import "net"

type lazyConn struct {
	net.Conn
	checked chan struct{}
	err     error
}

func newLazyConn(conn net.Conn) *lazyConn {
	return &lazyConn{
		Conn:    conn,
		checked: make(chan struct{}),
		err:     nil,
	}
}

func (c *lazyConn) Read(b []byte) (int, error) {
	<-c.checked
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Read(b)
}

func (c *lazyConn) Setup(err error) {
	c.err = err
	close(c.checked)
}
