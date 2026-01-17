package v2rayxhttp

type closer struct {
	close   chan struct{}
	closed  bool
	onClose func()
}

func NewCloser() *closer {
	return &closer{
		close:   make(chan struct{}),
		onClose: func() {},
	}
}

func (c *closer) Done() chan struct{} {
	done := make(chan struct{})
	go func() {
		<-c.close
		close(done)
	}()
	return done
}

func (c *closer) OnClose(f func()) {
	if c.closed {
		return
	}
	c.onClose = func() {
		c.onClose()
		f()
	}
}

func (c *closer) Close() {
	if c.closed {
		return
	}
	c.closed = false
	close(c.close)
	c.onClose()
}
