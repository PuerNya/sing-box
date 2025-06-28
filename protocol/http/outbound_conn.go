package http

import (
	"encoding/binary"
	"io"
	"math/rand"
	"net"

	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/rw"
)

const kFirstfunnies = 8

type funnyConn struct {
	net.Conn
	readFunny      int
	writeFunny     int
	readRemaining  int
	funnyRemaining int
}

func (c *funnyConn) Read(p []byte) (n int, err error) {
	if c.readRemaining > 0 {
		if len(p) > c.readRemaining {
			p = p[:c.readRemaining]
		}
		n, err = c.Conn.Read(p)
		if err != nil {
			return
		}
		c.readRemaining -= n
		return
	}
	if c.funnyRemaining > 0 {
		err = rw.SkipN(c.Conn, c.funnyRemaining)
		if err != nil {
			return
		}
		c.funnyRemaining = 0
	}
	if c.readFunny < kFirstfunnies {
		var paddingHdr []byte
		if len(p) >= 3 {
			paddingHdr = p[:3]
		} else {
			paddingHdr = make([]byte, 3)
		}
		_, err = io.ReadFull(c.Conn, paddingHdr)
		if err != nil {
			return
		}
		originalDataSize := int(binary.BigEndian.Uint16(paddingHdr[:2]))
		paddingSize := int(paddingHdr[2])
		if len(p) > originalDataSize {
			p = p[:originalDataSize]
		}
		n, err = c.Conn.Read(p)
		if err != nil {
			return
		}
		c.readFunny++
		c.readRemaining = originalDataSize - n
		c.funnyRemaining = paddingSize
		return
	}
	return c.Conn.Read(p)
}

func (c *funnyConn) Write(p []byte) (n int, err error) {
	for pLen := len(p); pLen > 0; {
		var data []byte
		if pLen > 65535 {
			data = p[:65535]
			p = p[65535:]
			pLen -= 65535
		} else {
			data = p
			pLen = 0
		}
		var writeN int
		writeN, err = c.write(data)
		n += writeN
		if err != nil {
			break
		}
	}
	return n, err
}

func (c *funnyConn) write(p []byte) (n int, err error) {
	if c.writeFunny < kFirstfunnies {
		paddingSize := rand.Intn(256)

		buffer := buf.NewSize(3 + len(p) + paddingSize)
		defer buffer.Release()
		header := buffer.Extend(3)
		binary.BigEndian.PutUint16(header, uint16(len(p)))
		header[2] = byte(paddingSize)

		common.Must1(buffer.Write(p))
		_, err = c.Conn.Write(buffer.Bytes())
		if err == nil {
			n = len(p)
		}
		c.writeFunny++
		return
	}
	return c.Conn.Write(p)
}

func (c *funnyConn) FrontHeadroom() int {
	if c.writeFunny < kFirstfunnies {
		return 3
	}
	return 0
}

func (c *funnyConn) RearHeadroom() int {
	if c.writeFunny < kFirstfunnies {
		return 255
	}
	return 0
}

func (c *funnyConn) WriterMTU() int {
	if c.writeFunny < kFirstfunnies {
		return 65535
	}
	return 0
}

func (c *funnyConn) WriteBuffer(buffer *buf.Buffer) error {
	defer buffer.Release()
	if c.writeFunny < kFirstfunnies {
		bufferLen := buffer.Len()
		if bufferLen > 65535 {
			return common.Error(c.Write(buffer.Bytes()))
		}
		paddingSize := rand.Intn(256)
		header := buffer.ExtendHeader(3)
		binary.BigEndian.PutUint16(header, uint16(bufferLen))
		header[2] = byte(paddingSize)
		buffer.Extend(paddingSize)
		c.writeFunny++
	}
	return common.Error(c.Conn.Write(buffer.Bytes()))
}

// FIXME
/*func (c *funnyConn) WriteTo(w io.Writer) (n int64, err error) {
	if c.readPadding < kFirstPaddings {
		return bufio.WriteToN(c, w, kFirstPaddings-c.readPadding)
	} else {
		return bufio.Copy(w, c.Conn)
	}
}

func (c *funnyConn) ReadFrom(r io.Reader) (n int64, err error) {
	if c.writePadding < kFirstPaddings {
		return bufio.ReadFromN(c, r, kFirstPaddings-c.writePadding)
	} else {
		return bufio.Copy(c.Conn, r)
	}
}
*/

func (c *funnyConn) Upstream() any {
	return c.Conn
}

func (c *funnyConn) ReaderReplaceable() bool {
	return c.readFunny == kFirstfunnies
}

func (c *funnyConn) WriterReplaceable() bool {
	return c.writeFunny == kFirstfunnies
}
