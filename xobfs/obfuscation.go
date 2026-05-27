package xobfs

import (
	"net"

	"github.com/agnostic-t/neutrino-core/obfuscation"
	"github.com/agnostic-t/neutrino-obfs/xobfs/algo"
)

var _ obfuscation.Obfuscator = (*Obfuscator)(nil)

type XOBFSConn struct {
	net.Conn
	Psk []byte
}

func (c *XOBFSConn) Write(b []byte) (int, error) {
	obfsData, err := algo.Obfuscate(b, c.Psk)
	if err != nil {
		return 0, err
	}

	_, err = c.Conn.Write(obfsData)
	return len(b), err
}

func (c *XOBFSConn) Read(b []byte) (int, error) {
	tempBuf := make([]byte, 8192)

	n, err := c.Conn.Read(tempBuf)
	if err != nil {
		return n, err
	}

	deobfData, err := algo.Deobfuscate(tempBuf[:n], c.Psk)
	if err != nil {
		return 0, err
	}

	copy(b, deobfData)
	return len(deobfData), nil
}

type Obfuscator struct {
	Psk []byte
}

func (o *Obfuscator) WrapConnTo(conn net.Conn) (net.Conn, error) {
	wrapped := &XOBFSConn{
		Conn: conn,
		Psk:  o.Psk,
	}

	return wrapped, nil
}

func (o *Obfuscator) WrapConnFrom(conn net.Conn) (net.Conn, error) {
	wrapped := &XOBFSConn{
		Conn: conn,
		Psk:  o.Psk,
	}

	return wrapped, nil
}
