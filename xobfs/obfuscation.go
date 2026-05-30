package xobfs

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/agnostic-t/neutrino-core/obfuscation"
	"github.com/agnostic-t/neutrino-obfs/xobfs/algo"
)

var _ obfuscation.Obfuscator = (*Obfuscator)(nil)

type XOBFSConn struct {
	net.Conn
	Psk []byte

	readBuf []byte
}

func (c *XOBFSConn) Write(b []byte) (int, error) {
	maxChunk := 32768
	totalWritten := 0

	for len(b) > 0 {
		chunkSize := min(len(b), maxChunk)

		chunk := b[:chunkSize]
		b = b[chunkSize:]

		obfsData, err := algo.Obfuscate(chunk, c.Psk)
		if err != nil {
			return totalWritten, err
		}

		frame := make([]byte, 2+len(obfsData))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(obfsData)))
		copy(frame[2:], obfsData)

		if _, err := c.Conn.Write(frame); err != nil {
			return totalWritten, err
		}

		totalWritten += chunkSize
	}

	return totalWritten, nil
}

func (c *XOBFSConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.Conn, lenBuf); err != nil {
		return 0, err
	}
	frameLen := binary.BigEndian.Uint16(lenBuf)

	frameBuf := make([]byte, frameLen)
	if _, err := io.ReadFull(c.Conn, frameBuf); err != nil {
		return 0, err
	}

	deobfData, err := algo.Deobfuscate(frameBuf, c.Psk)
	if err != nil {
		return 0, err
	}

	n := copy(b, deobfData)
	if n < len(deobfData) {
		c.readBuf = deobfData[n:]
	}

	return n, nil
}

type Obfuscator struct {
	Psk []byte
}

func (o *Obfuscator) WrapConnTo(conn net.Conn) (net.Conn, error) {
	return &XOBFSConn{Conn: conn, Psk: o.Psk}, nil
}

func (o *Obfuscator) WrapConnFrom(conn net.Conn) (net.Conn, error) {
	return &XOBFSConn{Conn: conn, Psk: o.Psk}, nil
}
