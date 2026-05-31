package xobfs

import (
	"crypto/rand"
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

func encodeByteNoZero(b, baseMask uint8) uint8 {
	mask := baseMask
	if mask == b {
		mask ^= 0x80
	}
	return b ^ mask
}

func decodeByteNoZero(enc, baseMask uint8) uint8 {
	candidate := enc ^ baseMask
	if candidate == baseMask {
		return enc ^ (baseMask ^ 0x80)
	}
	return candidate
}

func ObfsEncodeHeader(len uint16, psk []byte) ([4]byte, error) {
	var hdr [4]byte
	if _, err := rand.Read(hdr[2:4]); err != nil {
		return hdr, err
	}
	for i := 2; i < 4; i++ {
		if hdr[i] == 0 {
			hdr[i] = 0x01
		}
	}

	b0 := uint8(len >> 8)
	b1 := uint8(len & 0xFF)

	baseMask1 := psk[0] ^ 0x5A
	baseMask2 := psk[1] ^ 0xA5

	hdr[0] = encodeByteNoZero(b0, baseMask1)
	hdr[1] = encodeByteNoZero(b1, baseMask2)

	return hdr, nil
}

func ObfsDecodeHeader(hdr [4]byte, psk []byte) (uint16, [2]byte, error) {
	baseMask1 := psk[0] ^ 0x5A
	baseMask2 := psk[1] ^ 0xA5

	b0 := decodeByteNoZero(hdr[0], baseMask1)
	b1 := decodeByteNoZero(hdr[1], baseMask2)

	return uint16(b0)<<8 | uint16(b1), [2]byte{hdr[2], hdr[3]}, nil
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

		frame := make([]byte, 4+len(obfsData))
		header, err := ObfsEncodeHeader(uint16(len(obfsData)), c.Psk)
		if err != nil {
			return totalWritten, err
		}

		copy(frame[:4], header[:])
		copy(frame[4:], obfsData)

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

	var header [4]byte
	if _, err := io.ReadFull(c.Conn, header[:]); err != nil {
		return 0, err
	}
	frameLen, _, err := ObfsDecodeHeader(header, c.Psk)

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
