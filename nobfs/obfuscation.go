package nobfs

import (
	"net"

	"github.com/agnostic-t/neutrino-core/obfuscation"
)

var _ obfuscation.Obfuscator = (*NullObfuscator)(nil)

type NullObfuscator struct {
}

func (o *NullObfuscator) WrapConnTo(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

func (o *NullObfuscator) WrapConnFrom(conn net.Conn) (net.Conn, error) {
	return conn, nil
}
