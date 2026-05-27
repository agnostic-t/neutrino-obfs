package xobfs

import (
	"net"

	"github.com/agnostic-t/neutrino-core/obfuscation"
)

var _ obfuscation.Obfuscator = (*Obfuscator)(nil)

type Obfuscator struct {
}

func (o *Obfuscator) WrapConnTo(conn net.Conn) (net.Conn, error) {

}

func (o *Obfuscator) WrapConnFrom(conn net.Conn) (net.Conn, error) {

}
