package acls

import (
	"fmt"
	"strings"
)

// Permission bit constants
const (
	PermRead    uint16 = 0x4
	PermWrite   uint16 = 0x2
	PermExecute uint16 = 0x1
	PermAll     uint16 = 0x7
	PermNone    uint16 = 0x0
)

// PermUintToString takes an int representation of a
// permission and returns the string representation "rwx".
// not granted permissions appear as "-".
func PermUintToString(p uint16) string {
	s := []string{"-", "-", "-"}

	if (p & 0x4) == PermRead {
		s[0] = "r"
	}
	if (p & 0x2) == PermWrite {
		s[1] = "w"
	}
	if (p & 0x1) == PermExecute {
		s[2] = "x"
	}
	return strings.Join(s, "")
}

// PermStringToUint takes a string representation of a permission "rwx"
// and returns the uint16 representation.
// an error is returned if the string is not exactly 3 characters long.
func PermStringToUint(s string) (uint16, error) {
	var p uint16 = 0
	if len(s) != 3 {
		return p, fmt.Errorf("invalid permission string length")
	}
	if s[0] == 'r' {
		p |= PermRead
	}
	if s[1] == 'w' {
		p |= PermWrite
	}
	if s[2] == 'x' {
		p |= PermExecute
	}
	return p, nil
}
