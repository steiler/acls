package acls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// ACLEntry the ACLEntry represents the single lines
// of permission.
//   - Tag references the type (group, user, etc.)
//   - Perm is the permission in its numerical format
//   - Id is the id of the group or user or whatever tag points to
type ACLEntry struct {
	Tag  Tag
	Perm uint16
	Id   uint32
}

// NewEntry returns a new ACLEntry
func NewEntry(tag Tag, id uint32, perm uint16) *ACLEntry {
	return &ACLEntry{
		Tag:  tag,
		Perm: perm,
		Id:   id,
	}
}

// parse parses a single ACLEntry from the given byte slice.
// it will read 8 bytes and return the remaining bytes.
// the malformed error is returned if the len of
// the byte slice is less then 8
func (a *ACLEntry) parse(b []byte) ([]byte, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("malformed data")
	}
	a.Tag = Tag(binary.LittleEndian.Uint16(b[:2]))
	a.Perm = binary.LittleEndian.Uint16(b[2:4])
	a.Id = binary.LittleEndian.Uint32(b[4:8])
	return b[8:], nil
}

// String returns a string representation of the ACLEntry
func (a *ACLEntry) String() string {
	return fmt.Sprintf("Tag: %10s (%2d), ID: %10d, Perm: %s (%d)", Tag2String(a.Tag), a.Tag, a.Id, PermUintToString(a.Perm), a.Perm)
}

// equalTagID returns true if the given ACLEntry carries
// the same ID and Tag values as actual entry. False otherwise.
// The Perm attribute is not considered in this check.
func (a *ACLEntry) equalTagID(e *ACLEntry) bool {
	if e.Tag != a.Tag {
		return false
	}
	if e.Id != a.Id {
		return false
	}
	return true
}

// Equal returns true if the given ACLEntry equals the actual ACLEntry
func (a *ACLEntry) Equal(e *ACLEntry) bool {
	return a.Id == e.Id && a.Tag == e.Tag && a.Perm == e.Perm
}

// ToByteSlice returns the ACLEntry as a byte slice in
// little endian order, which is the representation required
// for the Setxattr(...) call
func (a *ACLEntry) ToByteSlice(result *bytes.Buffer) {
	binary.Write(result, binary.LittleEndian, a.Tag)
	binary.Write(result, binary.LittleEndian, a.Perm)
	binary.Write(result, binary.LittleEndian, a.Id)
}

// PermUintToString takes an int representation of a
// permission and returns the string representation "rwx".
// not granted permissions appear as "-".
func PermUintToString(p uint16) string {
	s := []string{"-", "-", "-"}

	if (p & 0x4) == 0x4 {
		s[0] = "r"
	}
	if (p & 0x2) == 0x2 {
		s[1] = "w"
	}
	if (p & 0x1) == 0x1 {
		s[2] = "x"
	}
	return strings.Join(s, "")
}
