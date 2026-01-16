package acls

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// ACLEntry the ACLEntry represents the single lines
// of permission.
//   - tag references the type (group, user, etc.)
//   - perm is the permission in its numerical format
//   - id is the id of the group or user or whatever tag points to
type ACLEntry struct {
	tag  Tag
	perm uint16
	id   uint32
}

// NewEntry returns a new ACLEntry
func NewEntry(tag Tag, id uint32, perm uint16) *ACLEntry {
	return &ACLEntry{
		tag:  tag,
		perm: perm,
		id:   id,
	}
}

// Tag returns the tag of the ACLEntry
func (e *ACLEntry) Tag() Tag { return e.tag }

// Perm returns the permission of the ACLEntry
func (e *ACLEntry) Perm() uint16 { return e.perm }

// ID returns the ID of the ACLEntry
func (e *ACLEntry) ID() uint32 { return e.id }

// HasPerm checks if the entry has the specified permission bit(s)
func (e *ACLEntry) HasPerm(perm uint16) bool {
	return (e.perm & perm) == perm
}

// WithPerm returns a new ACLEntry with the specified permission bit(s) added
func (e *ACLEntry) WithPerm(perm uint16) *ACLEntry {
	return NewEntry(e.tag, e.id, e.perm|perm)
}

// WithoutPerm returns a new ACLEntry with the specified permission bit(s) removed
func (e *ACLEntry) WithoutPerm(perm uint16) *ACLEntry {
	return NewEntry(e.tag, e.id, e.perm&^perm)
}

// WithExactPerm returns a new ACLEntry with the exact permission specified
func (e *ACLEntry) WithExactPerm(perm uint16) *ACLEntry {
	return NewEntry(e.tag, e.id, perm)
}

// parse parses a single ACLEntry from the given byte slice.
// it will read 8 bytes and return the remaining bytes.
// the malformed error is returned if the len of
// the byte slice is less then 8
func (a *ACLEntry) parse(b []byte) ([]byte, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("malformed data")
	}
	a.tag = Tag(binary.LittleEndian.Uint16(b[:2]))
	a.perm = binary.LittleEndian.Uint16(b[2:4])
	a.id = binary.LittleEndian.Uint32(b[4:8])
	return b[8:], nil
}

// String returns a string representation of the ACLEntry
func (a *ACLEntry) String() string {
	return fmt.Sprintf("Tag: %10s (%2d), ID: %10d, Perm: %s (%d)", Tag2String(a.tag), a.tag, a.id, PermUintToString(a.perm), a.perm)
}

// equalTagID returns true if the given ACLEntry carries
// the same ID and Tag values as actual entry. False otherwise.
// The perm attribute is not considered in this check.
func (a *ACLEntry) equalTagID(e *ACLEntry) bool {
	if e.tag != a.tag {
		return false
	}
	if e.id != a.id {
		return false
	}
	return true
}

// Equal returns true if the given ACLEntry equals the actual ACLEntry
func (a *ACLEntry) Equal(e *ACLEntry) bool {
	return a.id == e.id && a.tag == e.tag && a.perm == e.perm
}

// ToByteSlice returns the ACLEntry as a byte slice in
// little endian order, which is the representation required
// for the Setxattr(...) call
func (a *ACLEntry) ToByteSlice(result *bytes.Buffer) {
	binary.Write(result, binary.LittleEndian, a.tag)
	binary.Write(result, binary.LittleEndian, a.perm)
	binary.Write(result, binary.LittleEndian, a.id)
}
