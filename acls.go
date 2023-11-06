package acls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type ACLAttr string

const (
	PosixACLAccess  ACLAttr = "system.posix_acl_access"
	PosixACLDefault ACLAttr = "system.posix_acl_default"
)

type Tag uint16

const (
	// Undefined ACL type.
	TAG_ACL_UNDEFINED_FIELD = 0x0
	// Discretionary access rights for
	//processes whose effective user ID
	//matches the user ID of the file's owner.
	TAG_ACL_USER_OBJ = 0x1
	// Discretionary access rights for
	// processes whose effective user ID
	// matches the ACL entry qualifier.
	TAG_ACL_USER = 0x2
	// Discretionary access rights for
	// processes whose effective groupID or
	// any supplemental groups match the group
	// ID of the file's owner.
	TAG_ACL_GROUP_OBJ = 0x4
	// Discretionary access rights for
	// processes whose effective group ID or
	// any supplemental groups match the ACL
	// entry qualifier.
	TAG_ACL_GROUP = 0x8
	// The maximum discretionary access rights
	// that can be granted to a process in the
	// file group class. This is only valid
	// for POSIX.1e ACLs.
	TAG_ACL_MASK = 0x10
	// Discretionary access rights for
	// processes not covered by any other ACL
	// entry. This is only valid for POSIX.1e
	// ACLs.
	TAG_ACL_OTHER = 0x20
	// Same as ACL_OTHER.
	TAG_ACL_OTHER_OBJ = TAG_ACL_OTHER
	// Discretionary access rights for all
	// users. This is only valid for NFSv4
	// ACLs.
	TAG_ACL_EVERYONE = 0x40
)

// ACL handles Posix ACL data
type ACL struct {
	version uint32
	entries []*ACLEntry
}

// Load loads the attr defined POSIX.ACL type (access or default)
// from the given filepath
func (a *ACL) Load(fsPath string, attr ACLAttr) error {
	a.entries = []*ACLEntry{}
	a.version = 2

	// Get the ACL as an extended attribute.
	attrSize, err := unix.Getxattr(fsPath, string(attr), nil)
	switch {
	case err == unix.ENODATA:
		// there is not acl attached to the fsPath object
		// so bootstrap it with regular chown type of information
		return a.bootstrapACL(fsPath)
	case err != nil:
		return err
	}

	// Allocate a buffer to hold the ACL data.
	attrValue := make([]byte, attrSize)

	// Retrieve the ACL data.
	_, err = unix.Getxattr(fsPath, string(attr), attrValue)
	if err != nil {
		return err
	}

	return a.parse(attrValue)
}

func (a *ACL) bootstrapACL(fsPath string) error {
	var err error
	// no acl exists, so lets create a default one
	info, err := os.Stat(fsPath)
	if err != nil {
		return err
	}

	// determine UID and GID of fsPath
	file_sys := info.Sys()
	if file_sys == nil {
		return fmt.Errorf("error determining file %q UID and GID", fsPath)
	}
	Gid := file_sys.(*syscall.Stat_t).Gid
	Uid := file_sys.(*syscall.Stat_t).Uid

	// determine permissions
	perm := info.Mode().Perm()
	UserEntry := NewEntry(TAG_ACL_USER_OBJ, Uid, uint16((perm>>6)&7))
	GroupEntry := NewEntry(TAG_ACL_GROUP_OBJ, Gid, uint16((perm>>3)&7))
	MaskEntry := NewEntry(TAG_ACL_MASK, math.MaxUint16, uint16(7))
	OtherEntry := NewEntry(TAG_ACL_OTHER, math.MaxUint16, uint16(perm&7))

	// add newly created entries to the entries.
	a.entries = append(a.entries, UserEntry, GroupEntry, OtherEntry, MaskEntry)
	return nil
}

// Apply applies the ACL with its ACLEntries to as
// either access or default ACLs to the given filesstem path
func (a *ACL) Apply(fsPath string, attr ACLAttr) error {
	b := &bytes.Buffer{}
	a.toByteSlice(b)
	return unix.Setxattr(fsPath, string(attr), b.Bytes(), 0)
}

// toByteSlice return the ACL in its byte slice representation
// read to be used by Setxattr(...)
func (a *ACL) toByteSlice(result *bytes.Buffer) {
	a.sort()
	binary.Write(result, binary.LittleEndian, a.version)
	for _, e := range a.entries {
		e.ToByteSlice(result)
	}
}

// AddEntry adds the given entry to the ACL
// It will make sure that no entry with the same
// Tag and ID combination exists. If so, it will
// replace (not merge) the existing entry with the given.
func (a *ACL) AddEntry(e *ACLEntry) error {
	deleted := a.DeleteEntry(e)
	if deleted != nil {
		log.Debugf("Existing entry %q deleted", deleted.String())
	}
	a.entries = append(a.entries, e)
	return nil
}

// DeleteEntry deletes the entry that has the same tag and id
// if it exists and returns the deleted entry
func (a *ACL) DeleteEntry(e *ACLEntry) *ACLEntry {
	if pos := a.EntryExists(e); pos >= 0 {
		return a.deleteEntryPos(pos)
	}
	return nil
}

// deleteEntryPos delete the entry at a given position
// used internally
func (a *ACL) deleteEntryPos(pos int) *ACLEntry {
	tmp := a.entries
	a.entries = append(tmp[:pos], tmp[pos+1:]...)
	return tmp[pos]
}

// EntryExists checks if an entry with the given Tag and ID already exist
// if so it return -1 of not the position of the duplicate is returned as
// a positive int
func (a *ACL) EntryExists(e *ACLEntry) int {
	for pos, entry := range a.entries {
		if entry.equalTagID(e) {
			return pos
		}
	}
	return -1
}

// parse parses the byte slice that contains the ACLEntries
// and add them to a.entries.
func (a *ACL) parse(b []byte) error {
	if len(b) < 4 {
		return fmt.Errorf("expecting at least a 32 bit header, got %d", len(b)*4)
	}
	a.version = binary.LittleEndian.Uint32(b[:4])

	remainder := b[4:]
	var err error
	for {
		e := &ACLEntry{}
		remainder, err = e.parse(remainder)
		if err != nil {
			return err
		}
		a.entries = append(a.entries, e)
		if len(remainder) == 0 {
			break
		}
	}

	return nil
}

// String returns a human readable for of the ACL
func (a *ACL) String() string {
	sb := &strings.Builder{}

	for _, e := range a.entries {
		sb.WriteString(e.String())
		sb.WriteString("\n")
	}

	return fmt.Sprintf("ACL:\n-----\nVersion: %d\nEntries:\n%s\n", a.version, sb.String())
}

// sort Sorts the ACLEntries stored in a.entries
// by their tag number. To apply the ACL the tags ned to
// be in ascending order
func (a *ACL) sort() {
	sort.Slice(a.entries, func(i, j int) bool {
		return a.entries[i].tag < a.entries[j].tag
	})
}

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
	return fmt.Sprintf("Tag: %d, ID: %d, Perm: %d", a.tag, a.id, a.perm)
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

// ToByteSlice returns the ACLEntry as a byte slice in
// little endian order, which is the representation required
// for the Setxattr(...) call
func (a *ACLEntry) ToByteSlice(result *bytes.Buffer) {
	binary.Write(result, binary.LittleEndian, a.tag)
	binary.Write(result, binary.LittleEndian, a.perm)
	binary.Write(result, binary.LittleEndian, a.id)
}
