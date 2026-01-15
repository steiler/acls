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

// ACL handles Posix ACL data
type ACL struct {
	Version uint32
	Entries []*ACLEntry
}

// Load loads the attr defined POSIX.ACL type (access or default)
// from the given filepath
func (a *ACL) Load(fsPath string, attr ACLAttr) error {
	a.Entries = []*ACLEntry{}
	a.Version = 2

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

// bootstrapACL loads the regular file permissions as ACL entries
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
	MaskEntry := NewEntry(TAG_ACL_MASK, math.MaxUint32, uint16(7))
	OtherEntry := NewEntry(TAG_ACL_OTHER, math.MaxUint32, uint16(perm&7))

	// add newly created entries to the entries.
	a.Entries = append(a.Entries, UserEntry, GroupEntry, OtherEntry, MaskEntry)
	return nil
}

// Apply applies the ACL with its ACLEntries to as
// either access or default ACLs to the given filesstem path
func (a *ACL) Apply(fsPath string, attr ACLAttr) error {
	b := &bytes.Buffer{}
	a.ToByteSlice(b)
	return unix.Setxattr(fsPath, string(attr), b.Bytes(), 0)
}

// ToByteSlice return the ACL in its byte slice representation
// read to be used by Setxattr(...)
func (a *ACL) ToByteSlice(result *bytes.Buffer) {
	a.sort()
	binary.Write(result, binary.LittleEndian, a.Version)
	for _, e := range a.Entries {
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
	a.Entries = append(a.Entries, e)
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
	result := a.Entries[pos]
	a.Entries = append(a.Entries[:pos], a.Entries[pos+1:]...)
	return result
}

// EntryExists checks if an entry with the given Tag and ID already exist
// if so it return -1 of not the position of the duplicate is returned as
// a positive int
func (a *ACL) EntryExists(e *ACLEntry) int {
	for pos, entry := range a.Entries {
		if entry.equalTagID(e) {
			return pos
		}
	}
	return -1
}

// Equal returns true if the given ACL equals the actual ACL
func (a *ACL) Equal(e *ACL) bool {
	if !(len(a.Entries) == len(e.Entries) && a.Version == e.Version) {
		return false
	}
	// sort before comparing
	a.sort()
	e.sort()
	for id, val := range a.Entries {
		if !val.Equal(e.Entries[id]) {
			return false
		}
	}
	return true
}

// parse parses the byte slice that contains the ACLEntries
// and add them to a.Entries.
func (a *ACL) parse(b []byte) error {
	if len(b) < 4 {
		return fmt.Errorf("expecting at least a 32 bit header, got %d", len(b)*4)
	}
	a.Version = binary.LittleEndian.Uint32(b[:4])

	remainder := b[4:]
	var err error
	for {
		e := &ACLEntry{}
		remainder, err = e.parse(remainder)
		if err != nil {
			return err
		}
		a.Entries = append(a.Entries, e)
		if len(remainder) == 0 {
			break
		}
	}

	return nil
}

// String returns a human readable for of the ACL
func (a *ACL) String() string {
	sb := &strings.Builder{}
	// sort before generating
	a.sort()

	for _, e := range a.Entries {
		sb.WriteString(e.String())
		sb.WriteString("\n")
	}

	return fmt.Sprintf("Version: %d\nEntries:\n%s", a.Version, sb.String())
}

// sort Sorts the ACLEntries stored in a.Entries
// by their tag number. To apply the ACL the tags ned to
// be in ascending order
func (a *ACL) sort() {
	sort.Slice(a.Entries, func(i, j int) bool {
		return a.Entries[i].Tag < a.Entries[j].Tag
	})
}

// copy returns a copy of the ACL
func (a *ACL) Copy() *ACL {
	c := ACL{Version: a.Version}
	c.Entries = make([]*ACLEntry, len(a.Entries))

	for i, e := range a.Entries {
		d := *e
		c.Entries[i] = &d
	}

	return &c
}
