package acls

import (
	"bytes"
	"encoding/hex"
	"math"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"testing"
)

func TestACL_String(t *testing.T) {
	type fields struct {
		version uint32
		entries []*ACLEntry
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "Regular, two entries",
			fields: fields{
				version: 2,
				entries: []*ACLEntry{
					NewEntry(TAG_ACL_USER, 55, 7),
					NewEntry(TAG_ACL_GROUP, 5000, 6),
				},
			},
			want: `Version: 2
Entries:
Tag:       USER ( 2), ID:         55, Perm: rwx (7)
Tag:      GROUP ( 8), ID:       5000, Perm: rw- (6)
`,
		},
		{
			name: "No Entries",
			fields: fields{
				version: 2,
				entries: []*ACLEntry{},
			},
			want: `Version: 2
Entries:
`,
		},
		{
			name: "Regular, two entries max uint32 UID",
			fields: fields{
				version: 2,
				entries: []*ACLEntry{
					NewEntry(TAG_ACL_USER, math.MaxUint32, 7),
					NewEntry(TAG_ACL_GROUP, math.MaxUint32, 2),
				},
			},
			want: `Version: 2
Entries:
Tag:       USER ( 2), ID: 4294967295, Perm: rwx (7)
Tag:      GROUP ( 8), ID: 4294967295, Perm: -w- (2)
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ACL{
				version: tt.fields.version,
				entries: tt.fields.entries,
			}
			if got := a.String(); got != tt.want {
				t.Errorf("ACL.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

var unsortedACLEntries = []*ACLEntry{
	NewEntry(TAG_ACL_USER_OBJ, 2222, 7),
	NewEntry(TAG_ACL_EVERYONE, math.MaxUint32, 2),
	NewEntry(TAG_ACL_OTHER, math.MaxUint32, 2),
	NewEntry(TAG_ACL_MASK, math.MaxUint32, 2),
	NewEntry(TAG_ACL_GROUP_OBJ, 6666, 2),
	NewEntry(TAG_ACL_GROUP, 7777, 2),
	NewEntry(TAG_ACL_USER, 1111, 2),
}

func TestACL_sort(t *testing.T) {
	type fields struct {
		version uint32
		entries []*ACLEntry
	}
	tests := []struct {
		name   string
		fields fields
		want   *ACL
	}{
		{
			name: "one",
			fields: fields{
				version: 2,
				entries: unsortedACLEntries,
			},
			want: &ACL{
				version: 2,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
					unsortedACLEntries[6],
					unsortedACLEntries[4],
					unsortedACLEntries[5],
					unsortedACLEntries[3],
					unsortedACLEntries[2],
					unsortedACLEntries[1],
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &ACL{
				version: tt.fields.version,
				entries: tt.fields.entries,
			}
			a.sort()
			for id, val := range a.entries {
				if tt.want.entries[id] != val {
					t.Logf("Position %d should be %v but is %v", id, tt.want.entries[id], val)
					t.Fail()
				}
			}
		})
	}
}

func TestACL_parse(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name    string
		result  *ACL
		args    args
		wantErr bool
	}{
		{
			name: "parse",
			result: &ACL{
				version: 2,
				entries: []*ACLEntry{
					NewEntry(TAG_ACL_USER_OBJ, 4294967295, 7),
					NewEntry(TAG_ACL_GROUP_OBJ, 4294967295, 7),
					NewEntry(TAG_ACL_GROUP, 5558, 7),
					NewEntry(TAG_ACL_MASK, 4294967295, 7),
					NewEntry(TAG_ACL_OTHER, 4294967295, 5),
				},
			},
			args: args{
				s: "0200000001000700ffffffff04000700ffffffff08000700b615000010000700ffffffff20000500ffffffff",
			},
			wantErr: false,
		},
		{
			name: "input to short ACL",
			args: args{
				s: "0200",
			},
			wantErr: true,
		},
		{
			name: "input to short ACLEntry",
			args: args{
				s: "0200000001000700ff",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := hex.DecodeString(tt.args.s)
			acl := &ACL{}
			if err != nil {
				t.Errorf("failed to decode hex string %q", tt.args.s)
			}
			if err := acl.parse(b); (err != nil) != tt.wantErr {
				t.Errorf("ACL.parse() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				// should not continue with equal check then we expect an error
				return
			}
			if !tt.result.Equal(acl) {
				t.Errorf("expected %s, got %s", tt.result.String(), acl.String())
			}
		})
	}
}

func TestACL_ToByteSlice(t *testing.T) {
	tests := []struct {
		name   string
		acl    *ACL
		result string
	}{
		{
			name: "Entries sorted",
			acl: &ACL{
				version: 2,
				entries: []*ACLEntry{
					NewEntry(TAG_ACL_USER_OBJ, 4294967295, 7),
					NewEntry(TAG_ACL_GROUP_OBJ, 4294967295, 7),
					NewEntry(TAG_ACL_GROUP, 5558, 7),
					NewEntry(TAG_ACL_MASK, 4294967295, 7),
					NewEntry(TAG_ACL_OTHER, 4294967295, 5),
				},
			},
			result: "0200000001000700ffffffff04000700ffffffff08000700b615000010000700ffffffff20000500ffffffff",
		},
		{
			name: "Entries unsorted",
			acl: &ACL{
				version: 2,
				entries: []*ACLEntry{
					NewEntry(TAG_ACL_MASK, 4294967295, 7),
					NewEntry(TAG_ACL_OTHER, 4294967295, 5),
					NewEntry(TAG_ACL_USER_OBJ, 4294967295, 7),
					NewEntry(TAG_ACL_GROUP, 5558, 7),
					NewEntry(TAG_ACL_GROUP_OBJ, 4294967295, 7),
				},
			},
			result: "0200000001000700ffffffff04000700ffffffff08000700b615000010000700ffffffff20000500ffffffff",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &bytes.Buffer{}
			tt.acl.ToByteSlice(b)
			result := hex.EncodeToString(b.Bytes())
			if result != tt.result {
				t.Errorf("byte representations do not match. expected %q, got %q", tt.result, result)
			}
		})
	}
}

func TestACL_AddEntry(t *testing.T) {
	tests := []struct {
		name       string
		acl        *ACL
		addEntry   *ACLEntry
		wantErr    bool
		entriesLen int
	}{
		{
			name:       "Add to empty",
			acl:        &ACL{},
			addEntry:   NewEntry(TAG_ACL_GROUP, 5555, 7),
			entriesLen: 1,
			wantErr:    false,
		},
		{
			name: "Add to existing list",
			acl: &ACL{
				entries: []*ACLEntry{
					NewEntry(TAG_ACL_GROUP, 5556, 7),
					NewEntry(TAG_ACL_EVERYONE, math.MaxUint32, 7),
					NewEntry(TAG_ACL_GROUP, 8845, 7),
				},
			},
			addEntry:   NewEntry(TAG_ACL_GROUP, 5555, 7),
			entriesLen: 4,
			wantErr:    false,
		},
		{
			name: "Add overwriting existing Tag+ID",
			acl: &ACL{
				entries: []*ACLEntry{
					NewEntry(TAG_ACL_EVERYONE, math.MaxUint32, 7),
					NewEntry(TAG_ACL_GROUP, 5556, 7),
				},
			},
			addEntry:   NewEntry(TAG_ACL_GROUP, 5556, 5),
			entriesLen: 2,
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.acl.AddEntry(tt.addEntry); (err != nil) != tt.wantErr {
				t.Errorf("ACL.AddEntry() error = %v, wantErr %v", err, tt.wantErr)
			}
			if len(tt.acl.entries) != tt.entriesLen {
				t.Errorf("expected %d entries, but contains %d", tt.entriesLen, len(tt.acl.entries))
			}
			exists := false
			for _, e := range tt.acl.entries {
				if e.Equal(tt.addEntry) {
					exists = true
					break
				}
			}
			if !exists {
				t.Errorf("expected entry\n%s not found", tt.addEntry.String())
			}
		})
	}
}

func TestACL_Equal(t *testing.T) {
	tests := []struct {
		name   string
		ACLOne *ACL
		ACLTwo *ACL
		want   bool
	}{
		{
			name: "Equal",
			want: true,
			ACLOne: &ACL{
				version: 2,
				entries: unsortedACLEntries,
			},
			ACLTwo: &ACL{
				version: 2,
				entries: unsortedACLEntries,
			},
		},
		{
			name: "Not Equal same length",
			want: false,
			ACLOne: &ACL{
				version: 2,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
					unsortedACLEntries[1],
					unsortedACLEntries[2],
				},
			},
			ACLTwo: &ACL{
				version: 2,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
					unsortedACLEntries[1],
					unsortedACLEntries[3],
				},
			},
		},
		{
			name: "Same entries different order",
			want: true,
			ACLOne: &ACL{
				version: 2,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
					unsortedACLEntries[1],
					unsortedACLEntries[2],
				},
			},
			ACLTwo: &ACL{
				version: 2,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
					unsortedACLEntries[2],
					unsortedACLEntries[1],
				},
			},
		},
		{
			name: "Different Version",
			want: false,
			ACLOne: &ACL{
				version: 3,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
				},
			},
			ACLTwo: &ACL{
				version: 2,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.ACLOne.Equal(tt.ACLTwo); got != tt.want {
				t.Errorf("ACL.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACL_Load(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Errorf("error determining user and group")
	}
	UID, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Errorf("error converting UID %s to int", u.Uid)
	}
	GID, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Errorf("error converting GID %s to int", u.Gid)
	}

	tests := []struct {
		name     string
		wantErr  bool
		attr     ACLAttr
		result   *ACL
		entryLen int
	}{
		{
			name:    "Load non acl",
			wantErr: false,
			attr:    PosixACLAccess,
			result: &ACL{
				version: 2,
				entries: []*ACLEntry{
					NewEntry(TAG_ACL_USER_OBJ, uint32(UID), 6),
					NewEntry(TAG_ACL_GROUP_OBJ, uint32(GID), 0),
					NewEntry(TAG_ACL_MASK, math.MaxUint32, 7),
					NewEntry(TAG_ACL_OTHER, math.MaxUint32, 0),
				},
			},
			entryLen: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			f, err := os.CreateTemp("", "acltest")
			if err != nil {
				t.Errorf("failed to create directory for testing")
			}

			a := &ACL{}
			if err := a.Load(f.Name(), tt.attr); (err != nil) != tt.wantErr {
				t.Errorf("ACL.Load() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				// we wanted an error so lets not check the result any further
				return
			}
			if len(a.entries) != tt.entryLen {
				t.Errorf("expected %d entries got %d", tt.entryLen, len(a.entries))
			}
			tt.result.sort()
			a.sort()
			if !a.Equal(tt.result) {
				t.Errorf("expected %s, got %s", tt.result.String(), a.String())
			}
			err = f.Close()
			if err != nil {
				t.Errorf("failed closing temp file %s: %v", f.Name(), err)
			}
			err = os.Remove(f.Name())
			if err != nil {
				t.Errorf("failed removing temp file %s: %v", f.Name(), err)
			}
		})
	}
}

func TestLoadApplyLoad(t *testing.T) {
	// create a tmp file
	f, err := os.CreateTemp("", "acltest")
	if err != nil {
		t.Errorf("failed to create directory for testing %v", err)
	}

	// init new acl
	a := &ACL{}
	// load ACL
	err = a.Load(f.Name(), PosixACLAccess)
	if err != nil {
		t.Errorf("failed loading ACL %v", err)
	}

	err = a.Apply(f.Name(), PosixACLAccess)
	if err != nil {
		t.Errorf("failed applying acl to %q: %v", f.Name(), err)
	}

	// reload updated policy
	err = a.Load(f.Name(), PosixACLAccess)
	if err != nil {
		t.Errorf("failed loading ACL %v", err)
	}

	// close the file
	err = f.Close()
	if err != nil {
		t.Errorf("failed closing temp file %s", f.Name())
	}
	// remove the tmp file
	err = os.Remove(f.Name())
	if err != nil {
		t.Errorf("failed removing temp file %s", f.Name())
	}
}

func TestACL_DeleteEntry(t *testing.T) {

	tests := []struct {
		name          string
		acl           *ACL
		deleteEntry   *ACLEntry // tag and id must match the one on the acl
		deletedEntry  *ACLEntry // is the one deleted from the ACL
		shouldSucceed bool
	}{
		{
			name: "Delete an entry",
			acl: &ACL{
				version: 2,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
					unsortedACLEntries[1],
					unsortedACLEntries[2],
					unsortedACLEntries[3],
					unsortedACLEntries[4],
				},
			},
			deleteEntry:   NewEntry(unsortedACLEntries[2].tag, unsortedACLEntries[2].id, unsortedACLEntries[2].perm),
			deletedEntry:  unsortedACLEntries[2],
			shouldSucceed: true,
		},
		{
			name: "Delete non-existing",
			acl: &ACL{
				version: 2,
				entries: []*ACLEntry{
					unsortedACLEntries[0],
					unsortedACLEntries[1],
					unsortedACLEntries[2],
					unsortedACLEntries[3],
					unsortedACLEntries[4],
				},
			},
			deleteEntry:   NewEntry(TAG_ACL_GROUP, 32456, 7),
			deletedEntry:  nil,
			shouldSucceed: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			preLen := len(tt.acl.entries)

			if got := tt.acl.DeleteEntry(tt.deleteEntry); !reflect.DeepEqual(got, tt.deletedEntry) {
				t.Errorf("ACL.DeleteEntry() = %v, want %v", got, tt.deletedEntry)
			}
			if tt.shouldSucceed {
				if preLen-1 != len(tt.acl.entries) {
					t.Errorf("expected %d entries after delete, got %d", preLen-1, len(tt.acl.entries))
				}
			}
		})
	}
}

func TestGetEntry(t *testing.T) {
	tests := []struct {
		name       string
		setupFunc  func(*ACL)
		searchTag  Tag
		searchID   uint32
		expectNil  bool
		expectPerm uint16
	}{
		{
			name: "get existing user entry",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries, NewEntry(TAG_ACL_USER, 1000, 6))
			},
			searchTag:  TAG_ACL_USER,
			searchID:   1000,
			expectNil:  false,
			expectPerm: 6,
		},
		{
			name: "get existing group entry",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries, NewEntry(TAG_ACL_GROUP, 2000, 7))
			},
			searchTag:  TAG_ACL_GROUP,
			searchID:   2000,
			expectNil:  false,
			expectPerm: 7,
		},
		{
			name: "get non-existing entry returns nil",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries, NewEntry(TAG_ACL_USER, 1000, 6))
			},
			searchTag: TAG_ACL_USER,
			searchID:  5000,
			expectNil: true,
		},
		{
			name: "get from empty ACL returns nil",
			setupFunc: func(a *ACL) {
				// no entries added
			},
			searchTag: TAG_ACL_USER,
			searchID:  1000,
			expectNil: true,
		},
		{
			name: "get user entry among multiple different tag types",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries,
					NewEntry(TAG_ACL_USER_OBJ, math.MaxUint32, 7),
					NewEntry(TAG_ACL_USER, 1000, 6),
					NewEntry(TAG_ACL_GROUP, 2000, 5),
					NewEntry(TAG_ACL_MASK, math.MaxUint32, 7),
					NewEntry(TAG_ACL_OTHER, math.MaxUint32, 0),
				)
			},
			searchTag:  TAG_ACL_USER,
			searchID:   1000,
			expectNil:  false,
			expectPerm: 6,
		},
		{
			name: "get group entry among multiple different tag types",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries,
					NewEntry(TAG_ACL_USER_OBJ, math.MaxUint32, 7),
					NewEntry(TAG_ACL_USER, 1000, 6),
					NewEntry(TAG_ACL_GROUP, 2000, 5),
					NewEntry(TAG_ACL_MASK, math.MaxUint32, 7),
					NewEntry(TAG_ACL_OTHER, math.MaxUint32, 0),
				)
			},
			searchTag:  TAG_ACL_GROUP,
			searchID:   2000,
			expectNil:  false,
			expectPerm: 5,
		},
		{
			name: "get user from multiple user entries with different IDs",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries,
					NewEntry(TAG_ACL_USER, 1000, 6),
					NewEntry(TAG_ACL_USER, 1001, 7),
					NewEntry(TAG_ACL_USER, 1002, 5),
					NewEntry(TAG_ACL_GROUP, 2000, 4),
				)
			},
			searchTag:  TAG_ACL_USER,
			searchID:   1001,
			expectNil:  false,
			expectPerm: 7,
		},
		{
			name: "get group from multiple group entries with different IDs",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries,
					NewEntry(TAG_ACL_GROUP, 2000, 6),
					NewEntry(TAG_ACL_GROUP, 2001, 7),
					NewEntry(TAG_ACL_GROUP, 2002, 5),
					NewEntry(TAG_ACL_USER, 1000, 4),
				)
			},
			searchTag:  TAG_ACL_GROUP,
			searchID:   2002,
			expectNil:  false,
			expectPerm: 5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := &ACL{version: 2}
			tt.setupFunc(acl)

			searchEntry := NewEntry(tt.searchTag, tt.searchID, 0)
			result := acl.GetEntry(searchEntry)

			if tt.expectNil && result != nil {
				t.Errorf("expected nil, got %v", result)
			}
			if !tt.expectNil && result == nil {
				t.Errorf("expected entry, got nil")
			}
			if !tt.expectNil && result.perm != tt.expectPerm {
				t.Errorf("expected perm %d, got %d", tt.expectPerm, result.perm)
			}
		})
	}
}

func TestACL_GetEntries(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func(*ACL)
		expectLen int
	}{
		{
			name: "get entries from empty ACL",
			setupFunc: func(a *ACL) {
				// no entries added
			},
			expectLen: 0,
		},
		{
			name: "get single entry",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries, NewEntry(TAG_ACL_USER, 1000, 6))
			},
			expectLen: 1,
		},
		{
			name: "get multiple entries",
			setupFunc: func(a *ACL) {
				a.entries = append(a.entries,
					NewEntry(TAG_ACL_USER_OBJ, math.MaxUint32, 7),
					NewEntry(TAG_ACL_USER, 1000, 6),
					NewEntry(TAG_ACL_GROUP, 2000, 5),
					NewEntry(TAG_ACL_OTHER, math.MaxUint32, 0),
				)
			},
			expectLen: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acl := &ACL{version: 2}
			tt.setupFunc(acl)

			entries := acl.GetEntries()

			if entries == nil {
				t.Errorf("expected non-nil slice, got nil")
			}
			if len(entries) != tt.expectLen {
				t.Errorf("expected %d entries, got %d", tt.expectLen, len(entries))
			}
		})
	}
}

func TestACL_GetEntries_IsSliceCopy(t *testing.T) {
	// Specifically test that GetEntries returns a true slice copy
	acl := &ACL{
		version: 2,
		entries: []*ACLEntry{
			NewEntry(TAG_ACL_USER, 1000, 6),
			NewEntry(TAG_ACL_GROUP, 2000, 5),
			NewEntry(TAG_ACL_MASK, math.MaxUint32, 7),
		},
	}

	entries1 := acl.GetEntries()
	entries2 := acl.GetEntries()

	// Both should have same content
	if len(entries1) != len(entries2) {
		t.Errorf("two calls to GetEntries have different lengths: %d vs %d", len(entries1), len(entries2))
	}

	// But they should be different slice objects
	if &entries1[0] == &entries2[0] {
		t.Errorf("GetEntries returned references to the same slice, should be copies")
	}

	// Modifying one should not affect the other
	entries1 = append(entries1, NewEntry(TAG_ACL_OTHER, math.MaxUint32, 0))
	if len(entries2) == len(entries1) {
		t.Errorf("modifying returned slice affected subsequent calls")
	}

	// Original ACL should still have 3 entries
	if len(acl.entries) != 3 {
		t.Errorf("modifications to returned slice affected original ACL")
	}
}

func TestACL_GetEntries_AllEntriesPresent(t *testing.T) {
	// Test that all entries are returned and in accessible form
	originalEntries := []*ACLEntry{
		NewEntry(TAG_ACL_USER_OBJ, 1001, 7),
		NewEntry(TAG_ACL_USER, 2001, 6),
		NewEntry(TAG_ACL_USER, 2002, 5),
		NewEntry(TAG_ACL_GROUP_OBJ, 3001, 7),
		NewEntry(TAG_ACL_GROUP, 3002, 6),
		NewEntry(TAG_ACL_MASK, math.MaxUint32, 7),
		NewEntry(TAG_ACL_OTHER, math.MaxUint32, 0),
	}

	acl := &ACL{
		version: 2,
		entries: append([]*ACLEntry{}, originalEntries...),
	}

	retrieved := acl.GetEntries()

	if len(retrieved) != len(originalEntries) {
		t.Fatalf("expected %d entries, got %d", len(originalEntries), len(retrieved))
	}

	// Verify each entry can be compared
	for i, entry := range originalEntries {
		if !entry.Equal(retrieved[i]) {
			t.Errorf("entry %d not equal: expected %v, got %v", i, entry.String(), retrieved[i].String())
		}
	}
}
