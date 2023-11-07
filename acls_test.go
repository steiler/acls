package acls

import (
	"bytes"
	"encoding/hex"
	"math"
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
			name: "input to short",
			args: args{
				s: "0200",
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
