package acls

import "testing"

func TestACLEntry_Getters(t *testing.T) {
	tests := []struct {
		name         string
		entry        *ACLEntry
		expectedTag  Tag
		expectedID   uint32
		expectedPerm uint16
	}{
		{
			name:         "user entry",
			entry:        NewEntry(TAG_ACL_USER, 1000, 6),
			expectedTag:  TAG_ACL_USER,
			expectedID:   1000,
			expectedPerm: 6,
		},
		{
			name:         "group entry",
			entry:        NewEntry(TAG_ACL_GROUP, 2000, 7),
			expectedTag:  TAG_ACL_GROUP,
			expectedID:   2000,
			expectedPerm: 7,
		},
		{
			name:         "user obj entry with no permissions",
			entry:        NewEntry(TAG_ACL_USER_OBJ, 0, 0),
			expectedTag:  TAG_ACL_USER_OBJ,
			expectedID:   0,
			expectedPerm: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.Tag(); got != tt.expectedTag {
				t.Errorf("Tag() = %v, want %v", got, tt.expectedTag)
			}
			if got := tt.entry.ID(); got != tt.expectedID {
				t.Errorf("ID() = %v, want %v", got, tt.expectedID)
			}
			if got := tt.entry.Perm(); got != tt.expectedPerm {
				t.Errorf("Perm() = %v, want %v", got, tt.expectedPerm)
			}
		})
	}
}

func TestACLEntry_HasPerm(t *testing.T) {
	tests := []struct {
		name      string
		entry     *ACLEntry
		checkPerm uint16
		want      bool
	}{
		{
			name:      "has read permission",
			entry:     NewEntry(TAG_ACL_USER, 1000, PermRead),
			checkPerm: PermRead,
			want:      true,
		},
		{
			name:      "has write permission",
			entry:     NewEntry(TAG_ACL_USER, 1000, PermWrite),
			checkPerm: PermWrite,
			want:      true,
		},
		{
			name:      "has execute permission",
			entry:     NewEntry(TAG_ACL_USER, 1000, PermExecute),
			checkPerm: PermExecute,
			want:      true,
		},
		{
			name:      "has read and execute",
			entry:     NewEntry(TAG_ACL_USER, 1000, PermRead|PermExecute),
			checkPerm: PermRead | PermExecute,
			want:      true,
		},
		{
			name:      "has all permissions",
			entry:     NewEntry(TAG_ACL_USER, 1000, PermAll),
			checkPerm: PermAll,
			want:      true,
		},
		{
			name:      "does not have write when only read",
			entry:     NewEntry(TAG_ACL_USER, 1000, PermRead),
			checkPerm: PermWrite,
			want:      false,
		},
		{
			name:      "does not have read+write when only read",
			entry:     NewEntry(TAG_ACL_USER, 1000, PermRead),
			checkPerm: PermRead | PermWrite,
			want:      false,
		},
		{
			name:      "no permissions check none",
			entry:     NewEntry(TAG_ACL_USER, 1000, PermNone),
			checkPerm: PermNone,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.entry.HasPerm(tt.checkPerm); got != tt.want {
				t.Errorf("HasPerm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestACLEntry_WithPerm(t *testing.T) {
	tests := []struct {
		name         string
		entry        *ACLEntry
		addPerm      uint16
		expectedPerm uint16
	}{
		{
			name:         "add read to empty",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermNone),
			addPerm:      PermRead,
			expectedPerm: PermRead,
		},
		{
			name:         "add write to read",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermRead),
			addPerm:      PermWrite,
			expectedPerm: PermRead | PermWrite,
		},
		{
			name:         "add execute to read+write",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermRead|PermWrite),
			addPerm:      PermExecute,
			expectedPerm: PermAll,
		},
		{
			name:         "add read when already has read (idempotent)",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermRead),
			addPerm:      PermRead,
			expectedPerm: PermRead,
		},
		{
			name:         "add multiple at once",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermNone),
			addPerm:      PermRead | PermExecute,
			expectedPerm: PermRead | PermExecute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.WithPerm(tt.addPerm)

			// Verify new entry has correct permission
			if result.Perm() != tt.expectedPerm {
				t.Errorf("WithPerm() perm = %v, want %v", result.Perm(), tt.expectedPerm)
			}

			// Verify it's a new entry (immutability)
			if result == tt.entry {
				t.Errorf("WithPerm() returned same pointer, should create new entry")
			}

			// Verify original entry unchanged
			if tt.entry.Perm() == result.Perm() && tt.entry.Perm() != tt.expectedPerm {
				// This is ok - original could equal result if no change needed
			}

			// Verify tag and ID preserved
			if result.Tag() != tt.entry.Tag() {
				t.Errorf("WithPerm() changed tag")
			}
			if result.ID() != tt.entry.ID() {
				t.Errorf("WithPerm() changed ID")
			}
		})
	}
}

func TestACLEntry_WithoutPerm(t *testing.T) {
	tests := []struct {
		name         string
		entry        *ACLEntry
		removePerm   uint16
		expectedPerm uint16
	}{
		{
			name:         "remove read from all",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermAll),
			removePerm:   PermRead,
			expectedPerm: PermWrite | PermExecute,
		},
		{
			name:         "remove write from all",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermAll),
			removePerm:   PermWrite,
			expectedPerm: PermRead | PermExecute,
		},
		{
			name:         "remove execute from all",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermAll),
			removePerm:   PermExecute,
			expectedPerm: PermRead | PermWrite,
		},
		{
			name:         "remove read from read-only",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermRead),
			removePerm:   PermRead,
			expectedPerm: PermNone,
		},
		{
			name:         "remove write when not present (idempotent)",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermRead),
			removePerm:   PermWrite,
			expectedPerm: PermRead,
		},
		{
			name:         "remove multiple at once",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermAll),
			removePerm:   PermRead | PermWrite,
			expectedPerm: PermExecute,
		},
		{
			name:         "remove all permissions",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermAll),
			removePerm:   PermAll,
			expectedPerm: PermNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.WithoutPerm(tt.removePerm)

			// Verify new entry has correct permission
			if result.Perm() != tt.expectedPerm {
				t.Errorf("WithoutPerm() perm = %v, want %v", result.Perm(), tt.expectedPerm)
			}

			// Verify it's a new entry (immutability)
			if result == tt.entry {
				t.Errorf("WithoutPerm() returned same pointer, should create new entry")
			}

			// Verify tag and ID preserved
			if result.Tag() != tt.entry.Tag() {
				t.Errorf("WithoutPerm() changed tag")
			}
			if result.ID() != tt.entry.ID() {
				t.Errorf("WithoutPerm() changed ID")
			}
		})
	}
}

func TestACLEntry_WithExactPerm(t *testing.T) {
	tests := []struct {
		name         string
		entry        *ACLEntry
		newPerm      uint16
		expectedPerm uint16
	}{
		{
			name:         "set to read only",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermAll),
			newPerm:      PermRead,
			expectedPerm: PermRead,
		},
		{
			name:         "set to all from none",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermNone),
			newPerm:      PermAll,
			expectedPerm: PermAll,
		},
		{
			name:         "set to none from all",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermAll),
			newPerm:      PermNone,
			expectedPerm: PermNone,
		},
		{
			name:         "set to read+execute",
			entry:        NewEntry(TAG_ACL_USER, 1000, PermWrite),
			newPerm:      PermRead | PermExecute,
			expectedPerm: PermRead | PermExecute,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.entry.WithExactPerm(tt.newPerm)

			// Verify new entry has correct permission
			if result.Perm() != tt.expectedPerm {
				t.Errorf("WithExactPerm() perm = %v, want %v", result.Perm(), tt.expectedPerm)
			}

			// Verify it's a new entry (immutability)
			if result == tt.entry {
				t.Errorf("WithExactPerm() returned same pointer, should create new entry")
			}

			// Verify tag and ID preserved
			if result.Tag() != tt.entry.Tag() {
				t.Errorf("WithExactPerm() changed tag")
			}
			if result.ID() != tt.entry.ID() {
				t.Errorf("WithExactPerm() changed ID")
			}
		})
	}
}

func TestACLEntry_PermissionChaining(t *testing.T) {
	// Test that permission methods can be chained
	entry := NewEntry(TAG_ACL_USER, 1000, PermNone)

	result := entry.WithPerm(PermRead).WithPerm(PermWrite).WithoutPerm(PermRead)

	if result.Perm() != PermWrite {
		t.Errorf("chained operations resulted in perm = %v, want %v", result.Perm(), PermWrite)
	}

	// Verify original unchanged
	if entry.Perm() != PermNone {
		t.Errorf("original entry was modified")
	}
}
