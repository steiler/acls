[![codecov](https://codecov.io/gh/steiler/acls/graph/badge.svg?token=5DQWBVKCU3)](https://codecov.io/gh/steiler/acls)

# Overview

This library provides a pure Go implementation for managing Linux filesystem Access Control Lists (ACLs) without any cgo dependencies. It allows you to programmatically adjust both regular access ACLs (`system.posix_acl_access`) and default ACLs (`system.posix_acl_default`), serving as a native Go alternative to the `getfacl` and `setfacl` command-line tools.

**Key Features:**
- 🔒 **No cgo dependencies** - Pure Go implementation for maximum portability
- 🛡️ **Immutable entries** - ACL entries are immutable; modifications create new entries
- 🎯 **Type-safe** - Strong typing for tags, permissions, and IDs
- 🧰 **Intuitive API** - Fluent interface for permission manipulation
- ✅ **Well-tested** - Comprehensive test coverage

# Sample

## Basic Usage

This example demonstrates loading ACL entries from a file, adding a new entry, and applying the modified ACL back to the filesystem.

```go
package main

import (
    "fmt"
    log "github.com/sirupsen/logrus"
    "github.com/steiler/acls"
)

func main() {
    // Define the path to the file for which you want to manage ACLs
    filePath := "/tmp/foo"

    // Create a new ACL instance
    a := acls.NewACL()
    
    // Load existing ACL entries from the filesystem
    // If no ACL is attached, this loads standard POSIX permissions as ACL entries
    err := a.Load(filePath, acls.PosixACLAccess)
    if err != nil {
        log.Fatal(err)
    }
    
    // Add a new entry: grant group 5558 read+write+execute permissions
    err = a.AddEntry(acls.NewEntry(acls.TAG_ACL_GROUP, 5558, acls.PermAll))
    if err != nil {
        log.Fatal(err)
    }
    
    // Print a human-readable representation of the ACL
    fmt.Println(a.String())

    // Apply the modified ACL back to the filesystem as an access ACL
    err = a.Apply(filePath, acls.PosixACLAccess)
    if err != nil {
        log.Fatal(err)
    }
}
```

The output of the `fmt.Println(a.String())` looks like the following:

```
Version: 2
Entries:
Tag:   USER_OBJ ( 1), ID:       1000, Perm: rwx (7)
Tag:  GROUP_OBJ ( 4), ID:       1000, Perm: rwx (7)
Tag:      GROUP ( 8), ID:       5558, Perm: rwx (7)
Tag:       MASK (16), ID: 4294967295, Perm: rwx (7)
Tag:      OTHER (32), ID: 4294967295, Perm: r-x (5)
```

## Iterating Over Entries

You can retrieve and iterate over all ACL entries:

```go
a := acls.NewACL()
a.Load(filePath, acls.PosixACLAccess)

for _, entry := range a.GetEntries() {
    fmt.Printf("Tag: %s, ID: %d, Perm: %s\n", 
        acls.Tag2String(entry.Tag()), 
        entry.ID(), 
        acls.PermUintToString(entry.Perm()))
}
```

## Permission Manipulation

The library provides convenient methods for working with permissions:

```go
a := acls.NewACL()
a.Load(filePath, acls.PosixACLAccess)

// Add execute permission to all entries that have read permission
for _, entry := range a.GetEntries() {
    if entry.HasPerm(acls.PermRead) {
        // Create a new entry with execute permission added
        newEntry := entry.WithPerm(acls.PermExecute)
        a.AddEntry(newEntry)
    }
}

// Create an entry with exact permissions
entry := acls.NewEntry(acls.TAG_ACL_USER, 1000, acls.PermRead|acls.PermWrite)

// Remove write permission
readOnlyEntry := entry.WithoutPerm(acls.PermWrite)

// Set exact permissions
rwxEntry := entry.WithExactPerm(acls.PermAll)
```

Available permission constants:
- `acls.PermRead` - Read permission (r--)
- `acls.PermWrite` - Write permission (-w-)
- `acls.PermExecute` - Execute permission (--x)
- `acls.PermAll` - All permissions (rwx)
- `acls.PermNone` - No permissions (---)

# Features
- Add ACL Entry
- Delete ACL Entry
- Get specific ACL Entry
- Get all ACL Entries
- Modify ACL Entry (via delete + add)
- Read ACL entry fields (Tag, ID, Permission)
- Permission manipulation (add, remove, set, check)
- Permission constants for cleaner code
- Print ACL Entry
- Read ACL entries from one file object, apply to another
- Adjust default and access ACL
- Convert between string and numeric permission formats
