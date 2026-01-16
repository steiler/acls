package acls

import (
	"fmt"
	"strings"
	"testing"
)

func TestPermUintToString(t *testing.T) {
	type args struct {
		p uint16
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "perm 0",
			args: args{
				p: 0,
			},
			want: "---",
		},
		{
			name: "perm 1",
			args: args{
				p: 1,
			},
			want: "--x",
		},
		{
			name: "perm 2",
			args: args{
				p: 2,
			},
			want: "-w-",
		},
		{
			name: "perm 3",
			args: args{
				p: 3,
			},
			want: "-wx",
		},
		{
			name: "perm 4",
			args: args{
				p: 4,
			},
			want: "r--",
		},
		{
			name: "perm 5",
			args: args{
				p: 5,
			},
			want: "r-x",
		},
		{
			name: "perm 6",
			args: args{
				p: 6,
			},
			want: "rw-",
		},
		{
			name: "perm 7",
			args: args{
				p: 7,
			},
			want: "rwx",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PermUintToString(tt.args.p); got != tt.want {
				t.Errorf("PermUintToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermStringToUint(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		want        uint16
		wantErr     bool
		errContains string
	}{
		{
			name:    "no permissions",
			input:   "---",
			want:    PermNone,
			wantErr: false,
		},
		{
			name:    "execute only",
			input:   "--x",
			want:    PermExecute,
			wantErr: false,
		},
		{
			name:    "write only",
			input:   "-w-",
			want:    PermWrite,
			wantErr: false,
		},
		{
			name:    "write and execute",
			input:   "-wx",
			want:    PermWrite | PermExecute,
			wantErr: false,
		},
		{
			name:    "read only",
			input:   "r--",
			want:    PermRead,
			wantErr: false,
		},
		{
			name:    "read and execute",
			input:   "r-x",
			want:    PermRead | PermExecute,
			wantErr: false,
		},
		{
			name:    "read and write",
			input:   "rw-",
			want:    PermRead | PermWrite,
			wantErr: false,
		},
		{
			name:    "all permissions",
			input:   "rwx",
			want:    PermAll,
			wantErr: false,
		},
		{
			name:        "too short",
			input:       "rw",
			want:        0,
			wantErr:     true,
			errContains: "invalid permission string length",
		},
		{
			name:        "too long",
			input:       "rwxr",
			want:        0,
			wantErr:     true,
			errContains: "invalid permission string length",
		},
		{
			name:        "empty string",
			input:       "",
			want:        0,
			wantErr:     true,
			errContains: "invalid permission string length",
		},
		{
			name:    "with dashes in different positions",
			input:   "r-x",
			want:    PermRead | PermExecute,
			wantErr: false,
		},
		{
			name:    "all dashes",
			input:   "---",
			want:    PermNone,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := PermStringToUint(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("PermStringToUint() expected error, got nil")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("PermStringToUint() error = %v, want error containing %q", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("PermStringToUint() unexpected error = %v", err)
				}
			}

			if got != tt.want {
				t.Errorf("PermStringToUint() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermStringToUint_RoundTrip(t *testing.T) {
	// Test that converting to string and back gives the same result
	tests := []uint16{
		PermNone,
		PermExecute,
		PermWrite,
		PermWrite | PermExecute,
		PermRead,
		PermRead | PermExecute,
		PermRead | PermWrite,
		PermAll,
	}

	for _, perm := range tests {
		t.Run(fmt.Sprintf("perm_%d", perm), func(t *testing.T) {
			str := PermUintToString(perm)
			result, err := PermStringToUint(str)

			if err != nil {
				t.Errorf("PermStringToUint() unexpected error = %v", err)
			}
			if result != perm {
				t.Errorf("round-trip failed: started with %d, got string %q, ended with %d", perm, str, result)
			}
		})
	}
}
