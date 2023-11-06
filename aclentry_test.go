package acls

import "testing"

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
