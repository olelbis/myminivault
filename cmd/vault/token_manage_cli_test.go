package main

import (
	"strings"
	"testing"
	"time"
)

func TestParseTokenCreationOptions(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    tokenCreationOptions
		wantErr string
	}{
		{
			name: "defaults read permission and max uses",
			args: []string{"--keys=API_*", "--duration=2h"},
			want: tokenCreationOptions{keyPattern: "API_*", duration: 2 * time.Hour, permissions: []string{"read"}, maxUses: 100},
		},
		{
			name: "accepts trimmed explicit permissions",
			args: []string{"--keys=*", "--duration=30m", "--permissions=read, write", "--max-uses=4"},
			want: tokenCreationOptions{keyPattern: "*", duration: 30 * time.Minute, permissions: []string{"read", "write"}, maxUses: 4},
		},
		{name: "requires key pattern", args: []string{"--duration=2h"}, wantErr: "both --keys and --duration are required"},
		{name: "requires duration", args: []string{"--keys=API_*"}, wantErr: "both --keys and --duration are required"},
		{name: "rejects colon pattern", args: []string{"--keys=API:*", "--duration=2h"}, wantErr: "token key patterns cannot contain ':'"},
		{name: "rejects invalid duration", args: []string{"--keys=API_*", "--duration=tomorrow"}, wantErr: "invalid duration format"},
		{name: "rejects long duration", args: []string{"--keys=API_*", "--duration=25h"}, wantErr: "maximum duration is 24 hours for security"},
		{name: "rejects invalid max uses", args: []string{"--keys=API_*", "--duration=2h", "--max-uses=0"}, wantErr: "max uses must be greater than zero"},
		{name: "rejects invalid permission", args: []string{"--keys=API_*", "--duration=2h", "--permissions=admin"}, wantErr: "invalid permission: admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTokenCreationOptions(tt.args)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTokenCreationOptions: %v", err)
			}
			if got.keyPattern != tt.want.keyPattern || got.duration != tt.want.duration || got.maxUses != tt.want.maxUses || strings.Join(got.permissions, ",") != strings.Join(tt.want.permissions, ",") {
				t.Fatalf("options = %+v, want %+v", got, tt.want)
			}
		})
	}
}
