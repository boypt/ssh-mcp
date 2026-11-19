package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExactHostValuePrecedesWildcardBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "Host *\n  StrictHostKeyChecking accept-new\n\nHost jarvis\n  StrictHostKeyChecking yes\n\nHost *.lab\n  StrictHostKeyChecking no\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	if got := exactHostValue("jarvis", "StrictHostKeyChecking"); got != "yes" {
		t.Errorf("exact host: got %q, want %q", got, "yes")
	}
	if got := exactHostValue("box.lab", "StrictHostKeyChecking"); got != "" {
		t.Errorf("wildcard-only block must not be treated as exact: got %q", got)
	}
	if got := exactHostValue("other", "StrictHostKeyChecking"); got != "" {
		t.Errorf("unmatched host: got %q, want empty", got)
	}
}

func TestSSHConfigValuePrecedenceForPortAndUser(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := "Host *\n  Port 2222\n  User everyone\n\nHost jarvis\n  Port 22\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sshConfigValue("jarvis", "Port"); got != "22" {
		t.Errorf("Port: got %q, want exact-host value 22", got)
	}
	if got := exactHostValue("jarvis", "User"); got != "" {
		t.Errorf("User: exact pass should not see wildcard value, got %q", got)
	}
}
