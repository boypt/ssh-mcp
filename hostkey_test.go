package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func newTestPublicKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}
	return key
}

var testRemote = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}

func TestBuildHostKeyCallbackStrictRejectsUnknownHost(t *testing.T) {
	hc := HostConfig{StrictHostKeyChecking: "ask", KnownHostsFiles: []string{filepath.Join(t.TempDir(), "known_hosts")}}
	cb, err := buildHostKeyCallback(hc)
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}

	err = cb("10.0.0.1:22", testRemote, newTestPublicKey(t))
	if err == nil || !strings.Contains(err.Error(), "not in known_hosts") {
		t.Fatalf("expected unknown host error, got: %v", err)
	}
}

func TestBuildHostKeyCallbackStrictAcceptsKnownKey(t *testing.T) {
	key := newTestPublicKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"10.0.0.1"}, key) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cb, err := buildHostKeyCallback(HostConfig{StrictHostKeyChecking: "yes", KnownHostsFiles: []string{path}})
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}
	if err := cb("10.0.0.1:22", testRemote, key); err != nil {
		t.Fatalf("expected known key to be accepted, got: %v", err)
	}
}

func TestBuildHostKeyCallbackRejectsChangedKey(t *testing.T) {
	oldKey := newTestPublicKey(t)
	newKey := newTestPublicKey(t)
	path := filepath.Join(t.TempDir(), "known_hosts")
	line := knownhosts.Line([]string{"10.0.0.1"}, oldKey) + "\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	for _, mode := range []string{"yes", "accept-new"} {
		cb, err := buildHostKeyCallback(HostConfig{StrictHostKeyChecking: mode, KnownHostsFiles: []string{path}})
		if err != nil {
			t.Fatalf("buildHostKeyCallback(%s): %v", mode, err)
		}
		err = cb("10.0.0.1:22", testRemote, newKey)
		if err == nil || !strings.Contains(err.Error(), "changed") {
			t.Fatalf("mode %s: expected changed key error, got: %v", mode, err)
		}
	}
}

func TestBuildHostKeyCallbackAcceptNewRecordsUnknownHost(t *testing.T) {
	key := newTestPublicKey(t)
	dir := filepath.Join(t.TempDir(), "nested")
	path := filepath.Join(dir, "known_hosts")

	cb, err := buildHostKeyCallback(HostConfig{StrictHostKeyChecking: "accept-new", KnownHostsFiles: []string{path}})
	if err != nil {
		t.Fatalf("buildHostKeyCallback: %v", err)
	}
	if err := cb("10.0.0.2:22", testRemote, key); err != nil {
		t.Fatalf("expected unknown host to be accepted, got: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known_hosts: %v", err)
	}
	if !strings.HasPrefix(string(data), "10.0.0.2 ") {
		t.Fatalf("expected recorded entry for 10.0.0.2, got: %q", data)
	}

	cb, err = buildHostKeyCallback(HostConfig{StrictHostKeyChecking: "accept-new", KnownHostsFiles: []string{path}})
	if err != nil {
		t.Fatalf("buildHostKeyCallback reload: %v", err)
	}
	if err := cb("10.0.0.2:22", testRemote, key); err != nil {
		t.Fatalf("expected recorded key to be accepted on reconnect, got: %v", err)
	}
}

func TestBuildHostKeyCallbackNoAcceptsAnyKey(t *testing.T) {
	for _, mode := range []string{"no", "off"} {
		cb, err := buildHostKeyCallback(HostConfig{StrictHostKeyChecking: mode})
		if err != nil {
			t.Fatalf("buildHostKeyCallback(%s): %v", mode, err)
		}
		if err := cb("10.0.0.3:22", testRemote, newTestPublicKey(t)); err != nil {
			t.Fatalf("mode %s: expected any key accepted, got: %v", mode, err)
		}
	}
}

func TestExpandKnownHostsFiles(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	got := expandKnownHostsFiles("~/.ssh/known_hosts none /tmp/extra")
	want := []string{filepath.Join(home, ".ssh", "known_hosts"), "/tmp/extra"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestResolveHostConfigKnownHostsDefault(t *testing.T) {
	hc := resolveHostConfig("some-random-host-xyz")
	if len(hc.KnownHostsFiles) == 0 {
		t.Fatal("expected default UserKnownHostsFile entries")
	}
}

func TestIsAllowedNilAllowlistIsUnrestricted(t *testing.T) {
	mgr := NewSSHManager(nil)
	if mgr.hasAllowlist() {
		t.Fatal("nil allowlist should not report an allowlist")
	}
	if !mgr.isAllowed("anything") {
		t.Fatal("nil allowlist should allow any alias")
	}

	mgr = NewSSHManager([]string{})
	if !mgr.hasAllowlist() {
		t.Fatal("empty allowlist should report an allowlist")
	}
	if mgr.isAllowed("anything") {
		t.Fatal("empty allowlist should allow no alias")
	}
}

func TestConnectReusesActiveSession(t *testing.T) {
	mgr := NewSSHManager(nil)
	mgr.sessions["s1"] = &SSHSession{id: "s1", alias: "reuse-host-xyz", manager: mgr, active: true}

	id, err := mgr.ConnectWithSize("reuse-host-xyz", 80, 24)
	if err != nil {
		t.Fatalf("expected existing session to be reused, got error: %v", err)
	}
	if id != "s1" {
		t.Fatalf("expected reused session s1, got %s", id)
	}
	if len(mgr.sessions) != 1 {
		t.Fatalf("expected no new session, have %d", len(mgr.sessions))
	}
}
