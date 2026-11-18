package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	sshconfig "github.com/kevinburke/ssh_config"
	"github.com/taigrr/jety"
)

// HostConfig holds resolved SSH connection details for a host alias.
type HostConfig struct {
	Hostname              string
	Port                  string
	User                  string
	KeyPath               string
	Password              string
	StrictHostKeyChecking string
	KnownHostsFiles       []string
}

// resolveHostConfig looks up an alias in ~/.ssh/config and applies sane
// fallbacks for missing fields. The IdentityFile path is expanded so that
// tilde-prefixed paths work without manual handling.
func resolveHostConfig(alias string) HostConfig {
	hc := HostConfig{
		Hostname:              sshconfig.Get(alias, "HostName"),
		Port:                  sshconfig.Get(alias, "Port"),
		User:                  sshconfig.Get(alias, "User"),
		KeyPath:               sshconfig.Get(alias, "IdentityFile"),
		StrictHostKeyChecking: strings.ToLower(sshconfig.Get(alias, "StrictHostKeyChecking")),
		KnownHostsFiles:       expandKnownHostsFiles(sshconfig.Get(alias, "UserKnownHostsFile")),
	}

	if hc.Hostname == "" {
		hc.Hostname = alias
	}
	if hc.Port == "" {
		hc.Port = defaultPort
	}
	if hc.User == "" {
		hc.User = os.Getenv("USER")
	}

	hc.KeyPath = expandHome(hc.KeyPath)

	return hc
}

// endpoint identifies the resolved connection target. Sessions are reused per
// endpoint, so the same machine reached by alias or by IP shares one session.
func (hc HostConfig) endpoint() string {
	return hc.User + "@" + hc.Hostname + ":" + hc.Port
}

// parseTarget splits a connection target of the form [user@]host[:port] into
// its parts. IPv6 literals are bracketed when a port is given ([fe80::1]:22);
// a bare IPv6 address without a port is returned as the host. Empty user or
// port means none was given.
func parseTarget(target string) (user, host, port string, err error) {
	if i := strings.LastIndex(target, "@"); i >= 0 {
		user, target = target[:i], target[i+1:]
	}

	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		return user, target[1 : len(target)-1], "", nil
	}
	if strings.Count(target, ":") == 1 || strings.HasPrefix(target, "[") {
		host, port, err = net.SplitHostPort(target)
		if err != nil {
			return "", "", "", fmt.Errorf("invalid host %q: %w", target, err)
		}
		if port == "" {
			return "", "", "", fmt.Errorf("missing port in %q", target)
		}
		return user, host, port, nil
	}
	return user, target, "", nil
}

// expandHome replaces a leading "~/" with the user's home directory.
func expandHome(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

// expandKnownHostsFiles splits a UserKnownHostsFile value into paths, expanding
// "~/" and dropping the "none" sentinel, as OpenSSH does.
func expandKnownHostsFiles(value string) []string {
	var files []string
	for _, field := range strings.Fields(value) {
		if field == "none" {
			continue
		}
		files = append(files, expandHome(field))
	}
	return files
}

// loadAllowedHosts reads the "hosts" key from the active jety configuration
// and returns its string entries. Returns nil when the key is absent or not a
// list of strings.
func loadAllowedHosts() []string {
	raw := jety.Get("hosts")
	if raw == nil {
		return nil
	}

	slice, ok := raw.([]any)
	if !ok {
		return nil
	}

	hosts := make([]string, 0, len(slice))
	for _, val := range slice {
		if host, ok := val.(string); ok {
			hosts = append(hosts, host)
		}
	}

	return hosts
}
