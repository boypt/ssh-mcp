package main

import (
	"os"
	"path/filepath"
	"strings"

	sshconfig "github.com/kevinburke/ssh_config"
)

// sshConfigValue returns the value of key for alias from the ssh configuration,
// for any key (HostName, Port, User, IdentityFile, ...).
// A Host block that names alias exactly (no "*" or "?" in its patterns) takes
// precedence over wildcard blocks such as "Host *", whatever their position in
// ~/.ssh/config. Otherwise the general lookup applies, which honours wildcard
// blocks and system config. Returns "" when nothing sets the key.
func sshConfigValue(alias, key string) string {
	if value := exactHostValue(alias, key); value != "" {
		return value
	}
	return sshconfig.Get(alias, key)
}

// exactHostValue returns the first value for key in a ~/.ssh/config Host block
// whose patterns contain no wildcards and which matches alias. Returns "" when
// the file is missing, unparsable, or has no such value.
func exactHostValue(alias, key string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	f, err := os.Open(filepath.Join(home, ".ssh", "config"))
	if err != nil {
		return ""
	}
	defer f.Close()

	cfg, err := sshconfig.Decode(f)
	if err != nil {
		return ""
	}

	for _, host := range cfg.Hosts {
		if !exactHostBlock(host) || !host.Matches(alias) {
			continue
		}
		for _, node := range host.Nodes {
			if kv, ok := node.(*sshconfig.KV); ok && strings.EqualFold(kv.Key, key) {
				return kv.Value
			}
		}
	}
	return ""
}

// exactHostBlock reports whether every pattern of a Host block is a plain
// name, with no "*" or "?" wildcards.
func exactHostBlock(host *sshconfig.Host) bool {
	if len(host.Patterns) == 0 {
		return false
	}
	for _, p := range host.Patterns {
		if strings.ContainsAny(p.String(), "*?") {
			return false
		}
	}
	return true
}
