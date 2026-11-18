package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// buildHostKeyCallback returns the host key policy for hc, following the
// StrictHostKeyChecking and UserKnownHostsFile options from ~/.ssh/config:
//
//   - "no" / "off": accept any host key.
//   - "accept-new": accept and record unknown hosts; reject changed keys.
//   - anything else (default "ask"): reject unknown and changed keys. There is
//     no terminal to prompt on, so the error explains how to proceed.
func buildHostKeyCallback(hc HostConfig) (ssh.HostKeyCallback, error) {
	switch hc.StrictHostKeyChecking {
	case "no", "off":
		return ssh.InsecureIgnoreHostKey(), nil
	}

	acceptNew := hc.StrictHostKeyChecking == "accept-new"
	paths := strings.Join(hc.KnownHostsFiles, ", ")

	var existing []string
	for _, path := range hc.KnownHostsFiles {
		if _, err := os.Stat(path); err == nil {
			existing = append(existing, path)
		}
	}

	var check ssh.HostKeyCallback
	if len(existing) > 0 {
		cb, err := knownhosts.New(existing...)
		if err != nil {
			return nil, fmt.Errorf("failed to load known_hosts: %w", err)
		}
		check = cb
	} else {
		check = func(string, net.Addr, ssh.PublicKey) error {
			return &knownhosts.KeyError{}
		}
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := check(hostname, remote, key)
		if err == nil {
			return nil
		}

		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) {
			return err
		}

		if len(keyErr.Want) > 0 {
			return fmt.Errorf("host key for %s changed; possible man-in-the-middle, or the machine was replaced. "+
				"Check %s, remove the old entry, or set StrictHostKeyChecking no for this host", hostname, paths)
		}

		if !acceptNew {
			return fmt.Errorf("host key for %s is not in known_hosts (%s); connect once with ssh, "+
				"or set StrictHostKeyChecking accept-new for this host", hostname, paths)
		}

		return appendKnownHost(hc.KnownHostsFiles, hostname, key)
	}, nil
}

// appendKnownHost records key for hostname in the first configured known_hosts
// file, creating the file and its directory if needed.
func appendKnownHost(files []string, hostname string, key ssh.PublicKey) error {
	if len(files) == 0 {
		return fmt.Errorf("no writable known_hosts file configured for %s", hostname)
	}

	path := files[0]
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create %s: %w", filepath.Dir(path), err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}
	return nil
}
