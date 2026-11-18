package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// buildHostKeyCallback returns the host key policy for hc, following the
// StrictHostKeyChecking and UserKnownHostsFile options from ~/.ssh/config:
//
//   - "no" / "off": accept any host key.
//   - "yes": reject unknown and changed keys.
//   - "accept-new": record unknown hosts in known_hosts; reject changed keys.
//   - default ("ask" or unset): connect to unknown hosts and append a warning
//     to warnings so the caller can report it; reject changed keys.
//
// Changed keys are always rejected, since they may indicate a man-in-the-middle
// attack. Removing the old entry is left to the user.
func buildHostKeyCallback(hc HostConfig, warnings *[]string) (ssh.HostKeyCallback, error) {
	switch hc.StrictHostKeyChecking {
	case "no", "off":
		return ssh.InsecureIgnoreHostKey(), nil
	}

	policy := hc.StrictHostKeyChecking

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
			return changedKeyError(hostname, key, keyErr)
		}

		switch policy {
		case "yes":
			return fmt.Errorf("host key for %s is not in known_hosts (%s). Verify the fingerprint %s out of band, "+
				"then connect once with ssh to add it",
				knownhosts.Normalize(hostname), knownHostsDisplay(hc.KnownHostsFiles), ssh.FingerprintSHA256(key))
		case "accept-new":
			return appendKnownHost(hc.KnownHostsFiles, hostname, key)
		default:
			*warnings = append(*warnings, unknownHostWarning(hostname, key, hc.KnownHostsFiles))
			return nil
		}
	}, nil
}

// changedKeyError explains a host key mismatch and how the user can resolve it
// after confirming the change is legitimate.
func changedKeyError(hostname string, key ssh.PublicKey, keyErr *knownhosts.KeyError) error {
	known := keyErr.Want[0]
	host := knownhosts.Normalize(hostname)
	return fmt.Errorf("host key for %s has changed. This may be a man-in-the-middle attack, or the machine was reinstalled.\n"+
		"expected %s (%s line %d)\nreceived %s\n"+
		"If the machine was really replaced, confirm the new fingerprint with its owner, then remove the old entry: "+
		"ssh-keygen -R '%s' -f '%s'",
		host, ssh.FingerprintSHA256(known.Key), known.Filename, known.Line, ssh.FingerprintSHA256(key), host, known.Filename)
}

// unknownHostWarning describes a connection made to a host missing from
// known_hosts, without verifying its key.
func unknownHostWarning(hostname string, key ssh.PublicKey, files []string) string {
	return fmt.Sprintf("WARNING: host key for %s is not in known_hosts. Connected without verifying the host. "+
		"Fingerprint %s. Confirm it out of band, then add it to %s (for example by connecting once with ssh and accepting it).",
		knownhosts.Normalize(hostname), ssh.FingerprintSHA256(key), knownHostsDisplay(files))
}

// knownHostsDisplay names the known_hosts file used for new entries.
func knownHostsDisplay(files []string) string {
	if len(files) == 0 {
		return "known_hosts"
	}
	return files[0]
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
