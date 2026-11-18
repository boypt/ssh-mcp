package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool names exposed to MCP clients.
const (
	toolConnect      = "ssh_connect"
	toolExec         = "ssh_exec"
	toolSendCommand  = "ssh_send_command"
	toolSendKeys     = "ssh_send_keys"
	toolGetScreen    = "ssh_get_screen"
	toolClearScreen  = "ssh_clear_screen"
	toolResize       = "ssh_resize"
	toolListSessions = "ssh_list_sessions"
	toolListHosts    = "ssh_list_hosts"
	toolReadFile     = "ssh_read_file"
	toolWriteFile    = "ssh_write_file"
	toolEditFile     = "ssh_edit_file"
	toolUpload       = "ssh_upload"
	toolDownload     = "ssh_download"
	toolCloseSession = "ssh_close_session"
)

type connectArgs struct {
	Host   string `json:"host" jsonschema:"Alias, hostname, or IP. May be [user@]host[:port]; bracket IPv6 when giving a port."`
	User   string `json:"user,omitempty" jsonschema:"Login user. Overrides host's user and ~/.ssh/config."`
	Port   int    `json:"port,omitempty" jsonschema:"SSH port. Overrides host's port and ~/.ssh/config. Default 22."`
	Width  int    `json:"width,omitempty" jsonschema:"Initial terminal columns. Default 200."`
	Height int    `json:"height,omitempty" jsonschema:"Initial terminal rows. Default 50."`
}

type sessionArgs struct {
	SessionID string `json:"session_id" jsonschema:"SSH session ID"`
}

type commandArgs struct {
	SessionID string `json:"session_id" jsonschema:"SSH session ID"`
	Command   string `json:"command" jsonschema:"Command line to send. A newline is appended. Non-blocking; see the tool description."`
}

type execArgs struct {
	SessionID string `json:"session_id" jsonschema:"SSH session ID"`
	Command   string `json:"command" jsonschema:"A single shell command line to run and wait for. Must NOT contain newlines (use ssh_send_command for multi-line/heredoc input). Runs in the same persistent shell as ssh_send_command, so cwd and environment from earlier commands carry over."`
	TimeoutMs int    `json:"timeout_ms,omitempty" jsonschema:"How long to wait for completion before returning with the command still running. Defaults to 60000ms. Maximum 600000ms (10m)."`
}

type sendKeysArgs struct {
	SessionID string `json:"session_id" jsonschema:"SSH session ID"`
	Keys      string `json:"keys" jsonschema:"Raw bytes to write to the shell with NO trailing newline. Use for control characters and TUI navigation: Ctrl-C is \"\\u0003\", Ctrl-D \"\\u0004\", Escape \"\\u001b\", Enter \"\\r\". To run a command line, use ssh_exec or ssh_send_command instead."`
}

type resizeArgs struct {
	SessionID string `json:"session_id" jsonschema:"SSH session ID"`
	Width     int    `json:"width" jsonschema:"New terminal width in columns. Clamped to [20, 500]."`
	Height    int    `json:"height" jsonschema:"New terminal height in rows. Clamped to [5, 200]."`
}

type readFileArgs struct {
	SessionID  string `json:"session_id" jsonschema:"SSH session ID"`
	RemotePath string `json:"remote_path" jsonschema:"Absolute path of the remote file to read"`
	Offset     int64  `json:"offset,omitempty" jsonschema:"Byte offset to start reading from. Defaults to 0. Use with length to page through large files."`
	Length     int64  `json:"length,omitempty" jsonschema:"Maximum bytes to return. Defaults to and is capped at 262144 (256KiB). If the file has more data beyond what is returned, the response notes it was truncated."`
}

type writeFileArgs struct {
	SessionID  string `json:"session_id" jsonschema:"SSH session ID"`
	RemotePath string `json:"remote_path" jsonschema:"Absolute path of the remote file to write. Parent directories are created as needed; an existing file is overwritten."`
	Content    string `json:"content" jsonschema:"Exact content to write to the file"`
}

type editFileArgs struct {
	SessionID  string `json:"session_id" jsonschema:"SSH session ID"`
	RemotePath string `json:"remote_path" jsonschema:"Absolute path of the remote file to modify"`
	OldString  string `json:"old_string" jsonschema:"The text to replace. Leave empty to create a new file with new_string as its content (the file must not already exist)."`
	NewString  string `json:"new_string" jsonschema:"The text to replace it with. Leave empty to delete old_string from the file."`
	ReplaceAll bool   `json:"replace_all,omitempty" jsonschema:"Replace all occurrences of old_string (default false)."`
}

type uploadArgs struct {
	SessionID  string `json:"session_id" jsonschema:"SSH session ID"`
	LocalPath  string `json:"local_path" jsonschema:"Local file or directory path to upload"`
	RemotePath string `json:"remote_path" jsonschema:"Destination path on the remote host"`
}

type downloadArgs struct {
	SessionID  string `json:"session_id" jsonschema:"SSH session ID"`
	RemotePath string `json:"remote_path" jsonschema:"Remote file or directory path to download"`
	LocalPath  string `json:"local_path" jsonschema:"Destination path on the local host"`
}

// textResult builds a successful CallToolResult containing only the given
// text.
func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

// errorResult builds an error CallToolResult with the IsError flag set so the
// MCP client can distinguish failures from regular output.
func errorResult(format string, args ...any) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf(format, args...)}},
		IsError: true,
	}
}

// registerTools wires every MCP tool exposed by the server onto the manager.
func registerTools(server *mcp.Server, mgr *SSHManager) {
	mcp.AddTool(server, &mcp.Tool{
		Name: toolConnect,
		Description: "Connect to an SSH host by alias from ~/.ssh/config, or directly by hostname/IP. " +
			"Reuses a live session to the same user@host:port. " +
			"If the host key is unknown, the result includes a WARNING to relay to the user; " +
			"a changed key is rejected.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args connectArgs) (*mcp.CallToolResult, any, error) {
		opts := ConnectOptions{Host: args.Host, User: args.User, Width: args.Width, Height: args.Height}
		if args.Port != 0 {
			opts.Port = strconv.Itoa(args.Port)
		}
		sessionID, warnings, err := mgr.connect(opts)
		if err != nil {
			return errorResult("Failed to connect: %v", err), nil, nil
		}
		text := fmt.Sprintf("Connected successfully. Session ID: %s", sessionID)
		for _, w := range warnings {
			text += "\n\n" + w
		}
		return textResult(text), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolExec,
		Description: "Run one shell command and block until it finishes or timeout_ms elapses. " +
			"Returns the clean output and exit code. Runs in the same persistent shell as " +
			"ssh_send_command, so cwd and environment carry over. On timeout the command is NOT " +
			"killed: the result shows completed=false and the screen; poll with ssh_get_screen, " +
			"interrupt with ssh_send_keys (Ctrl-C), or wait. Do not use it for full-screen " +
			"programs (vim, less, htop, REPLs); use ssh_send_command and ssh_send_keys instead.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args execArgs) (*mcp.CallToolResult, any, error) {
		timeout := time.Duration(args.TimeoutMs) * time.Millisecond
		res, err := mgr.Exec(args.SessionID, args.Command, timeout)
		if err != nil {
			return errorResult("Failed to exec: %v", err), nil, nil
		}
		if !res.Completed {
			return textResult(fmt.Sprintf(
				"Command did not complete within %s and is STILL RUNNING in the shell. "+
					"It was not killed. Poll with ssh_get_screen, interrupt with ssh_send_keys "+
					"(Ctrl-C = \"\\u0003\"), or call ssh_exec again with a larger timeout_ms.\n\n"+
					"Current screen:\n%s",
				res.Duration.Round(time.Millisecond), res.Screen)), nil, nil
		}
		return textResult(fmt.Sprintf("exit_code=%d duration=%s\n%s",
			res.ExitCode, res.Duration.Round(time.Millisecond), res.Output)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolSendCommand,
		Description: "Send a command line to an SSH session without waiting for it to finish, then " +
			"return the screen after a short settle (~3.5s). Use it for interactive programs (vim, " +
			"htop, tmux, REPLs) and fire-and-forget launches. Prefer ssh_exec for commands that should " +
			"finish. To wait for a result, poll with ssh_get_screen until the prompt returns. " +
			"Do not send another command while one is still running.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args commandArgs) (*mcp.CallToolResult, any, error) {
		screen, err := mgr.SendCommand(args.SessionID, args.Command)
		if err != nil {
			return errorResult("Failed to send command: %v", err), nil, nil
		}
		return textResult(screen), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolSendKeys,
		Description: "Send raw bytes to the shell's stdin with NO trailing newline. " +
			"Use this for control characters and TUI navigation that ssh_send_command (which always " +
			"appends a newline) cannot express: interrupt a running command with Ctrl-C (\"\\u0003\"), " +
			"send EOF with Ctrl-D (\"\\u0004\"), press Escape (\"\\u001b\"), arrow keys, or a bare " +
			"Enter (\"\\r\"). To execute a command line, use ssh_exec or ssh_send_command instead. " +
			"After sending keys, read the result with ssh_get_screen.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args sendKeysArgs) (*mcp.CallToolResult, any, error) {
		if err := mgr.SendKeys(args.SessionID, args.Keys); err != nil {
			return errorResult("Failed to send keys: %v", err), nil, nil
		}
		return textResult("Keys sent"), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolGetScreen,
		Description: "Get the rendered screen of an SSH session. Use it to poll output after " +
			"ssh_send_command: wait on your side, then call it again until the prompt or expected " +
			"output appears. Waits ~2.5s before rendering, so polls are naturally spaced.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args sessionArgs) (*mcp.CallToolResult, any, error) {
		screen, err := mgr.GetScreen(args.SessionID)
		if err != nil {
			return errorResult("Failed to get screen: %v", err), nil, nil
		}
		return textResult(screen), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolClearScreen,
		Description: "Clear the LOCAL terminal emulator's screen and scrollback for a session. " +
			"This resets what ssh_get_screen / ssh_send_command will show, giving you a clean slate " +
			"when accumulated scrollback makes output hard to read. It does NOT send anything to the " +
			"remote shell (no `clear` command, no escape sequences to the host) and does not affect " +
			"the running shell's state -- only the local rendering buffer is reset.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args sessionArgs) (*mcp.CallToolResult, any, error) {
		if err := mgr.ClearScreen(args.SessionID); err != nil {
			return errorResult("Failed to clear screen: %v", err), nil, nil
		}
		return textResult("Screen cleared"), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        toolResize,
		Description: "Resize the terminal for an existing SSH session. Sends SIGWINCH to the remote shell so full-screen apps redraw at the new size. Width is clamped to [20, 500] columns and height to [5, 200] rows.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args resizeArgs) (*mcp.CallToolResult, any, error) {
		w, h, err := mgr.Resize(args.SessionID, args.Width, args.Height)
		if err != nil {
			return errorResult("Failed to resize: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("Resized session to %dx%d", w, h)), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolListSessions,
		Description: "List every SSH session this server knows about, along with its current state. " +
			"Each entry is rendered as `[active|inactive] <session_id> (<width>x<height>)`. " +
			"Only sessions reported as `active` accept ssh_send_command / ssh_get_screen / ssh_resize calls; " +
			"`inactive` entries are dead remotes pending automatic reap and will return ErrSessionInactive if you try to use them.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
		sessions := mgr.ListSessions()
		if len(sessions) == 0 {
			return textResult("No SSH sessions"), nil, nil
		}
		lines := make([]string, 0, len(sessions))
		for _, s := range sessions {
			state := "active"
			if !s.Active {
				state = "inactive"
			}
			lines = append(lines, fmt.Sprintf("[%s] %s (%dx%d)", state, s.ID, s.Width, s.Height))
		}
		return textResult("SSH sessions:\n" + strings.Join(lines, "\n")), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolListHosts,
		Description: "List allowed SSH hosts with resolved connection details. " +
			"When no allowlist is configured, any alias from ~/.ssh/config can be connected.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
		if !mgr.hasAllowlist() {
			return textResult("No allowlist configured: any host alias from ~/.ssh/config can be connected."), nil, nil
		}
		hosts := mgr.ListHosts()
		if len(hosts) == 0 {
			return textResult("No configured hosts"), nil, nil
		}
		return textResult("Available hosts:\n" + strings.Join(hosts, "\n")), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolReadFile,
		Description: "Read a remote file directly over SFTP and return its content as text. " +
			"Prefer this over `cat`-ing through the shell: it returns the exact file bytes with no " +
			"prompt, ANSI, or terminal-wrapping noise, and does not disturb the interactive session. " +
			"Returns up to 256KiB; use offset/length to page through larger files. The response notes " +
			"when output was truncated.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args readFileArgs) (*mcp.CallToolResult, any, error) {
		content, truncated, err := mgr.ReadFile(args.SessionID, args.RemotePath, args.Offset, args.Length)
		if err != nil {
			return errorResult("Failed to read file: %v", err), nil, nil
		}
		if truncated {
			return textResult(content + "\n\n[truncated: more data available; re-read with a larger offset]"), nil, nil
		}
		return textResult(content), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolWriteFile,
		Description: "Write content to a remote file directly over SFTP, creating parent directories " +
			"as needed and overwriting any existing file. Prefer this over here-docs / `echo >` through " +
			"the shell: it writes exact bytes with no quoting or escaping pitfalls and does not disturb " +
			"the interactive session.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args writeFileArgs) (*mcp.CallToolResult, any, error) {
		result, err := mgr.WriteFile(args.SessionID, args.RemotePath, args.Content)
		if err != nil {
			return errorResult("Failed to write file: %v", err), nil, nil
		}
		return textResult(result), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name: toolEditFile,
		Description: "Edit a remote file over SFTP by exact find-and-replace of old_string with " +
			"new_string. Empty old_string creates a file (it must not exist); empty new_string deletes " +
			"old_string. old_string must match exactly and be unique unless replace_all is true. " +
			"You must read the file with ssh_read_file first; the edit is refused if the file changed " +
			"on the remote since. For whole-file rewrites use ssh_write_file.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args editFileArgs) (*mcp.CallToolResult, any, error) {
		result, err := mgr.EditFile(args.SessionID, args.RemotePath, args.OldString, args.NewString, args.ReplaceAll)
		if err != nil {
			// Match-failure and guard messages are returned verbatim (no
			// "Failed to edit:" prefix) so they read exactly like the editor.
			return errorResult("%s", err.Error()), nil, nil
		}
		return textResult(result), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        toolUpload,
		Description: "Upload a local file or directory to a remote host via SFTP (recursive for directories)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args uploadArgs) (*mcp.CallToolResult, any, error) {
		result, err := mgr.Upload(args.SessionID, args.LocalPath, args.RemotePath)
		if err != nil {
			return errorResult("Failed to upload: %v", err), nil, nil
		}
		return textResult(result), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        toolDownload,
		Description: "Download a remote file or directory from a remote host via SFTP (recursive for directories)",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args downloadArgs) (*mcp.CallToolResult, any, error) {
		result, err := mgr.Download(args.SessionID, args.RemotePath, args.LocalPath)
		if err != nil {
			return errorResult("Failed to download: %v", err), nil, nil
		}
		return textResult(result), nil, nil
	})

	mcp.AddTool(server, &mcp.Tool{
		Name:        toolCloseSession,
		Description: "Close an SSH session",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args sessionArgs) (*mcp.CallToolResult, any, error) {
		if err := mgr.CloseSession(args.SessionID); err != nil {
			return errorResult("Failed to close session: %v", err), nil, nil
		}
		return textResult(fmt.Sprintf("Session %s closed successfully", args.SessionID)), nil, nil
	})
}
