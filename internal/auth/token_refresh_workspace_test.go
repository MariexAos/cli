// Copyright (c) 2026 Lark Technologies Pte. Ltd.
// SPDX-License-Identifier: MIT

package auth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/larksuite/cli/internal/core"
	"github.com/larksuite/cli/internal/keychain"
)

const (
	workspaceRefreshHelperEnv = "LARK_CLI_WORKSPACE_REFRESH_TEST_HELPER"
	workspaceRefreshServerEnv = "LARK_CLI_WORKSPACE_REFRESH_TEST_SERVER"
)

// seedSharedTestMasterKey gives every test process the same mocked macOS
// keychain master key so they can all decrypt one on-disk token store. Linux
// keeps its master key in the shared storage directory itself.
func seedSharedTestMasterKey(t testing.TB) {
	t.Helper()
	keyring.MockInit()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	if err := keyring.Set(keychain.LarkCliService, "master.key", key); err != nil {
		t.Fatalf("seed master key: %v", err)
	}
}

// TestWorkspaceRefreshHelperProcess is one lark-cli process refreshing the
// shared user token from the workspace selected by its environment.
func TestWorkspaceRefreshHelperProcess(t *testing.T) {
	if os.Getenv(workspaceRefreshHelperEnv) != "1" {
		return
	}
	seedSharedTestMasterKey(t)
	core.SetCurrentWorkspace(core.DetectWorkspaceFromEnv(os.Getenv))
	target, err := url.Parse(os.Getenv(workspaceRefreshServerEnv))
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		redirected := req.Clone(req.Context())
		redirected.URL.Scheme = target.Scheme
		redirected.URL.Host = target.Host
		redirected.Host = target.Host
		return http.DefaultTransport.RoundTrip(redirected)
	})}

	fmt.Fprintln(os.Stdout, "READY")
	var start [1]byte
	if _, err := io.ReadFull(os.Stdin, start[:]); err != nil {
		t.Fatalf("wait for start: %v", err)
	}
	stored := newRefreshTestToken()
	opts := newRefreshTestOptions(stored)
	opts.ErrOut = os.Stderr
	result, err := GetValidAccessToken(context.Background(), client, opts)
	if err != nil {
		fmt.Fprintf(os.Stdout, "ERR %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
		return
	}
	fmt.Fprintf(os.Stdout, "OK %s\n", result.AccessToken)
}

// TestGetValidAccessTokenSerializesRefreshAcrossWorkspaces reproduces a local
// workspace and a bot-driven workspace on one machine refreshing the same
// shared token after it expires. The token endpoint enforces single-use
// refresh tokens, so any refresh that is not serialized with the first one is
// rejected and clears the shared token.
func TestGetValidAccessTokenSerializesRefreshAcrossWorkspaces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows token storage is the real per-user registry; this test needs a temporary shared store")
	}
	setupStoredTokenTest(t)
	seedSharedTestMasterKey(t)
	stored := newRefreshTestToken()
	if err := SetStoredToken(stored); err != nil {
		t.Fatalf("SetStoredToken() error = %v", err)
	}

	var (
		mu             sync.Mutex
		currentRefresh = stored.RefreshToken
		requests       atomic.Int32
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var payload refreshRequest
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		valid := payload.RefreshToken == currentRefresh
		if valid {
			currentRefresh = "refresh-new"
		}
		mu.Unlock()
		if !valid {
			fmt.Fprint(w, `{"code":20073,"error_description":"The refresh token has been used. Please note that a refresh token can only be used once."}`)
			return
		}
		// Keep the rotation in flight so a refresh that is not serialized
		// with this one overlaps it deterministically.
		time.Sleep(500 * time.Millisecond)
		fmt.Fprint(w, `{"code":0,"access_token":"access-new","refresh_token":"refresh-new","expires_in":7200,"refresh_token_expires_in":86400}`)
	}))
	defer server.Close()

	baseEnv := make([]string, 0, len(os.Environ())+2)
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "OPENCLAW_") || strings.HasPrefix(entry, "HERMES_") || strings.HasPrefix(entry, "LARK_CHANNEL=") {
			continue
		}
		baseEnv = append(baseEnv, entry)
	}
	baseEnv = append(baseEnv, workspaceRefreshHelperEnv+"=1", workspaceRefreshServerEnv+"="+server.URL)

	type helper struct {
		workspace core.Workspace
		command   *exec.Cmd
		stdin     io.WriteCloser
		lines     *bufio.Scanner
		stderr    *bytes.Buffer
	}
	// The last helper also uses its own config directory: only the shared
	// token storage, not the CLI config location, may decide the lock.
	cases := []struct {
		workspace core.Workspace
		env       []string
	}{
		{workspace: core.WorkspaceLocal},
		{workspace: core.WorkspaceLarkChannel, env: []string{"LARK_CHANNEL=1"}},
		{workspace: core.WorkspaceLocal},
		{workspace: core.WorkspaceLarkChannel, env: []string{"LARK_CHANNEL=1", "LARKSUITE_CLI_CONFIG_DIR=" + t.TempDir()}},
	}
	helpers := make([]*helper, 0, len(cases))
	for _, tc := range cases {
		workspace := tc.workspace
		command := exec.Command(os.Args[0], "-test.run=^TestWorkspaceRefreshHelperProcess$")
		command.Env = append(append([]string(nil), baseEnv...), tc.env...)
		stdin, err := command.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe() error = %v", err)
		}
		stdout, err := command.StdoutPipe()
		if err != nil {
			t.Fatalf("StdoutPipe() error = %v", err)
		}
		h := &helper{workspace: workspace, command: command, stdin: stdin, lines: bufio.NewScanner(stdout), stderr: &bytes.Buffer{}}
		command.Stderr = h.stderr
		if err := command.Start(); err != nil {
			t.Fatalf("start helper process: %v", err)
		}
		t.Cleanup(func() {
			_ = stdin.Close()
			_ = command.Process.Kill()
			_ = command.Wait()
		})
		helpers = append(helpers, h)
	}

	readLine := func(h *helper) string {
		line := make(chan string, 1)
		go func() {
			if h.lines.Scan() {
				line <- h.lines.Text()
				return
			}
			line <- ""
		}()
		select {
		case got := <-line:
			return got
		case <-time.After(30 * time.Second):
			t.Fatalf("timed out waiting for %s helper; stderr=%s", h.workspace.Display(), h.stderr.String())
			return ""
		}
	}
	for _, h := range helpers {
		if got := readLine(h); got != "READY" {
			t.Fatalf("%s helper readiness = %q; stderr=%s", h.workspace.Display(), got, h.stderr.String())
		}
	}
	for _, h := range helpers {
		if _, err := io.WriteString(h.stdin, "x"); err != nil {
			t.Fatalf("start %s helper: %v", h.workspace.Display(), err)
		}
	}
	for _, h := range helpers {
		if got := readLine(h); got != "OK access-new" {
			t.Errorf("%s helper result = %q, want the single refreshed token; stderr=%s", h.workspace.Display(), got, h.stderr.String())
		}
	}

	if got := requests.Load(); got != 1 {
		t.Errorf("refresh requests = %d, want exactly 1 shared by every workspace", got)
	}
	current, err := GetStoredToken(stored.AppId, stored.UserOpenId)
	if err != nil {
		t.Fatalf("GetStoredToken() error = %v", err)
	}
	if current == nil {
		t.Fatal("stored token was deleted by a concurrent refresh from another workspace")
	}
	if current.RefreshToken != "refresh-new" || current.AccessToken != "access-new" {
		t.Fatalf("stored token = (%q, %q), want refreshed generation", current.AccessToken, current.RefreshToken)
	}
}
