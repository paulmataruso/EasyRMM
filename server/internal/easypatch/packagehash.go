package easypatch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// The hash list of every file the server hands out (ADR-0070) reads the
// engine's agent packages: their list, and each package itself, which
// the engine serves to agents without a statement.

// packageTimeout bounds one package's download.
const packageTimeout = 5 * time.Minute

// PackageList lists the agent packages the engine hosts, for the hash list.
// It returns none when no engine is connected.
func (s *Service) PackageList(ctx context.Context) ([]AgentPackage, error) {
	_, cl, err := s.conn(ctx)
	if err != nil || cl == nil {
		return nil, err
	}
	return cl.AgentPackages(ctx)
}

// OpenPackage opens an agent package from the engine, as an agent would
// download it. Only the engine's agent package paths are opened.
func (s *Service) OpenPackage(ctx context.Context, p AgentPackage) (io.ReadCloser, error) {
	_, cl, err := s.conn(ctx)
	if err != nil {
		return nil, err
	}
	if cl == nil {
		return nil, errors.New("no patching engine is connected")
	}
	return cl.OpenPackage(ctx, p)
}

// OpenPackage opens an agent package the engine hosts.
func (c *Client) OpenPackage(ctx context.Context, p AgentPackage) (io.ReadCloser, error) {
	if !strings.HasPrefix(p.DownloadURL, "/downloads/agent/") || strings.Contains(p.DownloadURL, "..") || strings.ContainsAny(p.DownloadURL, "?#\\") {
		return nil, fmt.Errorf("%q is not an agent package path", p.DownloadURL)
	}
	u := *c.base
	u.Path += p.DownloadURL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	hc := &http.Client{Transport: c.http.Transport, Timeout: packageTimeout, CheckRedirect: c.http.CheckRedirect}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, &Error{Detail: "Cannot reach the patching engine: " + reachError(err)}
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &Error{Status: resp.StatusCode, Detail: "The patching engine did not serve the package"}
	}
	return resp.Body, nil
}
