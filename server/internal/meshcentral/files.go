package meshcentral

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Files downloads MeshAgent binaries and device-group settings from
// MeshCentral's internal address, signed in as the service account
// (ADR-0015). MeshCentral refuses these downloads to anonymous visitors.
type Files struct {
	base string
	key  []byte
	http *http.Client
	now  func() time.Time

	mu       sync.Mutex
	cookies  []*http.Cookie
	signedAt time.Time
}

// ErrNoFile reports that MeshCentral has no such agent or group.
var ErrNoFile = errors.New("meshcentral: no such file")

// sessionReuse is how long a MeshCentral web session is reused before
// signing in again.
const sessionReuse = 10 * time.Minute

// NewFiles returns a downloader for the MeshCentral at baseURL (its internal
// http://127.0.0.1:port address).
func NewFiles(baseURL string, key []byte) (*Files, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return nil, fmt.Errorf("meshcentral: internal URL %q must be http://host:port", baseURL)
	}
	return &Files{
		base: strings.TrimSuffix(u.String(), "/"),
		key:  key,
		http: &http.Client{
			Timeout:       2 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		now: time.Now,
	}, nil
}

// Download is an open file from MeshCentral. Close it when done.
type Download struct {
	Body   io.ReadCloser
	Length int64 // -1 when unknown
}

// Agent opens the MeshAgent binary for a MeshCentral architecture number.
func (f *Files) Agent(ctx context.Context, arch int) (*Download, error) {
	return f.open(ctx, "/meshagents?id="+strconv.Itoa(arch))
}

// Settings returns the MeshAgent settings (.msh) that join a device group.
// MeshCentral 1.3.1 answers 401 for a group the account cannot see, which
// includes one that does not exist.
func (f *Files) Settings(ctx context.Context, meshID string) ([]byte, error) {
	id, ok := strings.CutPrefix(meshID, "mesh//")
	if !ok || id == "" {
		return nil, fmt.Errorf("meshcentral: %q is not a device group id", meshID)
	}
	d, err := f.open(ctx, "/meshsettings?id="+url.QueryEscape(id))
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(d.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("meshcentral: reading settings: %w", err)
	}
	if !strings.Contains(string(b), "MeshID=") {
		return nil, fmt.Errorf("meshcentral: the settings for %s hold no MeshID", meshID)
	}
	return b, nil
}

// open fetches path with a signed-in session, signing in again once if the
// cached session was refused.
func (f *Files) open(ctx context.Context, path string) (*Download, error) {
	for attempt := 0; ; attempt++ {
		cookies, err := f.session(ctx, attempt > 0)
		if err != nil {
			return nil, err
		}
		resp, err := f.get(ctx, path, cookies, "")
		if err != nil {
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return &Download{Body: resp.Body, Length: resp.ContentLength}, nil
		case resp.StatusCode == http.StatusNotFound:
			_ = resp.Body.Close()
			return nil, ErrNoFile
		case attempt == 0:
			_ = resp.Body.Close() // perhaps the session expired: sign in again
		default:
			_ = resp.Body.Close()
			return nil, fmt.Errorf("meshcentral: %s answered %d", strings.SplitN(path, "?", 2)[0], resp.StatusCode)
		}
	}
}

// session returns cookies of a MeshCentral web session for the service
// account.
func (f *Files) session(ctx context.Context, fresh bool) ([]*http.Cookie, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !fresh && f.cookies != nil && f.now().Sub(f.signedAt) < sessionReuse {
		return f.cookies, nil
	}
	token, err := LoginToken(f.key, UserID(ServiceAccount), f.now())
	if err != nil {
		return nil, err
	}
	resp, err := f.get(ctx, "/?login="+url.QueryEscape(token), nil, url.QueryEscape(token))
	if err != nil {
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return nil, fmt.Errorf("meshcentral: signing in as the service account failed (%d)", resp.StatusCode)
	}
	f.cookies, f.signedAt = cookies, f.now()
	return cookies, nil
}

// get requests path; secret, if any, is removed from errors.
func (f *Files) get(ctx context.Context, path string, cookies []*http.Cookie, secret string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.base+path, nil)
	if err != nil {
		return nil, err
	}
	// MeshCentral trusts the loopback proxy and marks its cookies Secure;
	// send them back by hand over the internal plain-HTTP connection.
	req.Header.Set("X-Forwarded-Proto", "https")
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // a request cookie; attributes do not apply
	}
	resp, err := f.http.Do(req)
	if err != nil {
		if secret != "" {
			err = redact(err, secret)
		}
		return nil, fmt.Errorf("meshcentral: %w", err)
	}
	return resp, nil
}
