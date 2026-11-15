package meshcentral

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/paulmataruso/easyrm/internal/config"
)

type Client struct {
	cfg        config.MeshCentralConfig
	httpClient *http.Client
	authCookie string
}

func NewClient(cfg config.MeshCentralConfig) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *Client) baseURL() string {
	if c.cfg.InternalURL != "" {
		return c.cfg.InternalURL
	}
	return c.cfg.URL
}

func (c *Client) Authenticate(ctx context.Context) error {
	body := map[string]string{
		"action":   "login",
		"username": c.cfg.AdminUser,
		"password": c.cfg.AdminPassword,
	}
	data, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/api/login", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("meshcentral auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("meshcentral auth failed (%d): %s", resp.StatusCode, string(body))
	}

	for _, cookie := range resp.Cookies() {
		if cookie.Name == "xid" || cookie.Name == "xid.sig" {
			if c.authCookie != "" {
				c.authCookie += "; "
			}
			c.authCookie += cookie.String()
		}
	}

	return nil
}

func (c *Client) GenerateLoginToken(ctx context.Context, username string, durationMinutes int) (string, error) {
	params := url.Values{}
	params.Set("user", username)
	params.Set("expire", fmt.Sprintf("%d", durationMinutes))
	params.Set("tokenkey", c.cfg.LoginTokenKey)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		c.baseURL()+"/api/logintoken?"+params.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Cookie", c.authCookie)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("meshcentral token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("meshcentral token failed (%d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	return result.Token, nil
}

type DeviceGroup struct {
	ID   string `json:"_id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type MeshDevice struct {
	ID     string `json:"_id"`
	Name   string `json:"name"`
	Host   string `json:"host"`
	OS     string `json:"osdesc"`
	State  int    `json:"conn"`
	MeshID string `json:"meshid"`
}

func (c *Client) ListDeviceGroups(ctx context.Context) ([]DeviceGroup, error) {
	var result struct {
		MeshList []map[string]DeviceGroup `json:"meshList"`
	}
	if err := c.apiCall(ctx, "meshes", nil, &result); err != nil {
		return nil, err
	}

	var groups []DeviceGroup
	for _, m := range result.MeshList {
		for _, g := range m {
			groups = append(groups, g)
		}
	}
	return groups, nil
}

func (c *Client) ListDevices(ctx context.Context) ([]MeshDevice, error) {
	var result struct {
		Nodes []map[string][]MeshDevice `json:"nodes"`
	}
	if err := c.apiCall(ctx, "nodes", nil, &result); err != nil {
		return nil, err
	}

	var devices []MeshDevice
	for _, nodeMap := range result.Nodes {
		for _, devList := range nodeMap {
			devices = append(devices, devList...)
		}
	}
	return devices, nil
}

func (c *Client) CreateDeviceGroup(ctx context.Context, name, desc string) (*DeviceGroup, error) {
	body := map[string]string{
		"meshname": name,
		"meshdesc": desc,
		"meshtype": "2",
	}
	var result struct {
		MeshID string `json:"meshid"`
	}
	if err := c.apiCall(ctx, "createmesh", body, &result); err != nil {
		return nil, err
	}
	return &DeviceGroup{ID: result.MeshID, Name: name, Desc: desc}, nil
}

func (c *Client) GetDeviceConnectURL(meshNodeID string) string {
	return fmt.Sprintf("%s/?node=%s", c.cfg.URL, meshNodeID)
}

func (c *Client) apiCall(ctx context.Context, action string, params map[string]string, result any) error {
	reqBody := map[string]string{"action": action}
	for k, v := range params {
		reqBody[k] = v
	}
	data, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL()+"/api/"+action, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cookie", c.authCookie)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("meshcentral api %s: %w", action, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("meshcentral api %s failed (%d): %s", action, resp.StatusCode, string(body))
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("decode %s response: %w", action, err)
		}
	}
	return nil
}
