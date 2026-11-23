package meshcentral

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// meshTypeAgent is a device group of devices running MeshAgent.
const meshTypeAgent = 2

// Link is a user's (or group's) rights on a device group, or a user's
// membership of a group, as MeshCentral stores it.
type Link struct {
	Name   string `json:"name"`
	Rights uint32 `json:"rights"`
}

// Mesh is a MeshCentral device group.
type Mesh struct {
	ID          string          `json:"_id"`
	Name        string          `json:"name"`
	Description string          `json:"desc"`
	Type        int             `json:"mtype"`
	Links       map[string]Link `json:"links"`
}

// User is a MeshCentral account.
type User struct {
	ID        string          `json:"_id"`
	Name      string          `json:"name"`
	RealName  string          `json:"realname"`
	SiteAdmin uint32          `json:"siteadmin"`
	Links     map[string]Link `json:"links"`
}

// AgentInfo describes the MeshAgent on a device.
type AgentInfo struct {
	// Type is MeshCentral's agent architecture number (4 = Windows x64,
	// 6 = Linux x64, …).
	Type    int    `json:"id"`
	Version int    `json:"ver"`
	Caps    int    `json:"caps"`
	Tag     string `json:"tag"`
}

// Node is a device known to MeshCentral.
type Node struct {
	ID     string    `json:"_id"`
	MeshID string    `json:"-"`
	Name   string    `json:"name"`
	Host   string    `json:"host"`
	OSDesc string    `json:"osdesc"`
	Agent  AgentInfo `json:"agent"`
	Conn   int       `json:"conn"`
	IP     string    `json:"ip"`
	OSName string    `json:"rname"`
}

// AgentConnected reports whether the device's agent is connected right now.
func (n Node) AgentConnected() bool { return n.Conn&1 != 0 }

// Meshes lists the device groups the service account belongs to.
func (c *Client) Meshes(ctx context.Context) ([]Mesh, error) {
	r, err := c.call(ctx, "meshes", nil)
	if err != nil {
		return nil, err
	}
	var out []Mesh
	if err := json.Unmarshal(r["meshes"], &out); err != nil {
		return nil, fmt.Errorf("meshcentral: meshes: %w", err)
	}
	return out, nil
}

// CreateMesh creates an agent device group and returns its id.
func (c *Client) CreateMesh(ctx context.Context, name, desc string) (string, error) {
	r, err := c.call(ctx, "createmesh", map[string]any{"meshname": name, "meshtype": meshTypeAgent, "desc": desc})
	if err != nil {
		return "", err
	}
	id := str(r["meshid"])
	if id == "" {
		return "", fmt.Errorf("meshcentral: createmesh returned no id")
	}
	return id, nil
}

// EditMesh renames a device group and sets its description.
func (c *Client) EditMesh(ctx context.Context, meshID, name, desc string) error {
	_, err := c.call(ctx, "editmesh", map[string]any{"meshid": meshID, "meshname": name, "desc": desc})
	return err
}

// DeleteMesh deletes a device group and every device in it.
func (c *Client) DeleteMesh(ctx context.Context, meshID string) error {
	_, err := c.call(ctx, "deletemesh", map[string]any{"meshid": meshID})
	return err
}

// Users lists every account.
func (c *Client) Users(ctx context.Context) ([]User, error) {
	r, err := c.call(ctx, "users", nil)
	if err != nil {
		return nil, err
	}
	var out []User
	if err := json.Unmarshal(r["users"], &out); err != nil {
		return nil, fmt.Errorf("meshcentral: users: %w", err)
	}
	return out, nil
}

// AddUser creates an account with a random password nobody learns and the
// given server rights.
func (c *Client) AddUser(ctx context.Context, name, realName string, siteRights uint32) error {
	_, err := c.call(ctx, "adduser", map[string]any{
		"username": name, "realname": realName, "randomPassword": true, "siteadmin": siteRights,
	})
	return err
}

// EditUser sets an account's real name and server rights.
func (c *Client) EditUser(ctx context.Context, userID, realName string, siteRights uint32) error {
	_, err := c.call(ctx, "edituser", map[string]any{"userid": userID, "realname": realName, "siteadmin": siteRights})
	return err
}

// DeleteUser deletes an account. MeshCentral closes its open sessions.
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	_, err := c.call(ctx, "deleteuser", map[string]any{"userid": userID})
	return err
}

// SetMeshRights gives a user exactly these rights on a device group.
func (c *Client) SetMeshRights(ctx context.Context, meshID, userID string, rights uint32) error {
	// addmeshuser reports a summary ("Added user …") instead of "ok", with
	// success and failure counts.
	r, err := c.call(ctx, "addmeshuser", map[string]any{"meshid": meshID, "userids": []string{userID}, "meshadmin": rights})
	var ce *CommandError
	if err != nil && (!errors.As(err, &ce) || r == nil) {
		return err
	}
	var n struct {
		Success int `json:"success"`
	}
	if raw, ok := r["success"]; ok {
		_ = json.Unmarshal(raw, &n.Success)
	}
	if n.Success != 1 {
		return &CommandError{Action: "addmeshuser", Result: str(r["result"])}
	}
	return nil
}

// RemoveMeshUser takes a user's rights on a device group away.
func (c *Client) RemoveMeshUser(ctx context.Context, meshID, userID string) error {
	_, err := c.call(ctx, "removemeshuser", map[string]any{"meshid": meshID, "userid": userID})
	return err
}

// Nodes lists every device in the service account's device groups.
func (c *Client) Nodes(ctx context.Context) ([]Node, error) {
	r, err := c.call(ctx, "nodes", nil)
	if err != nil {
		return nil, err
	}
	var groups map[string][]Node
	if err := json.Unmarshal(r["nodes"], &groups); err != nil {
		return nil, fmt.Errorf("meshcentral: nodes: %w", err)
	}
	var out []Node
	for meshID, nodes := range groups {
		for _, n := range nodes {
			n.MeshID = meshID
			out = append(out, n)
		}
	}
	return out, nil
}

// RemoveDevice deletes a device from MeshCentral, with its events and
// links, and disconnects its MeshAgent. A MeshAgent still installed creates
// the device again when it reconnects to its group.
func (c *Client) RemoveDevice(ctx context.Context, nodeID string) error {
	_, err := c.call(ctx, "removedevices", map[string]any{"nodeids": []string{nodeID}})
	return err
}

// MoveDevice moves a device to another device group (MeshCentral's
// changeDeviceMesh). The node keeps its identity, so its MeshAgent stays
// known; the agent's settings name the group it connects to, so they are
// rewritten as well (ADR-0069).
func (c *Client) MoveDevice(ctx context.Context, nodeID, meshID string) error {
	_, err := c.call(ctx, "changeDeviceMesh", map[string]any{"nodeids": []string{nodeID}, "meshid": meshID})
	return err
}

// UninstallAgent asks a device's MeshAgent to uninstall itself. MeshCentral
// passes it on only while MeshAgent is connected, and answers nothing.
func (c *Client) UninstallAgent(ctx context.Context, nodeID string) error {
	return c.send(ctx, "uninstallagent", map[string]any{"nodeids": []string{nodeID}})
}

// IsAlreadyExists reports MeshCentral's "already exists" failures, which a
// retried create may legitimately hit.
func IsAlreadyExists(err error) bool {
	var ce *CommandError
	return errors.As(err, &ce) && strings.Contains(strings.ToLower(ce.Result), "already exists")
}

// IsUnknown reports MeshCentral's failures for a missing user or group.
func IsUnknown(err error) bool {
	var ce *CommandError
	if !errors.As(err, &ce) {
		return false
	}
	r := strings.ToLower(ce.Result)
	return strings.Contains(r, "does not exist") || strings.Contains(r, "unknown")
}
