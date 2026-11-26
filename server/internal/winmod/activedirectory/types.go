package activedirectory

import "time"

// PasswordPolicy is the domain's default password and lockout policy.
type PasswordPolicy struct {
	MinLength                 int  `json:"minLength"`
	Complexity                bool `json:"complexity"`
	HistoryCount              int  `json:"historyCount"`
	MaxAgeDays                *int `json:"maxAgeDays"`
	LockoutThreshold          int  `json:"lockoutThreshold"`
	LockoutDurationMinutes    int  `json:"lockoutDurationMinutes"`
	LockoutObservationMinutes int  `json:"lockoutObservationMinutes"`
}

// Status is active_directory.status's result: the domain and the controller
// the script ran on.
type Status struct {
	Domain            string         `json:"domain"`
	DomainSID         string         `json:"domainSid"`
	Forest            string         `json:"forest"`
	ForestRootSID     string         `json:"forestRootSid"`
	DomainMode        string         `json:"domainMode"`
	ForestMode        string         `json:"forestMode"`
	Controller        string         `json:"controller"`
	ReadOnly          bool           `json:"readOnly"`
	GlobalCatalog     bool           `json:"globalCatalog"`
	PDCEmulator       string         `json:"pdcEmulator"`
	RecycleBinEnabled bool           `json:"recycleBinEnabled"`
	PasswordPolicy    PasswordPolicy `json:"passwordPolicy"`
}

// OU is one child of an organizational unit or container in the tree.
type OU struct {
	DN                  string `json:"dn"`
	Name                string `json:"name"`
	Kind                string `json:"kind"`
	ProtectedFromDelete bool   `json:"protectedFromDelete"`
	// Writable is false under the Domain Controllers container.
	Writable bool `json:"writable"`
}

// OUTree is active_directory.ou_tree's result.
type OUTree struct {
	Parent string `json:"parent"`
	Items  []OU   `json:"items"`
}

// Protection says how the guard sees a target: none, service (a second
// confirmation) or protected (refused), with the reason.
type Protection struct {
	Level  string `json:"protection"`
	Reason string `json:"reason"`
}

// UserRow is a row of user_list.
type UserRow struct {
	ID              string `json:"id"`
	Sam             string `json:"sam"`
	Name            string `json:"name"`
	UPN             string `json:"upn"`
	Enabled         bool   `json:"enabled"`
	LockedOut       bool   `json:"lockedOut"`
	PasswordExpired bool   `json:"passwordExpired"`
	Protection
}

// UserPage is a page of user_list. Next is the cursor of the following page,
// null on the last.
type UserPage struct {
	Items     []UserRow `json:"items"`
	Next      *string   `json:"next"`
	Scanned   int       `json:"scanned"`
	DomainSID string    `json:"domainSid"`
}

// User is user_get's result (sensitive: personal fields).
type User struct {
	ID                   string     `json:"id"`
	Sam                  string     `json:"sam"`
	UPN                  string     `json:"upn"`
	Name                 string     `json:"name"`
	DisplayName          string     `json:"displayName"`
	GivenName            string     `json:"givenName"`
	Surname              string     `json:"surname"`
	Description          string     `json:"description"`
	Mail                 string     `json:"mail"`
	Telephone            string     `json:"telephone"`
	Title                string     `json:"title"`
	Department           string     `json:"department"`
	Company              string     `json:"company"`
	Office               string     `json:"office"`
	OU                   string     `json:"ou"`
	Enabled              bool       `json:"enabled"`
	LockedOut            bool       `json:"lockedOut"`
	PasswordExpired      bool       `json:"passwordExpired"`
	PasswordNeverExpires bool       `json:"passwordNeverExpires"`
	CannotChangePassword bool       `json:"cannotChangePassword"`
	PasswordLastSetAt    *time.Time `json:"passwordLastSetAt"`
	AccountExpiresAt     *time.Time `json:"accountExpiresAt"`
	CreatedAt            *time.Time `json:"createdAt"`
	LastLogonApproxAt    *time.Time `json:"lastLogonApproxAt"`
	Groups               []string   `json:"groups"`
	Protection
}

// GroupRow is a row of group_list.
type GroupRow struct {
	ID          string `json:"id"`
	Sam         string `json:"sam"`
	Name        string `json:"name"`
	Scope       string `json:"scope"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Protection
}

// GroupPage is a page of group_list.
type GroupPage struct {
	Items     []GroupRow `json:"items"`
	Next      *string    `json:"next"`
	Scanned   int        `json:"scanned"`
	DomainSID string     `json:"domainSid"`
}

// Member is a direct member of a group.
type Member struct {
	ID   string `json:"id"`
	Sam  string `json:"sam"`
	Name string `json:"name"`
	// Kind is user, computer, group, foreign or other.
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

// MemberPage is a page of group_members.
type MemberPage struct {
	Items []Member `json:"items"`
	Next  *string  `json:"next"`
	Total int      `json:"total"`
}

// Check is one finding of health_read: ok, warning, critical, unknown,
// not_applicable or could_not_run.
type Check struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

// Partner is a replication partner and when it last succeeded.
type Partner struct {
	Partner       string     `json:"partner"`
	LastSuccessAt *time.Time `json:"lastSuccessAt"`
	LastResult    int        `json:"lastResult"`
}

// Replication is what the directory says about its own replication.
type Replication struct {
	FailureCount    int        `json:"failureCount"`
	OldestFailureAt *time.Time `json:"oldestFailureAt"`
	Partners        []Partner  `json:"partners"`
}

// Health is health_read's result.
type Health struct {
	Controller  string      `json:"controller"`
	Domain      string      `json:"domain"`
	Checks      []Check     `json:"checks"`
	Replication Replication `json:"replication"`
}

// Done is the result of a change that has nothing to return.
type Done struct {
	Done bool `json:"done"`
}

// Changed lists the attributes user_set changed.
type Changed struct {
	Changed []string `json:"changed"`
}

// Created is what user_create and group_create made.
type Created struct {
	ID   string `json:"id"`
	Sam  string `json:"sam"`
	Name string `json:"name"`
}

// Reset is user_reset_password's result: the flags only, never the password.
type Reset struct {
	MustChange bool `json:"mustChange"`
	Unlocked   bool `json:"unlocked"`
}
