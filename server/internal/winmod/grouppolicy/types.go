package grouppolicy

// The typed results of the module's actions (ADR-0083, slice 1). The scripts print exactly these shapes; the catalog
// decodes them strictly, so a field the script adds and the server does not know is refused.

// Status is group_policy.status's result: the domain, the controller the script ran on and the GPO counts.
type Status struct {
	Domain     string `json:"domain"`
	DomainDN   string `json:"domainDn"`
	Controller string `json:"controller"`
	GPOCount   int    `json:"gpoCount"`
	// Empty counts GPOs whose user and computer versions are both 0: nothing was ever saved in them.
	Empty int `json:"empty"`
	// Unlinked is the GPOs no domain, OU or site links to; null when the link tree was too large to walk.
	Unlinked *int `json:"unlinked"`
	// Sites and Containers are what the link walk covered.
	Targets int `json:"targets"`
}

// Version is one part's version number, as the directory and SYSVOL hold it. They differ while replication or a write is under way.
type Version struct {
	Directory int `json:"directory"`
	Sysvol    int `json:"sysvol"`
}

// Link is one link of a GPO to a domain, an OU or a site.
type Link struct {
	GPOID   string `json:"gpoId"`
	GPOName string `json:"gpoName"`
	// Target is the container's distinguished name, TargetName its name and Kind domain, ou or site.
	Target     string `json:"target"`
	TargetName string `json:"targetName"`
	Kind       string `json:"kind"`
	Enabled    bool   `json:"enabled"`
	Enforced   bool   `json:"enforced"`
	// Order is the link's position on its container (1 is applied last, so it wins).
	Order int `json:"order"`
}

// GPO is one Group Policy object, as the list shows it.
type GPO struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Status      string  `json:"status"`
	Description string  `json:"description"`
	Owner       string  `json:"owner"`
	Created     *string `json:"created"`
	Modified    *string `json:"modified"`
	Computer    Version `json:"computer"`
	User        Version `json:"user"`
	WMIFilter   string  `json:"wmiFilter"`
	// Default is true for the Default Domain Policy and the Default Domain Controllers Policy.
	Default   bool   `json:"default"`
	LinkCount int    `json:"linkCount"`
	Links     []Link `json:"links"`
}

// GPOPage is one page of group_policy.gpo_list.
type GPOPage struct {
	Total  int   `json:"total"`
	Offset int   `json:"offset"`
	Next   *int  `json:"next"`
	Items  []GPO `json:"items"`
	// Walked is false when the link tree was too large to walk, so the links are not known.
	Walked bool `json:"walked"`
}

// Trustee is one entry of a GPO's delegation.
type Trustee struct {
	Name string `json:"name"`
	SID  string `json:"sid"`
	// Type is user, group, computer, well_known or other.
	Type       string `json:"type"`
	Permission string `json:"permission"`
	Inherited  bool   `json:"inherited"`
	Denied     bool   `json:"denied"`
	// Apply says the trustee has Apply group policy, which is what security filtering is made of.
	Apply bool `json:"apply"`
}

// ReportLink is a link as the GPO's own report names it.
type ReportLink struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Enabled  bool   `json:"enabled"`
	Enforced bool   `json:"enforced"`
	// Sensitive is true for a link at the domain root, to the Domain Controllers OU or to a site.
	Sensitive bool `json:"sensitive"`
}

// GPODetail is group_policy.gpo_get's result: the GPO, its links, and its delegation.
type GPODetail struct {
	GPO
	ReportLinks []ReportLink `json:"reportLinks"`
	Trustees    []Trustee    `json:"trustees"`
}

// Target is a container a GPO can be linked to, with what is linked.
type Target struct {
	DN   string `json:"dn"`
	Name string `json:"name"`
	// Kind is domain, ou or site.
	Kind string `json:"kind"`
	// Sensitive is true for the domain root, the Domain Controllers OU and every site: a link there needs two people.
	Sensitive        bool   `json:"sensitive"`
	InheritanceBlock bool   `json:"inheritanceBlocked"`
	Links            []Link `json:"links"`
}

// LinkTree is one page of group_policy.link_tree.
type LinkTree struct {
	Domain  string   `json:"domain"`
	Total   int      `json:"total"`
	Offset  int      `json:"offset"`
	Next    *int     `json:"next"`
	Targets []Target `json:"targets"`
}

// WMIFilter is one WMI filter of the domain.
type WMIFilter struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Queries     []string `json:"queries"`
}

// WMIFilters is group_policy.wmi_filters's result.
type WMIFilters struct {
	Filters []WMIFilter `json:"filters"`
}

// Backup is what a change reports about the backup it took first. The zip itself is not stored in the result: the
// server moves it to its own table (Decode drops it).
type Backup struct {
	BackupID string  `json:"backupId"`
	Domain   string  `json:"domain"`
	GPOID    string  `json:"gpoId"`
	GPOName  string  `json:"gpoName"`
	Size     int     `json:"size"`
	SHA256   string  `json:"sha256"`
	Computer Version `json:"computer"`
	User     Version `json:"user"`
	// Zip is base64 of the zip of Backup-GPO's folder; empty in the stored form.
	Zip string `json:"zip,omitempty"`
}

// Changed is what a change answers: what it did, the versions it saw before and after and the backup it took first.
type Changed struct {
	// Summary is one readable line, kept in the audit.
	Summary string `json:"summary"`
	// Before and After are readable maps of what changed, for the audit's diff.
	Before map[string]string `json:"before"`
	After  map[string]string `json:"after"`
	// GPOID and GPOName name the GPO the change is about; empty for a change to a container (block inheritance).
	GPOID   string  `json:"gpoId"`
	GPOName string  `json:"gpoName"`
	Backup  *Backup `json:"backup"`
	// VersionBefore and VersionAfter are the GPO's versions around the change.
	VersionBefore *Versions `json:"versionBefore"`
	VersionAfter  *Versions `json:"versionAfter"`
}

// Versions are both parts' versions.
type Versions struct {
	Computer Version `json:"computer"`
	User     Version `json:"user"`
}

// Created is gpo_create's and gpo_copy's answer.
type Created struct {
	Changed
	ID string `json:"id"`
}

// Staged is gpo_restore_stage's answer.
type Staged struct {
	Index int `json:"index"`
	Count int `json:"count"`
}
