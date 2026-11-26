// Package report is the data an assessment's exports are made from (ADR-0078, slice C5): plain
// values, read once from the database, so that the OSCAL, CSV, ZIP and PDF writers have no database
// and no rules of their own.
package report

import "time"

// Report is one assessment, as exported.
type Report struct {
	AssessmentID string `json:"assessmentId"`
	OrgID        string `json:"organizationId"`
	OrgName      string `json:"organizationName"`
	Title        string `json:"title"`
	Assessor     string `json:"assessor"`
	State        string `json:"state"`
	Framework    string `json:"framework"`
	Version      string `json:"frameworkVersion"`
	// Generated is when the export was made; Approved when the assessment was.
	Generated  time.Time  `json:"generated"`
	Approved   *time.Time `json:"approved"`
	Disclaimer string     `json:"disclaimer"`

	Scope        []ScopeItem   `json:"scope"`
	Requirements []Requirement `json:"requirements"`
	POAM         []POAMItem    `json:"poam"`
	SSP          []Section     `json:"ssp"`
	Score        Score         `json:"score"`
}

// ScopeItem is a computer or group and the category it was put in.
type ScopeItem struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"` // "computer" or "group"
	Category string `json:"category"`
	Reason   string `json:"reason"`
}

// Objective is an objective's determination.
type Objective struct {
	ID            string `json:"id"`
	Determination string `json:"determination"`
	Source        string `json:"source"`
}

// EvidenceRef is a piece of evidence a requirement points to.
type EvidenceRef struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
}

// Requirement is a requirement as assessed.
type Requirement struct {
	ID             string        `json:"id"`
	NistID         string        `json:"nistId"`
	Title          string        `json:"title"`
	Family         string        `json:"family"`
	Status         string        `json:"status"`
	Origin         string        `json:"origin"`
	Partial        bool          `json:"partial"`
	Weight         int           `json:"weight"`
	Statement      string        `json:"statement"`
	Responsibility string        `json:"responsibility"`
	Owner          string        `json:"owner"`
	NextReview     string        `json:"nextReview"`
	Objectives     []Objective   `json:"objectives"`
	Evidence       []EvidenceRef `json:"evidence"`
}

// Milestone is a step of a plan-of-action item.
type Milestone struct {
	Title  string `json:"title"`
	Due    string `json:"due"`
	Status string `json:"status"`
}

// POAMItem is a plan-of-action item.
type POAMItem struct {
	ID         string      `json:"id"`
	ReqID      string      `json:"reqId"`
	NistID     string      `json:"nistId"`
	Weakness   string      `json:"weakness"`
	Points     int         `json:"points"`
	Eligible   bool        `json:"eligible"`
	Reason     string      `json:"eligibilityReason"`
	Status     string      `json:"status"`
	OpenedOn   string      `json:"openedOn"`
	ClosesBy   string      `json:"closesBy"`
	Owner      string      `json:"owner"`
	Resources  string      `json:"resources"`
	Milestones []Milestone `json:"milestones"`
}

// Section is a section of the system security plan.
type Section struct {
	ID        string `json:"id"`
	Heading   string `json:"heading"`
	Body      string `json:"body"`
	Generated bool   `json:"generated"`
}

// Score is the score range and the reading of the conditional-status rule.
type Score struct {
	Low         int      `json:"low"`
	High        int      `json:"high"`
	Number      *int     `json:"number"`
	NotMet      int      `json:"notMet"`
	Unassessed  int      `json:"unassessed"`
	Met         int      `json:"met"`
	SSPMissing  bool     `json:"sspMissing"`
	GateOutcome string   `json:"gateOutcome"`
	GateMin     int      `json:"gateMin"`
	Blockers    []string `json:"blockers"`
	L1Met       int      `json:"l1Met"`
	L1Of        int      `json:"l1Of"`
}
