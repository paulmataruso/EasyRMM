package assess

import "github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"

func sampleReport() *report.Report {
	n := 105
	return &report.Report{
		Scope:        []report.ScopeItem{{Name: "HQ-WIN", Kind: "computer", Category: "cui"}, {Name: "KIOSK", Kind: "computer", Category: "out_of_scope"}},
		Requirements: []report.Requirement{{NistID: "3.1.1", Title: "Authorized access only", Family: "AC", Status: Met, Statement: "Named accounts only."}, {NistID: "3.1.2", Title: "Allowed actions", Family: "AC", Status: NotMet}},
		POAM:         []report.POAMItem{{NistID: "3.1.2", Points: 5, Status: "draft", ClosesBy: "2027-06-01"}},
		Score:        report.Score{Low: 105, High: 105, Number: &n},
	}
}
