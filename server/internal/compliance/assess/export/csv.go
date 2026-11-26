// Package export writes an assessment as CSV, a PDF and a ZIP bundle (ADR-0078, slice C5).
package export

import (
	"bytes"
	"encoding/csv"
	"strconv"
	"strings"

	"github.com/paulmataruso/easyrmm/server/internal/compliance/assess/report"
)

// cell guards a spreadsheet against a formula: a value that starts with =, +, - or @ (or a tab or
// carriage return) is prefixed with a quote, as OWASP advises.
func cell(s string) string {
	if s != "" && strings.ContainsAny(s[:1], "=+-@\t\r") {
		return "'" + s
	}
	return s
}

// Requirements is one row per requirement.
func Requirements(r *report.Report) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	rows := [][]string{{"Requirement", "NIST SP 800-171", "Title", "Status", "Origin", "Points", "Partly implemented", "Responsibility", "Owner", "Next review", "Statement", "Evidence"}}
	for _, q := range r.Requirements {
		var ev []string
		for _, e := range q.Evidence {
			ev = append(ev, e.ID+" "+e.SHA256)
		}
		rows = append(rows, []string{cell(q.ID), cell(q.NistID), cell(q.Title), q.Status, q.Origin, strconv.Itoa(q.Weight), strconv.FormatBool(q.Partial),
			q.Responsibility, cell(q.Owner), q.NextReview, cell(q.Statement), cell(strings.Join(ev, "; "))})
	}
	if err := w.WriteAll(rows); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// POAM is one row per plan-of-action item.
func POAM(r *report.Report) ([]byte, error) {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	rows := [][]string{{"Requirement", "NIST SP 800-171", "Weakness", "Points", "May be on a plan of action", "Why", "Status", "Opened", "Closes by", "Owner", "Resources", "Milestones"}}
	for _, p := range r.POAM {
		var ms []string
		for _, m := range p.Milestones {
			ms = append(ms, m.Title+" ("+m.Due+", "+m.Status+")")
		}
		rows = append(rows, []string{cell(p.ReqID), cell(p.NistID), cell(p.Weakness), strconv.Itoa(p.Points), strconv.FormatBool(p.Eligible), cell(p.Reason),
			p.Status, p.OpenedOn, p.ClosesBy, cell(p.Owner), cell(p.Resources), cell(strings.Join(ms, "; "))})
	}
	if err := w.WriteAll(rows); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
