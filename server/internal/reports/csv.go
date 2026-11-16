package reports

import (
	"encoding/csv"
	"io"
	"strconv"
	"strings"
	"time"
)

// WriteCSV writes a report as CSV: UTF-8 with a byte order mark (so that
// spreadsheets read it as UTF-8), a header row, and times in UTC.
//
// A text cell that a spreadsheet would read as a formula (one starting with
// =, +, -, @, a tab or a carriage return) is written with a leading
// apostrophe, so that a device or package name cannot run a formula on the
// computer that opens the file (OWASP "CSV injection").
func WriteCSV(w io.Writer, r *Report) error {
	if _, err := io.WriteString(w, "\xef\xbb\xbf"); err != nil {
		return err
	}
	cw := csv.NewWriter(w)
	header := make([]string, len(r.Columns))
	for i, c := range r.Columns {
		header[i] = c.Label
		switch c.Type {
		case TypeTime:
			header[i] += " (UTC)"
		case TypePercent:
			header[i] += " (%)"
		}
	}
	if err := cw.Write(header); err != nil {
		return err
	}
	record := make([]string, len(r.Columns))
	for _, row := range r.Rows {
		for i := range record {
			record[i] = ""
			if i < len(row) {
				record[i] = cell(row[i])
			}
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func cell(v any) string {
	switch v := v.(type) {
	case nil:
		return ""
	case string:
		return defuse(v)
	case bool:
		if v {
			return "Yes"
		}
		return "No"
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case time.Time:
		return v.UTC().Format("2006-01-02 15:04:05")
	default:
		return ""
	}
}

func defuse(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// FileName is the name a report downloads as: easyrmm-devices-2026-11-16.csv.
func FileName(r *Report) string {
	return "easyrmm-" + r.Name + "-" + r.GeneratedAt.UTC().Format("2006-01-02") + ".csv"
}
