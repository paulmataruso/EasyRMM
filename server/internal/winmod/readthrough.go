package winmod

import "time"

// ReadFreshness is how long a read-through action's stored result is
// fresh (ADR-0073 section 5). The console shows the stored result at once and
// starts a new read when it is older than modsnap.AutoReadAge, which is
// shorter.
const ReadFreshness = 5 * time.Minute

// readThrough names the read actions a tab shows from their last result and
// refreshes on its own when the tab opens (ADR-0073 section 5, as amended by
// the automatic-read rule). Each is a read with no change in it: NewCatalog
// refuses a name here that changes anything, asks for a confirmation or a
// step-up. Actions that already declare a Freshness are not listed.
var readThrough = map[string]struct{}{
	"active_directory.computer_list":           {},
	"active_directory.group_list":              {},
	"active_directory.group_members":           {},
	"active_directory.ou_tree":                 {},
	"active_directory.user_get":                {},
	"active_directory.user_list":               {},
	"certificate_authority.activity":           {},
	"certificate_authority.ca_certificate":     {},
	"certificate_authority.crl_status":         {},
	"certificate_authority.request_get":        {},
	"certificate_authority.requests_list":      {},
	"certificate_authority.requests_pending":   {},
	"certificate_authority.template_available": {},
	"certificate_authority.template_list":      {},
	"dhcp.exclusion_list":                      {},
	"dhcp.option_list":                         {},
	"dhcp.reservation_list":                    {},
	"dhcp.scope_get":                           {},
	"dns.record_list":                          {},
	"dns.zone_get":                             {},
	"file_shares.openfile_list":                {},
	"file_shares.session_list":                 {},
	"file_shares.share_perms_get":              {},
	"print.driver_list":                        {},
	"print.job_list":                           {},
	"print.job_list_sensitive":                 {},
	"print.port_list":                          {},
	"windows_backup.disks":                     {},
	"windows_backup.job":                       {},
	"windows_backup.sensitive":                 {},
	"windows_backup.versions":                  {},
	"windows_backup.versions_prune_preview":    {},
}
