package dns

// pins are the SHA-256 of each embedded script (ADR-0073). Changing a script means changing its
// line here in the same reviewed change; a test and the catalog build check them.
var pins = map[string]string{
	"record_add":           "0e6aadad6eea760be72053845b53587a539416565c5a522dad21ea6bc9e1c412",
	"record_list":          "214b5d7a407f0d1c4cef311b88637392556a05d58469116fdcc80bbff3a3f747",
	"record_remove":        "31e26c80f57a73a681c6178345e0038dfbad23e4c5e1e02a9a6e192ad67d6966",
	"record_remove_all":    "6b9db51a1d6e5b45e2e7f6e8d7a0a85c9573de6aef281303268d88353068bfc6",
	"record_set":           "91bd4a0ec2f962512b0eb22e6616f99c524a1fe2fbb4d271b56528c582313bff",
	"status":               "e3cfcce8d4ba233814166987556c64d64113c6e416beffb13309d86fd5b48b6f",
	"zone_allow_nonsecure": "c7ada3ee3aef926d01d0162bdf2a1ab7e6771abccdabe284cfb7080c3cc91eca",
	"zone_create":          "f2000d8b4a1dc56e21d66668623a3c7ac8b713b58b181faa85b2b51abd286a37",
	"zone_get":             "89d0a1969d3d3158f52512ee3e42c34077cd8200d7ad0091fbc0113b099747d8",
	"zone_list":            "ebe5e172591d2f48daeddb1dc418b1e1db26907e8faf9c0a954e2bc61c532292",
	"zone_remove":          "59fde8efd53a2f69de515ad8877fcfe858311204aa3196b7b82993cf3b9932ee",
	"zone_set_update":      "c3feb6a1f96569cbc5d65c870d0bc915f619fd08f4968e790316d3c9f9186c47",
}
