package certauth

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"activity":               "31381177b87218da0de1a55c82f015957907ccbe12acc979834cf6d4e398f66f",
	"ca_certificate":         "6a1f7143b988bf11a9170bdc9855fb0e2a195932296cf166f23ecaa1420d0d48",
	"ca_findings":            "b790dbd26573cc68764368310eb1f4ebfc9bad29f85884f6458ed2774a2d4d05",
	"certificate_revoke":     "496f3fce91c2c9ec809d7354e429a3c59be2b48703bb1ba07caa439e16948c18",
	"certificate_unrevoke":   "fb55e6b89d79dd1efb6354d1e3ee807c427126b4aa0531f07df66a68d4c9a82d",
	"crl_publish":            "ac4953befcbf6f514c5ad416b609c95e8765f10d8217afdf8dc673ef333bfee7",
	"crl_status":             "d9f97695fd4b773598cb532a3b444cf9a1f2cb9984be8168f44b6a884aef4cb8",
	"request_approve":        "62e9b401eb6dff3b06d933493e09a9b950be1bdf5f1a6a225dba7b37cb34ab9e",
	"request_deny":           "e4ef07b18640591361030ba7533b79cefd312c13c35a0fa4b5c1b660ed50a141",
	"request_get":            "e7e79304708abe0bff26aec1be5e247e4ec0b4fe0c263c39c7521afb59738e31",
	"requests_list":          "5d3781e23de19e5dac4dd3b2b5266ef54e9797d0414f245fbae5ab06f3f0407d",
	"requests_pending":       "98cebdb9a9e0789e9f23a60ec4910a194746f5a6c99d04114989793152e97bc2",
	"status":                 "79acd0935d998b09d7b5734d0e2c0103556b5d249ed309e0dab3ffb73a40e21a",
	"template_available":     "040c19cdaade0cbbc5e108687eb5feb37eceac5829181d7d4be2ea9467b36d0c",
	"template_list":          "dc141c3a0bd9491cae48f780f58cbd25186936c9f4c39929772a744025ea73c3",
	"template_publish":       "2bf532dab4caf84d66346d5486ab5602aa16e6614ddc550d08cce4399351b4df",
	"template_publish_risky": "5e69ded2659181d017b271e6fbd0be732af0a52ffffb0c57a586a8d5833ced47",
	"template_unpublish":     "f9a681ed7557a667d1f5f027d09c9a038ab5dc361465e448e4f563e7299e5ff8",
}
