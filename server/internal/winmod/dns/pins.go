package dns

// pins are the SHA-256 of each embedded script (ADR-0073). Changing a script means changing its
// line here in the same reviewed change; a test and the catalog build check them.
var pins = map[string]string{
	"record_add":           "5059143ef7e6bdff08ce79b95e7dd1251f94a31f5459c021654cb1a77d4fc700",
	"record_list":          "37315f3530f77625a42025a3ac26d7c2051a6299056d403eb21f7475eaaa7277",
	"record_remove":        "74646ff689f1dec38b5b6864aa31186409a629e6de63f258557cc1598ee86126",
	"record_remove_all":    "ba6464462f6ae420cd551701873c860be9840f7c57340aef79b4c5c93665d20e",
	"record_set":           "13b9554cacb6ef356837ed88a101664683eeaa20a83b1ecaead2c050456b0a46",
	"status":               "e952b462f714b11f8ca2bf2d409d539179828d69855d90fef787ff6177d54bcd",
	"zone_allow_nonsecure": "5161f84067295ab2a3e0cc70a62effa27dbb19d66b25fe286bd98e4812841656",
	"zone_create":          "d6d79c23ee1c219cbae0f57ab6d100339d6741084169acef96f20ec1a4424709",
	"zone_get":             "25d970c3efb4e3f47da4a600529f5748ee485f4bfd11ee599d887aece82a2a72",
	"zone_list":            "bae0afe05913a1cfc43fcb16921f6daf0a168af39cc4f6335e594184f35d93f9",
	"zone_remove":          "4f7cd59c041b0e06d0eb032ea84b84cd70f0e86da8db4e2ae4c929b88443a6e0",
	"zone_set_update":      "60a6521cbad3e02b798f2c10cfb367de5353706f2ee8422db4b6a45c387d795b",
}
