package dhcp

// pins are the SHA-256 of each embedded script (ADR-0073). Changing a script means changing its
// line here in the same reviewed change; a test and the catalog build check them.
var pins = map[string]string{
	"exclusion_add":        "d797a77313371850d2663a6f5fe48f1a937a10ba72f7b8469b1da021fa0d8f9c",
	"exclusion_list":       "a014d02db3655406c62357e058ed88f2c1bdf04c4fe3f774b2964c663b5d1923",
	"exclusion_remove":     "e3686bd9b79637dce90e4793727898645437664278b3b4c31ebd009c2f3a04b0",
	"lease_list":           "61277963423c9bdad80c733b36ed0a41868bd0413a722375d9acc587ba6bea18",
	"lease_remove":         "02d2b5a7aeafa229926114d679393b021919b8a31093e2ad15d49adcb123d2d0",
	"lease_to_reservation": "72d3fbf281dc364f8d888041f9847974732dbe78ddf37d999a6b291970f459fd",
	"option_list":          "206524172cd26b32691c539a011b692e93c75fc1d3ba09d68b4a40688b6309e0",
	"option_set":           "83976ca5ba9ee3202d46b8bfdcb679e8f1796387613fc4d71fc5fc9f73b39acb",
	"option_set_network":   "46b18941ed80bf1f85b3f671c3926ca442eb27835db154df6e8e7d0ca5ae2520",
	"reservation_add":      "190cb805c97fd7790525f78cb4d7e10af3d0b9e0c51cd3f98855b8b9da8cff4b",
	"reservation_list":     "e00adb84d4d45a9accc4d7b643b643d80d90349da5801926a0a2634885645f1f",
	"reservation_remove":   "3fa80e684856d3fd4c18177eb4cca2a6bc0885bf821d5eced2f5da9ca23238e1",
	"reservation_set":      "c4eea8e07f2c61e4f7749a24462f6f411c632c2148b0a589292f5858ed3a4f27",
	"scope_activate":       "1f7505af3ffad8325e096a745e8c08ef59bf3c3bc46d0139bb2b29efb1a8bab3",
	"scope_create":         "6470f068376b1bf688f46b30863596be899261b1a7f49b0995c7c7646fb541f9",
	"scope_deactivate":     "e78044a07e81258d3aeb91cf9961103f54b7c6240461b615ac3857486c68d6f6",
	"scope_get":            "c084020c26a00f45e910385e69ddee69248f7c391a0a97f1912a733fb7d4baa5",
	"scope_list":           "ae2112409e7907bc73568d7bab742e298831792bfad2a72c855a61e63415f052",
	"scope_remove":         "edab344de6b87f7075dd84558e7a69a6ea1a46b35eb67b1429ec862155624b78",
	"scope_set":            "ad4dcc78777854f7f9a50623e2742ec6fb42739dc2206dcf91dc4a4f65f99898",
	"status":               "71ea486cc2c1090d725d90baef10d198e60263438e3ba711d8b58364d3210be5",
}
