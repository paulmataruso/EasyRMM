package fileshares

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"openfile_close":       "0ca36089d5b3ecae376abf4e9b7f711dfdcfde63ba3b9879c44791fdeb20f4f1",
	"openfile_list":        "5b6147b0f0fb9298c9415d5b82c11d62fd8dad636bd9a4152903948cc146ea46",
	"session_close":        "65a1d88015855df1b16b33c016317ffde973639af1bbf733c284004f8aa468ac",
	"session_list":         "d5ed4aee997274aac3c50a63a3eb99114542d8a918b9a2569a0618dfe6b12359",
	"share_access_block":   "e7504b4103749f5f1c931e15358f0920c6ea1a18249573e9682610b45eacc8b4",
	"share_access_get":     "f17faf0b8dfccdfb1e0688f0a51ec56c3dd8efb0c5d4832c71c5324cd5691b68",
	"share_access_grant":   "82622abf27da54c3eed1dc859d2cf7027758871677173d98827752fdf55bed4c",
	"share_access_revoke":  "2c4edc366411ad4c6bd17d0f99cf709769118d527bf1283e21b5bb5b79ad0de8",
	"share_access_unblock": "f4b6c252e2715de05fa7ac54135852b5d15ed4b5638d2cd2614148f02ba93c9c",
	"share_create":         "1381e3b89647d4eb7bc0e054bebc5f288628facb8228331f370534167eeccde5",
	"share_list":           "21c609599af726d70f0c39aea60d1037429d3c565de240bd5283db0cbe2e1653",
	"share_remove":         "c8a2377c209b160920b468a8e4efabe3db0b454237a944fb834cf9a94ac553da",
	"share_set":            "ed772aef947e5bcc823c3f0d549dcad7bb3868efe1704b9d325b17cd4ebdf84b",
	"status":               "33b2c0bce8d668bdc0098311e91228b0f4a46f0d8901bd4904ebb72c7c21a316",
}
