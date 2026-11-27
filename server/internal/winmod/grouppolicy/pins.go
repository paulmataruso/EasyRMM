package grouppolicy

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"gpo_backup":        "8e4c7ef3649b8e522007445a860fc3cbfd9740de74861c8d6f0d0eb49a05fb3e",
	"gpo_copy":          "fd018b91c25c9999d6b4dc04c442c1b6671ffe87f2cb302e16c050a62b7103ab",
	"gpo_create":        "7a77980b59375ab8ad588f553980b148b502003d09785af13021c56215d0f294",
	"gpo_delete":        "802369c08643aa9968a5ef3f16041a4be57ad95f741f0438f9d379bc68adfb45",
	"gpo_get":           "1095e3be21125f8a2a1c72cec407eb7d58d496f03aec32ac9e3329299b53c31f",
	"gpo_list":          "aeb937c34fc0890d086508f3afb3cff9264339aee7c0b61588a064668c0ebddd",
	"gpo_rename":        "dd4ea6ec830bf47abb225b3fbd58a10109c64869663a56953e74260a461527de",
	"gpo_report":        "72530eb3525c8b21d36ac0aea3e4869acbb51c67cfb68389e5025e24aaf799cc",
	"gpo_restore":       "fa1c8c5b82b817a22a224d728530ef216fc3ade7631fd714ed3d6dd876287f70",
	"gpo_restore_stage": "e04b9177681a482d5a4e32c8e33a96c6b5849e9930e9effe1fda17b1edfbb412",
	"gpo_status":        "7ebbd7cf62c3949f170caaec030a38c2897e527b86cddd42513e61f70c1ac2ba",
	"inheritance_block": "2c6b3eb321a49935fdc75a038964ad9af217a27d3ed090a2cab8586c907ef1d5",
	"link_add":          "d6dc8feb8a46261aeaa3f791d2171c306532e831ff65e6a9da7b0b200a5cdbff",
	"link_enabled":      "468f8af45f862f009912230cf448303eae8862f9ead2dce1f19d63e4b8ea973b",
	"link_enforced":     "70b6ff2e54644e961879c294f04f32dfe22f101cd26db1cd8552015c491ebbe2",
	"link_order":        "784c8f2293b3d78c6fb8d95711b9945cb000c15754387aceea2eb2c48a64b38a",
	"link_remove":       "e8ed5741f9e0734a1d3eb30ef8320ac075709b2d84b09f896bb860cc2991f486",
	"link_tree":         "03dad0c1448ff3d17a7b51decabfa6eb6b59b6cd6fa66b03c1acf96f4800df92",
	"sec_filter_add":    "310e3039d819cc6951b2dad0b5180f9069e9f2acd6b79209b2e39d366081e373",
	"sec_filter_remove": "e5ee5f359ab4b0fc729ed0d6f7057bc47f17ebad04a899007779d726db0bd60f",
	"status":            "297d03d85778d69d02fa3b15a912e33673ee055bfbb3226ac5a6018d0685fc4d",
	"wmi_filters":       "5e84dae320849a7472b7333cfbe777fabf5db59822548350eca2c029b11e353f",
	"wmi_set":           "b1ce7f4227ace24d731740e113c720cd0680b1f8731ffc178bb9b540b389f50f",
}

func pin(name string) string { return pins[name] }
