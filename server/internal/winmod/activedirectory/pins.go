package activedirectory

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"computer_disable":    "5bfdd4a8fd72acf891c198940b415d5a6de5e471f70f8c9a993c56745d55ef6d",
	"computer_list":       "c3f0c60cfa083a1261732a535f1cb345d59f4f72ae2066ee30efe1271222d062",
	"group_add_member":    "892051a21fd1d0f2991b6ec78923f0a7c205141f5a815e97f7ea9bc4b8606144",
	"group_create":        "920d143ae42db85343f174492395dcb626d9e0407f3d51c27e58a9f52df85248",
	"group_delete":        "7d8ec4b649e26fbf652853b5ec345ba52289f57fcc7afaac6936e694b661e2cf",
	"group_list":          "729b05a6b2d16ca4de9eae42cd4b0bfc45e07e2c98b34fe71656261a4d1a6c20",
	"group_members":       "f2f3469a6446d4ed5a89be4f1f4f1c89d839e215449de0abe8f1cbd97934cbe5",
	"group_remove_member": "0163aed3379a34cd024a4ef595fc5626ebd683ceb92128c5ef39afe136344f10",
	"health_read":         "3c6071ae1fd246e2e5c430dafbe96750f3ec58ef71c1c9131b060abef1ba84ab",
	"ou_tree":             "31eb8508538d68180de12db9ab56083efa8b087cc6002d7bc4624669cc4a0268",
	"privileged_members":  "24171081e889d2d12f927742d4ace1846786b0fb22231104e8139ed99b405258",
	"status":              "9f2630e66e81b5185caf0b534580f5fd22b531e9ab91a0612e19b71c4f1c5e32",
	"user_create":         "e61b8d47bc3dba29a38e13124789990ce661fabb5754e781db104fd70f498665",
	"user_delete":         "f5e5aac81b6b07d62bd07165f084cd14624e1ee75fe3aa11efcc981879f6f0e6",
	"user_disable":        "69d5aea288d91ad6051921788bdee85e2b1e680ad03fa18101283ed9bd177837",
	"user_enable":         "f4287d388b7d0272cf9fe5a5512553d4cceb8eb7a8e74256a764f945b304ad21",
	"user_get":            "dfbc3aefcff22a8b7476fbbfe414e4f8e0e1c13152bed57a50ce0c53368704c5",
	"user_list":           "6caba4cdc3cf74e88f99a8f054eab05df000c5b16f6d900c735f40c666c6dc3f",
	"user_move":           "b134fc26568b35b951ed61e1108ad4b5f5e8bb124090baf966444ce8ac589c05",
	"user_reset":          "dcb6208b55d1383d01a3f493f4203b6b34a239548a0446e8757e813d1c889bc3",
	"user_set":            "51aa5735bed8abd7c0a9f35dbbb4d8a1789947b21f0b4dd7034f98678774a1ce",
	"user_unlock":         "0bef3550128de0596a19540ce9c1af9dde8004c0be6fc46cc18419d4b8e0bf66",
}

func pin(name string) string { return pins[name] }
