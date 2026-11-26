package grouppolicy

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"gpo_backup":        "aaf53b9003a86ebd9ffb351e1bc8959b0d12b1dea050494d0024cd293dcf9542",
	"gpo_copy":          "d7c6ada18990e8d4e36f4105b127aaabede7d2c9e09ab14a91e0bac292fe0932",
	"gpo_create":        "3d3ea60fdcdaabf51d841fcafbf63795aa42bf7d47247aa2e7dcbcbbd3908131",
	"gpo_delete":        "4537b845dfef02ab0390232943ea05f1ec712df69923515d0f00ad1ce4ffca0d",
	"gpo_get":           "f20079bc6248f40290475994da85d66c11ab67af4bf45e317a3db361ce23e3fb",
	"gpo_list":          "78d2ece61c0ac080419eba37aa97bf0680033b3a826e49c7ca94cc75fce077b4",
	"gpo_rename":        "3f48cca4e1654f0429bcecabb6c06cd3f34d7f36d27357695198a4fb654bad12",
	"gpo_report":        "7365d42a9e7f0619edd13d79d76e710464b7fc87e855acb299e6e5f03c1c54c1",
	"gpo_restore":       "e4a6bad348df4eee519b32940df3cce4c1c714f429dbcf3b48fc6d06aa136313",
	"gpo_restore_stage": "4da4365cedc98e42513f99b26116ab0f7e670d1382080ff5f0bb60f4e6f41fec",
	"gpo_status":        "1ceab6e4532469ceeb704ea54fa72331ee451244a9e8abe36db96fc99dcb88ea",
	"inheritance_block": "c14d48f0e5e0eb41c97c900d4da0766569dead157a63fb551247791930c751a0",
	"link_add":          "2bbc346842e62890f13be05a7496966d7bbc660a75538872d219b94f2dc33298",
	"link_enabled":      "dd0763949025a3cecdded553b94f6cd57fea10919eab1332784576940f3fc1af",
	"link_enforced":     "f7ca5640933e151d68f31ed633a34fa72f336bdbe157507eb4085da40f38040b",
	"link_order":        "2c11598592130c768e5bbc83259893a24f0e054b70412e5ec83ff39db760da0e",
	"link_remove":       "a89461d4e7d8c42e0b1a58e14a1a9d20b55baf80d5f1fd0f4610442aea909bfd",
	"link_tree":         "c543e0c33d101f39a0479fb1c8309b905f650bae302b59b511253fe3e55db476",
	"sec_filter_add":    "ea08b381026f6b6f4e53df76c9b8aae669fa707d459e44eb9b5d0e8b7ad00a04",
	"sec_filter_remove": "9117bb14d049b5c3e3e89f6c461d262e709627c8665cbb0d183baf8d4e1436e6",
	"status":            "8f16df943d84781e3d72e23ff8075640fee90964a7c05227d677afbc0e61b775",
	"wmi_filters":       "23ac156fe9e9c1a80d2810e081c35691ea09d5b5ac61cc9dd33f49cabdb10471",
	"wmi_set":           "8f63bb9cc6be3c441e0d888ba84e03936182fcf6851c42f40a5437e8493a6c6d",
}

func pin(name string) string { return pins[name] }
