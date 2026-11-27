package grouppolicy

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"gpo_backup":        "2730aede8a907d661ca906e1e49d29f13cc477c35c09fc11baf174e010415e01",
	"gpo_copy":          "ed583b6497bf92e9ae0285bd23c792b3f73d94b1925317aaf0d70f4a177817b2",
	"gpo_create":        "dd37ae68d6f83a9a273a1f61e2715870da67954b37d069d43504e9787c80b80f",
	"gpo_delete":        "75fda4e1f827d0b66ed7fd4c6f78735472a9cc1cd31559e2ea13cca6707b02d8",
	"gpo_get":           "3aa73ff27d37e36215afd142203bf779e0c013df8bfcba73427472862e57e355",
	"gpo_list":          "2625845d7f2b9760d963c23dab7ef71ee173147dd1682155e09bc0290ee67fd6",
	"gpo_rename":        "9d799c8394ec0b9eb31486c6293fe4c874a9bb025f6dd6802e131b0439f42f23",
	"gpo_report":        "c6fedde672e98d11f1d86990632c9bcc24cb5039a9992475243a1805bf9bb141",
	"gpo_restore":       "4eaa992ced935204deb27881782686e9a74b93b020a9e19edbb11547ab722173",
	"gpo_restore_stage": "1800c7c4923f94ca941bd89e948e4a7a39fc5f5ad8db1c55b8ae3a40c339c97b",
	"gpo_status":        "5e630d436c5c067bb0dc00de594be28114de66e9e34b709e3db3b8198457fa6d",
	"inheritance_block": "4fa1f53c1bf5e9d92d036c69139be8cfe4cd592add6a8eca72bb1336c934fd04",
	"link_add":          "717b0970a824fc9aa3fcb4018102a1fdb4e9490e58ae79ab0aab0253c5ecab02",
	"link_enabled":      "c35c71251973dd4c6b05f7202ed7ef71580d82b00638d6cfacd8f20ae309eb5f",
	"link_enforced":     "4e8c3868c8030cd4014fe491bcfb7ee69b3a54ea944e9fc276e5b45daee10bc6",
	"link_order":        "7667f95b7b7d9805306449518470a512e843156c02e40d382d48e7c5379c5e2b",
	"link_remove":       "445aaad7d4af714ca60f575aa120bcd7387afd777305c72996ad9c59bf069124",
	"link_tree":         "ee27160dcbf5d933e6e6784bf32e7fc5915bc8252418ca8b1fb78ccbdbc678b2",
	"sec_filter_add":    "624589c321ae01826730933fceb50455b61c7b1278037dbd65521ed21807776d",
	"sec_filter_remove": "b9c5347c3209dd0192923fa729dd950469cfacfd41a57d3e05cb5584249bb30f",
	"status":            "fe09f42601735eb125858bc097d4c42db41eee934f1de814da8923c1b79ce575",
	"wmi_filters":       "c27f8fe442713aaf04a73af9436580bb818218dd74f5f7031ea3a65c79854fac",
	"wmi_set":           "a672d2606070533b2c3f810ddb368ac274b80869eace4234cc871b0eb8bd12dc",
}

func pin(name string) string { return pins[name] }
