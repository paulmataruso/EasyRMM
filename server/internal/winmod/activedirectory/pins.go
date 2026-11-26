package activedirectory

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"computer_disable":    "59162fadff20ba8597fe74e4ea019d677f28129d4c22049a58bc889d735991cf",
	"computer_list":       "0add05953cf6c84245e1ac15eec1d230d419dd61086283ac11335d638acebd8b",
	"group_add_member":    "09365d2e5a8c365b8b60166d9e0adc4eaab59cd1503b134b8053f37885a12900",
	"group_create":        "a7bb0c9147442fa9cefdaffc23dea72e4c7e0d527967ac845ae86e87bc3abed1",
	"group_delete":        "6872c401893d8baab7c57e92f06a80425de46cc3a28a108e1f33dd3868e067e9",
	"group_list":          "4206f003927c7e9e1e8515046c632dd19dc7be8099f2affbfff7a81c6781474f",
	"group_members":       "e7db499988afa483c3490e11cffbee618cff3bfda7ec587adfabfbf5ccf65410",
	"group_remove_member": "5015d1806b0ca87a1ed3d18143e0aca96d13cf6b247b1f4702e9f64ceeeae9a1",
	"health_read":         "8b0e55091d86dcc852304a8a28d5a87aadb9b47caaed9616f772c1195db33712",
	"ou_tree":             "01c2531130715e01a12bcb5b1b58f7630b48123600c8f806ef2c786925fda2bc",
	"privileged_members":  "0d0740213e94d206e6a07a3541ef788035c2e61886f86e5b2bafe3f2a6c593b1",
	"status":              "7f6b887a3e8ad9f35e299a52d25137277091b78ea38e5acb6c5670f13153f827",
	"user_create":         "6bbf838026e6b9c7c69a54ae22a3151158478e5cb5e2c2fdea7ffe99ebf8e866",
	"user_delete":         "2b3cfd63079b195eac0c3c2bf1b8cdce94681db415917fd215bdcfd76bd45c6c",
	"user_disable":        "0df50d2eb4f39104d91b362d1cde39e6f06461f7c02a492b884da6901cef8dbb",
	"user_enable":         "f5815f2e290670954e49afe225a6ac085cfde8e85eeffd0324beadb8828c0ce6",
	"user_get":            "85b04bcf5f19c39a4d98c15c6d0a663b671f268f4e76948b533cdfba57df0411",
	"user_list":           "6c2e6fd9952989a07c11e265200a8bca1880f699f449c247c4048b0344da0cc2",
	"user_move":           "4459a0fc54b70537e1ad40f40388f9c3026ebb76171703d9359a4ff4994b3e7c",
	"user_reset":          "0352739c2ac65c22285e6ef0c09c871818857414077e3dab3d1826f84a2e3c03",
	"user_set":            "995dcbc24eb16f1f6281caf2d52fb6c4d0b69ecc63e95707f601dde09209fd30",
	"user_unlock":         "cbb4351db1201a4031414353248004324504ca5e8c69534adca0a4d2d71d4e2b",
}

func pin(name string) string { return pins[name] }
