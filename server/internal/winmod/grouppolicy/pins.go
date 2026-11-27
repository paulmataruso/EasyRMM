package grouppolicy

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"gpo_backup":        "08b9f5d8d68befa9ab3a194da0d3d7d0aff472faa430e8689c72261d59db0353",
	"gpo_copy":          "7f44630b3361fe1d7256661c38e7349b001ae954e15eed2ed99dc58383db867f",
	"gpo_create":        "0ff78232765c49a8f1c771a57633326808dcbbb56002eb02c006a07d4d8d4d4c",
	"gpo_delete":        "45192d95015e863ad8a33ca9fe15ac6b4b25fe84368e31b0bc3dc6f1fa9dc784",
	"gpo_get":           "a269acdcbb24b7213e9037c50935ecbf69c83d56763973441ff15cef1c42b587",
	"gpo_list":          "a45070a05395e36f45b7d2dafe9eeeccca1dc3d2a138be39434a106439d5f7f0",
	"gpo_rename":        "00ee4429df94ca95551feec9ef9768f37abf587aef84524ec31e355dc0c6aeac",
	"gpo_report":        "3395a15880efdbe4cae6991db5ca7a34ac3d68becfb6faa1074c3893418d5fc5",
	"gpo_restore":       "09468045601ed9fac4190770604bc141fe61d76e66af928d36b109b17920621c",
	"gpo_restore_stage": "2b03fc180a73a1628881f86ac4ace6651511c195e97eaa865541b8328964bcfa",
	"gpo_status":        "38684b437f3ad577ecc74dedf5b2fa03bb173fa37033ef3861ea615c686d8830",
	"inheritance_block": "861ed35cb34b769e463c3d691f4ae6c06769ccd3c9a36301e092f04b64fab1e5",
	"link_add":          "d7de681ad65c837b4c08f3fc7fc3846a2e0e4485587d0e38f54803d02a806296",
	"link_enabled":      "5a451689dbe5d6b14833d32ffddb9a65d48a687d4cfa896b2609e71c0b3245f7",
	"link_enforced":     "08a206db812615a7592ff0917e027232c3b8d0c4d2293106c70e57c7988c34a0",
	"link_order":        "6a8368e2e86ee176535eb6ae612eb607c7466e4c6c76803a10309959807ba908",
	"link_remove":       "cfb27ddc19bb23b23c053904216aeb0b4c5e239f2ea15718486071eb9d458c0d",
	"link_tree":         "cb940bf291dc2dbc512a450ec96de45ab2b86069e9fd108dcc723fc2a18bfb85",
	"sec_filter_add":    "3a0f5334bc868a6ead8be7d90a721c4f10594f6a7458cabccf4aa65508074715",
	"sec_filter_remove": "245db3af3f7ebc4dea2f306c1dee46a199c71a47ad32b3de01b778815d6cb63a",
	"status":            "9a1e36178b2761dcf5ea4b3529045d896722140b02d769da3ba441acf07b08b2",
	"wmi_filters":       "1542484443a1ddf13541972cf8a4d1fb111f3a7dd3707807911877c178a32da4",
	"wmi_set":           "a611104b2172dcee0bbcb31ad69ce679187f33cfa7c2ba03c33ad3d4b9313cd4",
}

func pin(name string) string { return pins[name] }
