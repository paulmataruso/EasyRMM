package grouppolicy

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"gpo_backup":        "79b6b3995b32c5aac18c4a5c3ab08cf8f37887e79445112f1a6b81b50fbcaa3d",
	"gpo_copy":          "7f63d8c34818ef40637f30115ef388206063471057b1f1f1f52297856878c4fa",
	"gpo_create":        "9eaa906055790a8973a2fe2bc641f151c60ae3c875a32d75171b541bc5322fd0",
	"gpo_delete":        "8a9427aba424af30608c0371305e7a2c761239b0a2e9d89a2aae4b53722a0f63",
	"gpo_get":           "39351c3bb64e9c0ab8c04166b0fbaa06aac2596307ec4e11fe77c41c0a06b300",
	"gpo_list":          "bb5c656f0ac54c22e45f9b991c47191f6be43c30664a481292073172b8731f0d",
	"gpo_rename":        "a49afd930599a9fc2220d999a95c96c198203849bd004c4bdf42e1042e23441f",
	"gpo_report":        "8182563778dbcc06ab3f9668f923bf9612a3d6669d35365308c7bad415239314",
	"gpo_restore":       "778f1fc40074dd9353a5fb78e4e985e13f54480c9f5572c266f16e1da4069495",
	"gpo_restore_stage": "d0824847dc2fd0226bb65e1b0fe5dcc657a29ea0b9bd75c1191ad57a58b0a7f7",
	"gpo_status":        "5294c13b7a4f4e950fe04be03b3e087cd7a1a05038287034a39c5bbf5676447d",
	"inheritance_block": "e7e52a214e67a0dfa637018f5ee577fc1294957f359575aa10d15a7e0bc7e31c",
	"link_add":          "8201bbf215bb92507dea51939d3b5e5ecd44828c2cfd49dc2fc2244d026f0979",
	"link_enabled":      "fc1e37eb6fcdb7c6de2280eb34b0ce96896aa22e7876333524c19b794823767c",
	"link_enforced":     "de34adc4de9c319c5c43f8529c48793d61483271033994cbee27d1baf0b4926d",
	"link_order":        "10c22d026cf351d31c43ac1f4b60e59e2e38d4560d1761edc9aad3ded86320d5",
	"link_remove":       "246fdb72159fe4ec315718cb0dec83b2be2e8f627a17c40e985cf5424a7c900e",
	"link_tree":         "13d591c33d73c1a8a09df99b1d84ee3a599154f64c44f60c83505d6de1a5eecd",
	"sec_filter_add":    "a2217ed3dd25b5d26c856eae68b8aa90b547556e94e4c94fd0a630faa3555833",
	"sec_filter_remove": "1680b1a79ae8e805f59ef9f8f8ad418a95e100f28ed948107441061b1eab6ed8",
	"status":            "e1bd2859440c32caaacc1c035810fd7f60bd13d78240cb9713239d064b03447d",
	"wmi_filters":       "c733a6fdaf6476c8752d501759f5b886a0e6811eced5a9ee58a5243c25e781e6",
	"wmi_set":           "a66ad690c6222225c0921f416c1c7a4e6c0c8145352f540c81f9b59c6531e9d9",
}

func pin(name string) string { return pins[name] }
