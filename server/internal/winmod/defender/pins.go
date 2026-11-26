package defender

// scriptPins are the pinned SHA-256 hashes of the catalog's scripts. Changing a script means changing its line here, in review;
// a test and the catalog's build check them.
var scriptPins = map[string]string{
	"asr_read":           "2197a723a3df4f88b7d7cfea520c49b44cadd95302756e5cb314a741b1364d20",
	"asr_set":            "65a95046d104c0fca63fb5aa75ac7db48581ca7cbb1d43c8106e631643d7cdb8",
	"asr_weaken":         "d96fc78cfe0e79ce35096f72ba2dc87461aa14fe5e1af6a2a6df50153eee7cfa",
	"cfa_app_add":        "67d60f1a6b32698b664974a7fc681ae53689fa9d13bed8b79dba2002321894a3",
	"cfa_app_remove":     "73647c2978dc7c0337ab056503830c70c53f971d21c5ff95d5ff7a8ca60bd418",
	"cfa_folder_add":     "f354acc12a8f5b5efca2b83e9eb0bca202b29663a747bf804bb1146b5a64fcd1",
	"cfa_folder_remove":  "347cb4ebfbb84d358376a013e37cf07bf80bc6d55bed0b83ad8731d7baa6b870",
	"cfa_read":           "7da66be70ec6c4f9032f87959d057a6c7f359d3857fd85e2ff6cf01369377b51",
	"cfa_set":            "96c274996989e53299ab50721833cb8d2c96eb8d7a944c7c4f74152605405419",
	"cfa_weaken":         "7789c85cc7784e6a098cb0f24b8f07cb13b8640a527e3e7eed361a2ec1ccd8e8",
	"exclusion_add":      "cb355b7dbdfdbf7db4c44ddcea0d5d3a226560bf32a891676e3f5194f47fac16",
	"exclusion_remove":   "f8be31590cd5c870c13b72482ac613dfa4c9bd4c6978c768dad3d1e483c340d2",
	"exclusions_read":    "a4b4c48798be045fa9a97fbfcbd536fdbc2349945a163199d6cceb7a471f9b8f",
	"preferences_read":   "bda4c70037a610e010731944c21d11e8a7d158b7e99ff2586902e016e227c96a",
	"preferences_set":    "5d788d952790121b00a2b09e8e5726ef13336cb5f29d954aaa078a38a67246e5",
	"preferences_weaken": "5d788d952790121b00a2b09e8e5726ef13336cb5f29d954aaa078a38a67246e5",
	"quarantine_read":    "ad23741c9d921aef76eaa4a09adc488ad6d464144f8f0e78a6acc4777abedcee",
	"quarantine_restore": "76351360024d16823029da725971e34cd9a1d0b7df3687b45176d8e254c30ae7",
	"scan_cancel":        "35faea7c1b13879cf57213184059d71607b85bf6bc796f6d55cad1e74bccd3b9",
	"scan_custom":        "a8426518387c9978b4a8b1986d2a94f2382f3a9d72c381cae03ee6d2d32dac08",
	"scan_full":          "32f8361069315cf5b2aae35114c8b6b64d8dcbcd2940a48b8cf8b4958a869fb6",
	"scan_quick":         "e6e4f484b6a88fe04ca345526b990377a780aa958512a3970b7b7c4eb2e24675",
	"signatures_update":  "0c40f2990032836db624cd1b8a09921ec07b7db2ea846acafe8fb4810d2a3b51",
	"status":             "fcbc0fd4d138da91ab1604a2d018da09cf025486e362468bc19749a2b2653d6b",
	"threats_read":       "a6072976b0fa4e72298f65e0dba407e29d6cc576acd469b393460168ada7c28d",
	"threats_remove":     "91788cedba69e43edae59eb64d7799602c8693b062ae166caf8ddf8c1016a4c2",
}
