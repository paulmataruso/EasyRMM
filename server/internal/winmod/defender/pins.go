package defender

// scriptPins are the pinned SHA-256 hashes of the catalog's scripts. Changing a script means changing its line here, in review;
// a test and the catalog's build check them.
var scriptPins = map[string]string{
	"asr_read":           "e375d0251ee13db928738cef941f86fd276a3973572e4a12c2a03166d2988b51",
	"asr_set":            "c3eb49d5451a881e92f25d856679698032ad7cccbfd4da7af357a5ec95a0ff94",
	"asr_weaken":         "65a56ece876fc121d8aafa48e981c81ee7f1adc469e5ac39055d680d1def8940",
	"cfa_app_add":        "26f8de654bb630b3085670128c0a41ab687d1040b1cf60ab80940409dcd168f3",
	"cfa_app_remove":     "e26da307fae0e03fbd27a47a281f0ac3a758baa9882a9c507865e67a12a43719",
	"cfa_folder_add":     "51064d32461e5d5011fe98852c8cee1886ee951cd248043af55b0343a2654d44",
	"cfa_folder_remove":  "01a9fa8ae5effc8f5bf115bcc1c28e4a5e9f1ad74e94befcc1ff2af35890411c",
	"cfa_read":           "0c81fdbfb279ce86ea1458fde2c32cd6d3f4cfd7851fdc215c480eeaddc1108a",
	"cfa_set":            "ed19f40034ef0df0d07a7735218d8968e9d78ea70bd14e4164a3ea71baf0ba37",
	"cfa_weaken":         "427140f91359a044661f244e423af765e80f6f996f32cbad99c49393aae792f5",
	"exclusion_add":      "8357cc6f8b3a27cf648105ed910d6802ad433d0057228b4d7a21f757a2f41b6a",
	"exclusion_remove":   "40c68d8d7863286226ec4ee13bbb81870e65a37da081ba6ac32f00e5f0c881c9",
	"exclusions_read":    "37ae8a3062b4dc871c865236fc487e5d8c3812b38ebfaa766371b70e482a4385",
	"preferences_read":   "a8c50319ff2ec454ebd4216d79723f2ce92a42a1df0ab3e8a28de1fbb07ba68b",
	"preferences_set":    "5484adf8690341a53b2b21b269034a450df63b53440238976e15fe55ac6fc73f",
	"preferences_weaken": "5484adf8690341a53b2b21b269034a450df63b53440238976e15fe55ac6fc73f",
	"quarantine_read":    "b8b4618c04a358b5a171e7f8f6b6180f30e89f395826ef276410126269036931",
	"quarantine_restore": "7a4f3fa951a0a3f51974a9e29552c200227482f29812bc6b5eb4e8e47e80dfb1",
	"scan_cancel":        "3a54874d3f3f1c3ebad47f5e54cfffaf9ada57b1dcab84a429a26ce66985c5e7",
	"scan_custom":        "6db026e1e9d37bc5cb48d71b41c4df6fb62e434886656167254a335e4d51ee46",
	"scan_full":          "52d52868aaf7d6a2c054af351db29895ba6580b0ebea1d86cf5dc546c4ad2476",
	"scan_quick":         "74b20eb371fbb0c5e7aa71c5c0d4cc669baefdd9b5f6c776a1deb76e25241b13",
	"signatures_update":  "31538a324fe012e551044d3c3f49ed6ad77541781f3ee1ec584605a2570f00ec",
	"status":             "ece7a930a128e323d61d1eb05b6ee75f5730931aaccdcfbccbf33eeb4169f9cc",
	"threats_read":       "c0702f5ce987d4992341a4063b377dca598d73dd4b80133513ef71d12ac253cc",
	"threats_remove":     "d70eef2a7637f8ecd75ff732b82a247b9a46ea5631df575357b9637c1dd482d2",
}
