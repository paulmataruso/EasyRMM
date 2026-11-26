package backup

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"disks":                   "10ced7003d5882401d3758efbf647b1b10c02ed7e7bdb0aa077bff546bfa36c3",
	"feature_install":         "f768edd5b186831a65bd7202cd33a4948bbabb857321c5b2c6673dc50439e1d7",
	"job":                     "688d05dc190bcbffb8ff3db8552513ec954bf72244dfe6830653aeae90a49902",
	"policy_remove":           "30d6a42ccfb15b721f4cec6aae863e7ea5cfd6b854e1b4c58ae07cd924d8a579",
	"policy_set":              "bcca797e3439c94444a1b51dd261e20645a5530852a54cbed3bf5e143286feb8",
	"restore_files":           "1fe257599a9f2f8111f501a614e069010526348d93780e87089e39fba319c174",
	"restore_files_overwrite": "0543d5949f6ad465f9501e4828b6c50257c386e7b318e4277cf0ae3fc4a37102",
	"run_now":                 "52e6621b9d4d224c386d50b813f26d3a114948d715b4697aad2616d183058add",
	"sensitive":               "18e18666de81c187f7760c35d020b5f7662fa433a505488a82b24a24c28b07c0",
	"status":                  "9032e11e5bd18cd2392ade9b2bb2807ce1e835cd75f4159764d86d16f9cfbdff",
	"stop":                    "a376bd3ecbc35276b4de41c7dc46d701dff871efeaafd7d96b1c412062c00d93",
	"stop_recovery":           "29b64d8d836338a6ddde4c0a4e0575cec23de00f164265ac77c501197da6b536",
	"target_disk_set":         "ae4a615212cb911afdab245d9ba7e97d6daf20522c023d7abe70927249bd9252",
	"target_network_set":      "393fd1757c8322d3ac552639c43baf887b177632060e12260dc823be7fd1c84e",
	"target_volume_set":       "6eb30e6b50dcee8addb08bf52af20339befeffba444aa9a7ac852dea4ddc37ef",
	"versions":                "3242445aa269a306237083ffa78809bc7bfbc432e4ceb0fe29ee6732f5b9fc90",
	"versions_prune":          "cf27cf97dd60369c81f8fd9a32c913c33532eb9c6f840b30b86544e832ebf703",
	"versions_prune_preview":  "341bf93cb1503757d33945b2225371cf5273a1f304febf113dc0e1cd94eb1e25",
	"vss_full_set":            "c567a14b15c8f74ace75a31a15a41db36b27d335579fbf90bbe64e251a1cbedd",
}
