package printsrv

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"driver_add":               "fecc48d9e72d9e515ef8c49fe9c13d5cc34a6a452de3a0afc96ecdfa7ce875c0",
	"driver_list":              "207a8fb97a8afa451f6abc7a8f4501c79ba34f9cbcfb78501fead39e62ac11c0",
	"driver_remove":            "737bdfad1ebd6bfe4c7ef4daca7a08fd0786de34eae2f1fb7e8f309523f3051d",
	"hardening_status":         "0f516df64ea120dba0b35dca801a4fe5d13800d35aa899ef41f658bba6a79902",
	"job_cancel":               "57adec9e177cbc35967e30e3d51e1504a346b79dfd92229a2e92060d04e8e4ce",
	"job_list":                 "af36b77670dec1f758e1f3b7c7bd3767c961549bf0640ad5d91ad77b834063fd",
	"job_list_sensitive":       "e08169064d391e1719d7773801a1b25fc9f9faf1e87fb4a7e87c5bf47e594f49",
	"job_pause":                "e0a3b0b1d44920e3ca6d1bae41bcd41ff65a485ae1e95717e578fff9ae93e4f6",
	"job_restart":              "38e29af91ff06a0325a772f49bcecef68b147949d7f70b38ee8f41aa3d603827",
	"job_resume":               "b6eb883dcc098fef0e4004d254e14c59ad63aa03ff5107fbcfe142ca67f7d90f",
	"point_and_print_restrict": "c72024e6f44a4eb72e33e67c1c17db40c979453d717dcef0cf5d51e706082837",
	"port_add":                 "3f78ee5db362602aa28ee8b00afa17fce22009c46ae8c21d8fc37124dd240a7b",
	"port_list":                "c4bb863dbd271238aeaa47a98e17e331c0444582185ce86824ec088819287820",
	"port_remove":              "7664b153b026554fff9b0e27c36a3d22bcee7390332a272f37dd503581039978",
	"printer_add":              "37c3973e8cba6bac017c90d5e1d596cbe1ce2f691c8dcd28094c069fee79fb43",
	"printer_list":             "2976ce3175f85e5e95546f744bfcbaae50ad5bf39327c2e243956bf69eda4394",
	"printer_pause":            "9fc6d0881e35ab3e8435ecf441d87f8d7888ce83907058f6a2608a7d46de974b",
	"printer_remove":           "a856dde33499f16bb735838a9924392361c49857462a7929088c280b945c7a46",
	"printer_resume":           "a0a3f14d49898a0e87c7664559edb26a4fdaac36626a4092b4b6759c57a9ef29",
	"printer_set":              "e076604b81abd974ebb6c44ff0aa782cb2b08fbf7362911054b378d09508ce69",
	"queue_clear":              "7cff365127c3cf67d89a3eb301c5b3d0329fecccbce6fb8b10504558349a2d00",
	"spooler_restart":          "1c3660bc6a20f7734001ce618030792e078ef99521bd22f6bee0a97366fdbcf7",
	"status":                   "029be451a2f9944b88d0344b7278d2cc89c5a2d934f77a1ba5358a8ae838783e",
}
