package printsrv

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"driver_add":               "77c3247f39cb19837cca521f18dbbf62d8b4d263ec82df7b1f0c53196e6d02fe",
	"driver_list":              "26b36209cc7c20e8acea369a28b917eaa0e9b7626f0a212fe6a9b3680e36625b",
	"driver_remove":            "aace5a207f6208d295ab698e14cbc2f417b170f92624b9ba270c0b2772cdd002",
	"hardening_status":         "48cca740b1e3b2db41a0dcb85508659a8ab6dbd7009b4695173f9082163a3758",
	"job_cancel":               "2e3c5e084e3cb2150dd35c1c5420a6f90c8d17e8d92e576eaff8eca0a35b7d19",
	"job_list":                 "9be0876cdbdcf5f1c05d7a6de0c2f703ad54fddc92bc47762193bd1a9864ee1b",
	"job_list_sensitive":       "473673be9a6648d1b962cbd6106d60e297f65d7473b785bcc5462a7ec161e16f",
	"job_pause":                "9d3fd605bd9ef45045982929ed8fa64413f237b0a893d32bc091bd4c362ed6d9",
	"job_restart":              "c2d610f78cdaffcd253cfa6b6f37fa275186344f6cf9007d1b1c264e14f8f363",
	"job_resume":               "fead680f84adf880b0e46a871aacb8c6b99dbbc871dc81b406314dfff8fc6ddb",
	"point_and_print_restrict": "9edd42998cff6714d2569f90feedace4e04ee3bd75e9a1b7db2078cc34315e76",
	"port_add":                 "38e4a85bcdf1f2e5825882b1b30d3541953e49442dc7af41a37b9970fdf12b8a",
	"port_list":                "6ba6038273574782cedc503672cbe5c3fe3ee79ca5e3d32d14905c1049a99181",
	"port_remove":              "c96d29e31d9503d460bbb565f5fb36cd3d62d5d07af3ac53892ee54960ec7f24",
	"printer_add":              "fa318845da156f8e02a48490bd7de6d0f7bd1c33c25cde3eaf1dc3cb1fa042e8",
	"printer_list":             "ad59256a4f68f87d65e95677645e3a66b7a20908a328ba4d0daa93728f20a55d",
	"printer_pause":            "30126fc418b31dd28f87e4a85a224e14dab30f50621b7a91c877d8437c54239b",
	"printer_remove":           "169a4348c284f17fdd3e87c89c3615d47c7d9ec863555d8fc41cad7965d931c1",
	"printer_resume":           "492b42f943efa99a2593023e5cb54af7ab4a8d2c73c1def8c18eb1e9c3a46018",
	"printer_set":              "2615623ef6b2c741dc3ec83ae160652e39be8629669be5cfa0f654a4e1c3d92f",
	"queue_clear":              "701be41e4f322b6fc4d240f1818dcce26db0a16ec43215cd362a3c02c5ab5879",
	"spooler_restart":          "36e02fb3efaf0df93fce35cafd5f45fa43a95bfd01c1fcffea20b34dc8919d0a",
	"status":                   "16649c47e3e12f7d54bc9edf495fb7a52777671cc117217f6f55412a886c39f9",
}
