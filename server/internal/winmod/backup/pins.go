package backup

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"disks":                   "2dd8bbce9a2c93bb1e01df89645b5eba24afc45151e5eb0191253212941a1628",
	"feature_install":         "c2a2f689de2283fc59335dfc385eab58f8c4eb6d3f172477dde152854932eb08",
	"job":                     "4ee56c4f4e444de54addaebcae8068788289c407506ce6ea6d60bc5018ed0f5f",
	"policy_remove":           "a9518121dbdf6f03a2187fd5792a8c94ba60d81a8aed41bb5c25a8b71b75399c",
	"policy_set":              "d961d62fe5a7f0cb6cf27f11ec45ad126b19408cfbba43fb954bc97b8399211d",
	"restore_files":           "295821ff6278d13dc05f9be8523bfe1565ad1956b24ef5e0dd7df822f31d5abf",
	"restore_files_overwrite": "95cef2663bda5855b6676e2ca63d1a2cce95b7f4a61decff4f955f41c8969237",
	"run_now":                 "333b592035035a3dae5003c181dff6b4f5e05d9fa3c6821692038703d8f4d1ba",
	"sensitive":               "69428cae11e97dcf1c8e331d63f94bcff0e1c967e9b4a3725dafaf65219ebad8",
	"status":                  "9b5ca5191d567c6f635f68bf1310dc2d53b8c4086ea820a773e6d6373541401e",
	"stop":                    "56d1a9c03a350066e700a6788c79791155b8196c02cf493746245aba9f4b0917",
	"stop_recovery":           "4d13c0f22385c47f523d8698d6df6fc7d384fa20ca91046f49f2ca9ed5daa8d0",
	"target_disk_set":         "a84210fb3c6da72bf392bb02d34a5a8ea844c0594ed4c8067687e4961df44865",
	"target_network_set":      "ef47d3604302d3e552b023950c6b7eb1f64fd011a59c251b98bf40bebe8b7dc2",
	"target_volume_set":       "61149e28773447238da5664db98744b95190c8804d36aff39c4930de51f868e3",
	"versions":                "ef0e623bb8800d692baff0b2fcf6a9c4071e28fca8a1ea5783fafe7d27832a95",
	"versions_prune":          "6edc6afa0ab8a14f7178f09d4b626767344e6db8ba132f0e5c8c71fe5118d5dd",
	"versions_prune_preview":  "64d9c5a05cbae77100a1ef86dc1003d87ba0e5ed33004439c7a25042f4cd51a5",
	"vss_full_set":            "d17bdb1f90ec19694c06814f86b11c6c97cdba48c0804b81165c1218b5b569a6",
}
