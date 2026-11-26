package activedirectory

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"group_add_member":    "147f7a7b1eb4664d39b5994ca8520addd7e7abd96aba1fbddb624197f4e42c2a",
	"group_create":        "d26b21e4353560ea2c09d0a6391332bf053301c1c4cb3e26cd0a8d7d83a85cb5",
	"group_delete":        "4b21b794a3d4e224111781bcbeb4264fc24327f5af8037231da548b009fa87f1",
	"group_list":          "a9979522d9b17fe08c949e5569ab540db5cc57547544e1c134b4af5cb6b7f29b",
	"group_members":       "e7db499988afa483c3490e11cffbee618cff3bfda7ec587adfabfbf5ccf65410",
	"group_remove_member": "4f104e41d2db947a368652d731940e5f8203e72eabc79b64443312e99370e7be",
	"health_read":         "808700d19cf07118e7141985cb522332cb7c3e092e7009b989ca65c3c9d4b4a2",
	"ou_tree":             "01c2531130715e01a12bcb5b1b58f7630b48123600c8f806ef2c786925fda2bc",
	"status":              "7f6b887a3e8ad9f35e299a52d25137277091b78ea38e5acb6c5670f13153f827",
	"user_create":         "5d536c7c7690184e3a7610a1527ddbeb0a26ad53d62308e57692e0920ed2a655",
	"user_delete":         "ac985d6ec0331ccddbea62f5b1f67297c5e21ad678425d4c236d8460f1e877fe",
	"user_disable":        "d8c882c27e848ecde36818c088231bc96a7912417fc3ebc90741aaa472794e7b",
	"user_enable":         "1b15fb0f6d5d5108d39ff18d9080974a3795c282fe16bd03be395c04fa4bc564",
	"user_get":            "7ab4ad9cd8ddcfd70f4a3742f0d1464e60845c02d9a6f4672a9a3f2e19591601",
	"user_list":           "1b72bef04a9550c269ec98d526ea2697db579a2c77503b23180113313a706380",
	"user_move":           "7fa79f5c884aeb1011b3d9245804fc5b8fd5bdd9d9b843404033ff28e636f2f8",
	"user_reset":          "efc060c48372ff01a9469ec550b7b5b24b723911bd37dde259ea12a14be5d0c4",
	"user_set":            "1527e726c912c956036e329da7eab312cf702b266ce0b639a599d67dda8b589e",
	"user_unlock":         "7a574526ed8f1a19b7bb40b69cd798aad1ecc0b6078ec1d34e5c866835c58468",
}

func pin(name string) string { return pins[name] }
