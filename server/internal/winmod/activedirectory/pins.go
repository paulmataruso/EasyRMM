package activedirectory

// pins are the SHA-256 of each embedded script, written by gen.sh and reviewed with the script: a changed
// script is a changed line.
var pins = map[string]string{ //nolint:gosec // SHA-256 of scripts, not credentials
	"computer_disable":    "76b60ab2b129ab992e1eb85d4551e45fd727b407e53df29dfd8672d8c89bac1d",
	"computer_list":       "0add05953cf6c84245e1ac15eec1d230d419dd61086283ac11335d638acebd8b",
	"group_add_member":    "8bfb4f2c0a9bf6be1486ad651286f09f388d071706ea812361531e096cfcdeda",
	"group_create":        "299817ac2b0ae1e77169e6b63915153b9be2049f47ee18306372cf629a938a7c",
	"group_delete":        "d319fe93377759e4eaa1d6f5c4c90b2e9806d0184e9bba58d3429e73b1de6f8d",
	"group_list":          "f3bdc38bd80859b9c5b8cf1b2a3a1464ab5aac72d3b63a4cfd26dbe87b02d779",
	"group_members":       "e7db499988afa483c3490e11cffbee618cff3bfda7ec587adfabfbf5ccf65410",
	"group_remove_member": "f4ad9d55d3b08f0ef2fe3a57fba9afda3a8e74eef76202d232aff9c6390684fb",
	"health_read":         "8b0e55091d86dcc852304a8a28d5a87aadb9b47caaed9616f772c1195db33712",
	"ou_tree":             "01c2531130715e01a12bcb5b1b58f7630b48123600c8f806ef2c786925fda2bc",
	"privileged_members":  "277de587b4a417395d842145fc19aa1d727a49ce2fe0ce5882263f03c16ea4c3",
	"status":              "7f6b887a3e8ad9f35e299a52d25137277091b78ea38e5acb6c5670f13153f827",
	"user_create":         "6bdcc6443f16e26c8ddff330a69c8c2464223d337932217fa1da47c91a3a5267",
	"user_delete":         "6a727e8ba4060d8d5540e0fd0dd5ad7e70d6047840010373b0a8125d15db5256",
	"user_disable":        "47a246b873ca25dc6a10196b9a859f77c91ec84761866896ff240999b46b3353",
	"user_enable":         "4e268b95e3deb36531a8297b313640080b2fc5f5cb33778d974a19ed25e9b708",
	"user_get":            "d304b25fe82207940a82a74cb6828d89e41a397d4be322712485b6f0fc762616",
	"user_list":           "a4a2d222be8d36b64bbb835f2e4838dd81cb8ffc20fbf62d8041ae0e136f83dc",
	"user_move":           "972db71ff863746d9621a93eb89dce8f3dfb5a3885bd29ee58624d5e7580d906",
	"user_reset":          "515e2e0bac1083803be6b554291107c26258e553229007aef22352de2285375a",
	"user_set":            "fb0e63de68e8a3ea422d5ccd22e6720688881b4d1602a68819893c2d2e5c1d7e",
	"user_unlock":         "e220ee0cbfc1a034ec486a1fb9a85b05c2cebe106a132305f1e77670a8550fb8",
}

func pin(name string) string { return pins[name] }
