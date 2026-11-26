package fileshares

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"openfile_close":  "448a0c117c89983a427aad82a1d6e0e353d680517c911a491504765e93a931b0",
	"openfile_list":   "6495ec9cd43890585282cb1462bad83da401ef94843030b57b6a387992e1eb93",
	"session_close":   "ed9dfe1f86adbd148f0a958cca36fefd91bbcaf34fb749eb7685990c8cb2de1d",
	"session_list":    "c9ebfd50ea78d10759086f641b52d20948777d7dd9a64e581b1faf9912585b7b",
	"share_block":     "b1f9b9dff8aeba2c8dedfd816f590381d83f3fa9466335ec489b018832dbbc9e",
	"share_create":    "ad8b5549d163996134c6b33d556b77df458ce9480e9aa7c0475a37dfaf166352",
	"share_grant":     "dc488bccd2b137d17168967dd7ca8bd1064f287cf76100ce9f1eec3ef82d5a2c",
	"share_list":      "eb2cf335fbe718e19328d5bd93259d7ba8a98cce805258e8ce5dc72867a3e5fa",
	"share_perms_get": "28d4254333705651dd1e80f8a284207e62aa253c5c307ebcb7905b03e7fdbf82",
	"share_remove":    "d86e5537483d4ac7d40aa35d959e254d54406994c176e006e3c53d90a47f2240",
	"share_revoke":    "6fc7b20bdc36228cab8801a6fb8962cda191f905a8960e7a8e78413cf6d02595",
	"share_set":       "a039dea89acdc45ec17d03d9a9764784a9c9a1391a857417b3ce697b76b894da",
	"share_unblock":   "cca78bbda67580fe03ec50fdf814279e2ae5f18a67aa4b01c23b1e531ac9faba",
	"status":          "91207ec434c6380b7d67ab81cc8530bf32aec023e500a0f1a0a5b9f409ee38e1",
}
