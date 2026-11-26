package dhcp

// pins are the SHA-256 of each embedded script (ADR-0073). Changing a script means changing its
// line here in the same reviewed change; a test and the catalog build check them.
var pins = map[string]string{
	"exclusion_add":        "ca4ab6fae3c5e9567aaa78fdb630ce18e674aaf5055a2e99a6c8f4b6230a8b45",
	"exclusion_list":       "58fc854c23bb7b1cf012017f03327c2eb214dc1d44c50d576db12a637dc7ca63",
	"exclusion_remove":     "e06a09d787b1fb16ae530d299432df6d232f9efb8d8eb815fea200bc0f6c4437",
	"lease_list":           "e82161c8662e20e36cffe5667381e064ff1e860730533cab9cc50b8e77890421",
	"lease_remove":         "d9b473752f8438eb69ebd3d13173fb3e24e017f52c868246c5212a66ce8aeabf",
	"lease_to_reservation": "153b2ef20da6adde8332fc90c2547b48cdca4eeb9aa22d8594c9215280be2360",
	"option_list":          "5c98306eb839c33b66ba7d82509adfa8efd8dd743d5b3a7225914aa2b5947f1d",
	"option_set":           "7a84ba70cad6fca52fd5f9fbb31a051eccd7d46dc973b59ec2f162a0b9e9603b",
	"option_set_network":   "f9b77e6c42e11a6d6fdfa65455d18264eb98ad9efe4bc21cab4a3f214e85bb20",
	"reservation_add":      "0ede08d0c4ab8e6cd257f5b61d761438409ce0abeda0228fef80e33d332baaa4",
	"reservation_list":     "d02703a96b1111c42016bc989252b3bc01400c896fda3c707ef1f0211f7fc4ab",
	"reservation_remove":   "428a80c1971292cf29842f004963c2dfd0e91e442d44d3788a053a622679f706",
	"reservation_set":      "1b7b31b31199f596f4428d437e025beba4c01d2f18f914b82159bd84ed819f5d",
	"scope_activate":       "0c3d0f055d8a789438e7ba118c7abb166af829a2c2783152074f3721ca8fbd72",
	"scope_create":         "6202f27ae5416786177901c6f26b03c5fcea8b5f0e0ca331e0b8015d104e5973",
	"scope_deactivate":     "114785ec77f9776d6b064bf3fc720c5b3dda724f8d03eb5015fb05f888eadf0e",
	"scope_get":            "c518a9f756d0da882ed708cb3bdeac417e8e500f9ee695904019ebffdcd4e858",
	"scope_list":           "bf6f3e3da6044bb1d64bd456fa094368225caf277ef0b921178e3eed6f9e4a00",
	"scope_range_set":      "aaacc452ee1280e6108b9050976be4c7e61362e434672b8a0899db71dcd784a2",
	"scope_remove":         "a89f84623a810d6003d65161ff0ed679cd8912c39f4df59ae791d6fce7233244",
	"scope_set":            "c5ed4777342f14404ce0891197babef866f1f74c78f17d29fa1fe29ca95e6e0f",
	"status":               "38c41af18a1bc4b5e835a71058b303f40339f867e65f8860fae5acc01fcce41b",
}
