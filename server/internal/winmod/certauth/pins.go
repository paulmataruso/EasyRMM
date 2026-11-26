package certauth

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"activity":               "10c8587dafb64391cf2668ad77267f7fd8dcd0773b6abf97c4e11aba0618b38e",
	"ca_certificate":         "9ce544e232388fb245f1e2c295edf46039ba46718c8252d156aea5cf5db532ff",
	"ca_findings":            "fb3837d452f31f7843cd5cb6d40b96278c00e520c73f4eaef1bc4c5baacf83b1",
	"certificate_revoke":     "a8022f11bb5e42c2313e89edf230d8a831f165a4a17ea180bdbc543cbfbdc599",
	"certificate_unrevoke":   "44a7fe040a754b91c3bd677d4b6cc86b45a195dc2df4b32294f0507f24bf46e1",
	"crl_publish":            "789ed7cdc884300ccf6a784aa652926ae5d0594e1530e111a6e4fc7ca525a2ec",
	"crl_status":             "efb7e8a2d70a370e7d68887fa8cfc358f259cae448e72f15933791fb8a39db38",
	"request_approve":        "8e853db1ff472fa90e4d722f2d42e32f98e92a087f08d01419f1aee2b9aeb34e",
	"request_deny":           "29c566a22bf3c7a86f1b5a4e4e3bba0c1178f3dbf2f30b15dab0f1bf82cc28a2",
	"request_get":            "8074ecda07c71fb98d06a2264e0b6cfe097abe726963a39882e2128fe5f7ad83",
	"requests_list":          "446ffa9d0e1917d4bfcd4a2850a85e66418bd6b6a1611f3a9e05460d092ceca4",
	"requests_pending":       "21f12b790934b2fb8c7e6804573b12d0f34f39e26259e27141fd67b383611a90",
	"status":                 "f622a517bb3c7d7b5c5f418a15f0f44e037f42ea694b4e76989621c23e577af1",
	"template_available":     "dd02511bc5948bfe98144dd20137ef87ddadef6433dba74265a64654a8067601",
	"template_list":          "b4189fc365bc72a0ecd36b434ad4da3279a3ef2068565d1587d168cb21be187d",
	"template_publish":       "8b930ea086cd977152aee3a359939c530e6f675242e5172df3141690b01bde7a",
	"template_publish_risky": "832ea5de2f8a68fbfc5b26183c949e8c0286c1176f403095ade7864144a5efc3",
	"template_unpublish":     "0f3a2e84d1e6e7d34014863f70f6a71e9f4894d77ae945fb9bd943be31b884d4",
}
