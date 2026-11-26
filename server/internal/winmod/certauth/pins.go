package certauth

// pins are the SHA-256 of each action's assembled script (see Script).
var pins = map[string]string{
	"activity": "92cd3a2a53f912b42f8e699bfcf4d9ee949eec19f5e755442efdb6ed0dd9f942",
	"ca_certificate": "e3cc3eefcfee249fd60934e66635b5b516d1a6f9eda079c1d6670c48b8061cb5",
	"ca_findings": "7471a6d025a8a5943b041d9acf4833b1b2da208170fffca7c355a0e3d43d757f",
	"certificate_revoke": "104f84fa70d66997dfb2091a3db77aaa7decb369ead5601b27735d943ec681e7",
	"certificate_unrevoke": "04d6babf414597d0815b37bbed64062c88c7ed939bb5c4d50c4a341c46a1701c",
	"crl_publish": "e206963d26da0ae1a7afce7e24d17d3c36e1fc2e2ff65a1ee703541778fd666e",
	"crl_status": "d4da5c29341df6ada888a5820dc04e8363dc355011c6be30c4073e79d9d069c4",
	"request_approve": "67eee858ab1037951c8350dcfe6a3033ef621d7628fd8ed2c80cf9f96e2cef36",
	"request_deny": "3fa0fa397b616493f6f1783667254a8a3f79f3215df625fcdc48befa0fb84725",
	"request_get": "efda694ed2f82fa843daeef54717e8ae0fec34be17dc7df24a7d80c98d6f0b50",
	"requests_list": "852fe9f30f471e5967942dd2cb0bfa632172832e625dad8162eb4b93770fb397",
	"requests_pending": "ccf060f4df2918d80976749b014a50f0fd340d6d746030fb267d483b91a5f803",
	"status": "74f27f433ff02e6c8ed26feec344a30ceb6cd9d53ec8926ada2acd9935d6bc37",
	"template_available": "b387e6484c9948086ccda88b568af2f3f4dbb61f21f0b176b6db4169054aa4c9",
	"template_list": "fcc230f7a7c9097a8130d61bc72f1a18dd8229181242ae2b99a13d6df365399e",
	"template_publish": "1b51ea6941b34c42925cb04047a0f3c43e042b57f4d63d5253265daf384cfd96",
	"template_publish_risky": "ff2998d3fa924b33f9b34d1622551c04fd8b704474cd9e045af11ef5d6b2bce9",
	"template_unpublish": "9533f5577ec5eab6c5aebcf37dbc06a9d54fa188c90e5a52cdf992d801d75b14",
}
