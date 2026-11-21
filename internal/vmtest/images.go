package vmtest

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
)

// An Image is a distribution's official cloud image for amd64, pinned by
// the digest its vendor's checksum file gives.
type Image struct {
	// Name is how tests and EASYRMM_VM_IMAGE name it.
	Name string
	// URLs are tried in order: where the vendor publishes the file, then
	// where the same file moves when the release is superseded.
	URLs []string
	// Digest is "sha256:" or "sha512:" and the hex digest from the
	// vendor's checksum file. Debian publishes SHA-512 sums only.
	Digest string
	// Seed is how the image's cloud-init gets its NoCloud seed: over HTTP,
	// named in the SMBIOS serial number as "ds=nocloud" (cloud-init 24.4
	// and later take it; "nocloud-net" is deprecated there) or
	// "ds=nocloud-net" (22.4); or SeedISO where neither works.
	Seed string
}

// SeedISO is the Seed of images whose cloud-init takes an HTTP seed's name
// from the kernel command line only, as 23.4 does: a CD-ROM labeled
// cidata, built with xorriso.
const SeedISO = "iso"

// images are the releases the harness boots. Dated or versioned files only,
// never "latest", so that a pin stays valid. When updating one, take the
// digest from the checksum file named in its comment (and check that file's
// signature where the vendor signs it), never from the downloaded image.
var images = []Image{
	{
		// https://cloud.debian.org/images/cloud/bookworm/20261117-2665/SHA512SUMS
		// (cloud-init 22.4.2, from the image's .json beside it).
		Name:   "debian-12",
		URLs:   []string{"https://cloud.debian.org/images/cloud/bookworm/20261117-2665/debian-12-genericcloud-amd64-20261117-2665.qcow2"},
		Digest: "sha512:946b917a37882f16e5b3b0b2cbe5744637d0cd36190b5b53cbb21d14a54557d5b45e9e523021b8f52c1707dbe470489f3515458e0680ded76ee2574b4a8daf1b",
		Seed:   "nocloud-net",
	},
	{
		// https://cloud.debian.org/images/cloud/trixie/20261116-2664/SHA512SUMS
		// (cloud-init 25.1.4).
		Name:   "debian-13",
		URLs:   []string{"https://cloud.debian.org/images/cloud/trixie/20261116-2664/debian-13-genericcloud-amd64-20261116-2664.qcow2"},
		Digest: "sha512:37cb32b320820417eb04b335afcf489bfb4cecce4a957190d09cb2bffbe02b56a1cadd62d78c6ead92aa7839d5ea65e4260f994bbb4b54490df59fdf11ee1d97",
		Seed:   "nocloud",
	},
	{
		// https://cloud-images.ubuntu.com/releases/jammy/release-20261109/SHA256SUMS,
		// signed by the UEC Image Automatic Signing Key (cloud-init 26.1,
		// from the image's .manifest).
		Name:   "ubuntu-22.04",
		URLs:   []string{"https://cloud-images.ubuntu.com/releases/jammy/release-20261109/ubuntu-22.04-server-cloudimg-amd64.img"},
		Digest: "sha256:77d19e53656f87c95f1f6c6be59c789083b3f77fa08f9d88011ee04085c61f87",
		Seed:   "nocloud",
	},
	{
		// https://cloud-images.ubuntu.com/releases/noble/release-20261017/SHA256SUMS,
		// signed as above (cloud-init 26.1).
		Name:   "ubuntu-24.04",
		URLs:   []string{"https://cloud-images.ubuntu.com/releases/noble/release-20261017/ubuntu-24.04-server-cloudimg-amd64.img"},
		Digest: "sha256:04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94",
		Seed:   "nocloud",
	},
	{
		// https://dl.rockylinux.org/pub/rocky/8.10/images/x86_64/Rocky-8-GenericCloud-Base-8.10-20240528.0.x86_64.qcow2.CHECKSUM
		// (not signed). 8.10 is Rocky 8's last release. Its cloud-init,
		// 23.4, detects NoCloud over HTTP from the kernel command line
		// only, so its seed is a disk.
		Name: "rocky-8",
		URLs: []string{
			"https://dl.rockylinux.org/pub/rocky/8.10/images/x86_64/Rocky-8-GenericCloud-Base-8.10-20240528.0.x86_64.qcow2",
			"https://dl.rockylinux.org/vault/rocky/8.10/images/x86_64/Rocky-8-GenericCloud-Base-8.10-20240528.0.x86_64.qcow2",
		},
		Digest: "sha256:e56066c58606191e96184de9a9183a3af33c59bcbd8740d8b10ca054a7a89c14",
		Seed:   SeedISO,
	},
	{
		// https://dl.rockylinux.org/pub/rocky/9.9/images/x86_64/Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2.CHECKSUM,
		// signed by the Rocky release key 2022 (.CHECKSUM.asc) (cloud-init
		// 24.4).
		Name: "rocky-9",
		URLs: []string{
			"https://dl.rockylinux.org/pub/rocky/9.9/images/x86_64/Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2",
			"https://dl.rockylinux.org/vault/rocky/9.9/images/x86_64/Rocky-9-GenericCloud-Base-9.9-20261112.0.x86_64.qcow2",
		},
		Digest: "sha256:4f88f4209de50813d8054ab97309e7169a580206a0c4ea04f375d36c4846d50e",
		Seed:   "nocloud",
	},
	{
		// https://repo.almalinux.org/almalinux/9.9/cloud/x86_64/images/CHECKSUM,
		// signed by the AlmaLinux OS 9 key (CHECKSUM.asc) (cloud-init 24.4).
		Name: "alma-9",
		URLs: []string{
			"https://repo.almalinux.org/almalinux/9.9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-9.9-20261116.x86_64.qcow2",
			"https://vault.almalinux.org/9.9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-9.9-20261116.x86_64.qcow2",
		},
		Digest: "sha256:50e428e36083531995df84302268b95f0bf30db1d5e6b931f73dc40642dd77bb",
		Seed:   "nocloud",
	},
	{
		// https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-45-1.4-x86_64-CHECKSUM,
		// signed by the Fedora 45 key (cloud-init 26.2).
		Name: "fedora-45",
		URLs: []string{
			"https://dl.fedoraproject.org/pub/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-45-1.4.x86_64.qcow2",
			"https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/45/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-45-1.4.x86_64.qcow2",
		},
		Digest: "sha256:50bdc5e70f6a24f540932d15411c1c6ae9fcfa40fb990d876d83c5cc823b2ad0",
		Seed:   "nocloud",
	},
}

// ImageEnv chooses the images a run boots: names separated by commas or
// spaces, or every image when it is empty.
const ImageEnv = "EASYRMM_VM_IMAGE"

// Images returns the names of every pinned image.
func Images() []string {
	names := make([]string, len(images))
	for i, img := range images {
		names[i] = img.Name
	}
	return names
}

// Selected returns the images ImageEnv names, or all of them when it is
// unset, and fails the test on a name that is not pinned.
func Selected(t testing.TB) []string {
	t.Helper()
	names := strings.FieldsFunc(os.Getenv(ImageEnv), func(r rune) bool { return r == ',' || r == ' ' })
	if len(names) == 0 {
		return Images()
	}
	for _, name := range names {
		if _, err := lookup(name); err != nil {
			t.Fatalf("%s: %v", ImageEnv, err)
		}
	}
	return names
}

func lookup(name string) (Image, error) {
	i := slices.IndexFunc(images, func(img Image) bool { return img.Name == name })
	if i < 0 {
		return Image{}, fmt.Errorf("no image %q (pinned: %s)", name, strings.Join(Images(), ", "))
	}
	return images[i], nil
}
