package hardware

import (
	"strings"

	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// Which disks are read, and what each is (ADR-0065, "Which disks, and what
// each is"). A virtual machine's disks are judged one by one: a drive passed
// through to it has a real health log.

// emulatedModels are the models of hypervisors' emulated disks, lower case.
// A disk whose model (with its vendor, where the system names one apart)
// contains one is unsupported (virtual_disk), and nothing is sent to it. A
// disk whose model was changed by hand is read as what it says it is.
var emulatedModels = []string{
	"qemu harddisk",              // QEMU's IDE, SATA and SCSI disks
	"qemu nvme ctrl",             // QEMU's NVMe controller
	"msft virtual disk",          // Hyper-V and Azure
	"vmware virtual",             // VMware's SCSI, SATA and NVMe disks
	"vbox harddisk",              // VirtualBox's IDE and SATA disks
	"orcl-vbox-nvme",             // VirtualBox's NVMe disk
	"red hat virtio",             // virtio disks under Windows' drivers
	"amazon elastic block store", // EC2's EBS volumes
	"google persistentdisk",      // Compute Engine's SCSI disks
	"nvme_card-pd",               // Compute Engine's NVMe disks
}

// emulated reports whether a model names a hypervisor's emulated disk.
func emulated(model string) bool {
	m := strings.ToLower(strings.Join(strings.Fields(model), " "))
	for _, e := range emulatedModels {
		if strings.Contains(m, e) {
			return true
		}
	}
	return false
}

func virtualDisk(detail string) *failure {
	return fail(agentproto.FactUnsupported, agentproto.ReasonVirtualDisk, "%s", detail)
}

// Windows' storage bus types (STORAGE_BUS_TYPE).
const (
	busSCSI              = 1
	busATA               = 3
	busUSB               = 7
	busRAID              = 8
	busSATA              = 11
	busSD                = 12
	busMMC               = 13
	busVirtual           = 14
	busFileBackedVirtual = 15
	busSpaces            = 16
	busNVMe              = 17
)

// planBus decides, from a Windows disk's bus type and model, whether there
// is health to read and by which protocol: NVMe (17) through the
// protocol-specific query; SATA and ATA (11, 3) through ATA pass-through;
// the RAID bus (8), which covers hardware RAID volumes and single drives
// behind Intel RST or VMD alike, both, NVMe first. Every other bus is not
// read: SCSI, SAS, FC and iSCSI disks are a later slice.
func planBus(bus uint32, model string) (*failure, protocol) {
	switch {
	case bus == busVirtual || bus == busFileBackedVirtual:
		return virtualDisk("a virtual disk's bus"), 0
	case emulated(model):
		return virtualDisk("an emulated disk's model"), 0
	case bus == busSpaces:
		return fail(agentproto.FactUnsupported, agentproto.ReasonStorageSpaces, ""), 0
	case bus == busUSB:
		return fail(agentproto.FactUnavailable, agentproto.ReasonUSBBridge, ""), 0
	case bus == busSD || bus == busMMC:
		return fail(agentproto.FactUnsupported, agentproto.ReasonMemoryCard, ""), 0
	case bus == busNVMe:
		return nil, protoNVMe
	case bus == busATA || bus == busSATA:
		return nil, protoATA
	case bus == busRAID:
		return nil, protoEither
	}
	return notThisProtocol("bus type %d", bus), 0
}
