//go:build windows

package hardware

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/paulmataruso/easyrmm/agent/inventory"
	"github.com/paulmataruso/easyrmm/internal/agentproto"
)

// TestRefusedBeforeTheSystemCallWindows: a command off the list never
// reaches DeviceIoControl; a listed one does, here on no disk.
func TestRefusedBeforeTheSystemCallWindows(t *testing.T) {
	nvme, ata := &winNVMe{h: windows.InvalidHandle}, &winATA{h: windows.InvalidHandle}
	for c := range ataNames {
		for _, m := range ataMutations(c) {
			if _, ok := ataNames[m]; ok {
				continue
			}
			if _, _, err := ata.ata(m); !errors.Is(err, errNotAllowed) {
				t.Fatalf("%+v: %v", m, err)
			}
		}
	}
	for c := range nvmeNames {
		for _, m := range nvmeMutations(c) {
			if _, err := nvme.nvme(m); !errors.Is(err, errNotAllowed) {
				t.Fatalf("%+v: %v", m, err)
			}
		}
	}
	if _, _, err := ata.ata(ataIdentify); !is(err, agentproto.ReasonIOError) {
		t.Errorf("IDENTIFY on no disk: %v", err)
	}
	if _, err := nvme.nvme(nvmeHealthLog); !is(err, agentproto.ReasonIOError) {
		t.Errorf("health log on no disk: %v", err)
	}
	if nvme.route() != "device" || ata.route() != "ata" {
		t.Error("routes")
	}
	nvme.property = propertyAdapterProtocol
	if nvme.route() != "adapter" {
		t.Error("the adapter's route")
	}
}

func TestOpenNoDisk(t *testing.T) {
	const path = `\\.\PhysicalDrive4095`
	if _, err := openNVMe(path); !is(err, agentproto.ReasonIOError) {
		t.Errorf("NVMe: %v", err)
	}
	if _, err := openATA(path, false); !is(err, agentproto.ReasonIOError) {
		t.Errorf("ATA: %v", err)
	}
	if sweep(path) {
		t.Error("a call out on no disk")
	}
	if f := openFailure(windows.ERROR_ACCESS_DENIED); f.reason != agentproto.ReasonAccessDenied {
		t.Errorf("access: %+v", f)
	}
}

func TestPlanWindows(t *testing.T) {
	disk := func(bus uint32, model string) inventory.ListedDisk {
		return inventory.ListedDisk{Disk: agentproto.Disk{Name: "PhysicalDrive1", Model: model, Serial: "S1"}, Bus: bus}
	}
	f, tg := planWindows("", disk(busNVMe, "Stand-in NVMe"))
	if f != nil || tg.proto != protoNVMe || tg.limit != nvmeTimeout || tg.key != "PhysicalDrive1/S1" || len(tg.paths) != 1 || tg.paths[0] != `\\.\PhysicalDrive1` {
		t.Errorf("NVMe: %+v %+v", f, tg)
	}
	if f, tg := planWindows("", disk(busSATA, "Stand-in SATA")); f != nil || tg.proto != protoATA || tg.limit != ataTimeout {
		t.Errorf("SATA: %+v %+v", f, tg)
	}
	if f, _ := planWindows("", disk(busSATA, "Msft Virtual Disk")); f == nil || f.reason != agentproto.ReasonVirtualDisk {
		t.Errorf("virtual: %+v", f)
	}
}

func TestCallError(t *testing.T) {
	for err, want := range map[error]string{
		windows.ERROR_NOT_SUPPORTED:                            agentproto.ReasonStorageDriver,
		windows.ERROR_INVALID_FUNCTION:                         agentproto.ReasonStorageDriver,
		windows.ERROR_INVALID_PARAMETER:                        agentproto.ReasonStorageDriver,
		windows.ERROR_ACCESS_DENIED:                            agentproto.ReasonAccessDenied,
		windows.ERROR_OPERATION_ABORTED:                        agentproto.ReasonTimeout,
		windows.ERROR_SEM_TIMEOUT:                              agentproto.ReasonTimeout,
		windows.ERROR_CRC:                                      agentproto.ReasonIOError,
		fmt.Errorf("wrapped: %w", windows.ERROR_NOT_SUPPORTED): agentproto.ReasonStorageDriver,
	} {
		if f := callError("IOCTL", err); f.reason != want {
			t.Errorf("%v: %s, want %s", err, f.reason, want)
		}
	}
	if f := busy(); f.reason != agentproto.ReasonTimedOutRecently {
		t.Errorf("busy: %+v", f)
	}
}
