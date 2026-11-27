//go:build windows

package escrow

import (
	"context"
	"errors"
	"fmt"
	"strings"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows/registry"
)

// The same exception to the no-WMI rule as the reader (ADR-0081, section 5):
// BitLocker is changed through Win32_EncryptableVolume in this process, never
// through manage-bde and never through a script, so that a recovery password
// that is made passes from WMI to the sealed upload and nowhere else.
const (
	tpmNamespace = `root\CIMV2\Security\MicrosoftTpm`
	cimNamespace = `root\CIMV2`
	// domainRoleBackup and domainRolePrimary are Win32_ComputerSystem.DomainRole
	// of a domain controller.
	domainRoleBackup  = 4
	domainRolePrimary = 5
	// encryptUsedSpaceOnly is Win32_EncryptableVolume.Encrypt's
	// ENCRYPT_DATA_ONLY flag; 0 encrypts the whole volume.
	encryptUsedSpaceOnly = 1
)

// SystemManager changes BitLocker through WMI.
type SystemManager struct{}

var _ Manager = SystemManager{}

// withVolume calls f with the Win32_EncryptableVolume whose device ID is id,
// or whose drive letter is letter when id is empty.
func withVolume(id, letter string, f func(vol *ole.IDispatch) error) error {
	w, err := connect()
	if err != nil {
		return err
	}
	defer w.close()
	found := false
	err = w.volumes(func(vol *ole.IDispatch) (bool, error) {
		devID, err := str(vol, "DeviceID")
		if err != nil {
			return false, err
		}
		l, _ := str(vol, "DriveLetter")
		if (id != "" && devID != id) || (id == "" && !strings.EqualFold(l, letter)) {
			return false, nil
		}
		found = true
		return true, f(vol)
	})
	if err == nil && !found {
		err = errors.New("the volume is not there")
	}
	return err
}

// Preconditions reads the computer's name and role, the TPM's state, whether
// the edition has BitLocker and whether a restart is pending.
func (SystemManager) Preconditions(ctx context.Context) (Preconditions, error) {
	var p Preconditions
	// The edition: the BitLocker namespace's class exists where the edition has it.
	if w, err := connect(); err == nil {
		p.EditionAllows = true
		w.close()
	}
	if err := cimRow(`SELECT Name, DomainRole FROM Win32_ComputerSystem`, cimNamespace, func(d *ole.IDispatch) error {
		name, err := str(d, "Name")
		if err != nil {
			return err
		}
		role, err := num(d, "DomainRole")
		if err != nil {
			return err
		}
		p.Computer = name
		p.DomainController = role == domainRoleBackup || role == domainRolePrimary
		return nil
	}); err != nil {
		return p, fmt.Errorf("reading the computer's role: %w", err)
	}
	// A TPM that is present, enabled, activated and owned. No row: no TPM.
	_ = cimRow(`SELECT IsEnabled_InitialValue, IsActivated_InitialValue FROM Win32_Tpm`, tpmNamespace, func(d *ole.IDispatch) error {
		en, err1 := boolProp(d, "IsEnabled_InitialValue")
		ac, err2 := boolProp(d, "IsActivated_InitialValue")
		p.TPMReady = err1 == nil && err2 == nil && en && ac
		return nil
	})
	p.RebootPending = rebootPending()
	return p, ctx.Err()
}

// cimRow runs a query in a namespace and calls f with its first row.
func cimRow(query, ns string, f func(*ole.IDispatch) error) error {
	w, err := connectTo(ns)
	if err != nil {
		return err
	}
	defer w.close()
	v, err := oleutil.CallMethod(w.svc, "ExecQuery", query)
	if err != nil {
		return err
	}
	defer func() { _ = v.Clear() }()
	var ferr error
	got := false
	err = oleutil.ForEach(v.ToIDispatch(), func(item *ole.VARIANT) error {
		if got {
			return nil
		}
		got = true
		ferr = f(item.ToIDispatch())
		return nil
	})
	if err != nil {
		return err
	}
	if !got {
		return errors.New("no row")
	}
	return ferr
}

func boolProp(d *ole.IDispatch, prop string) (bool, error) {
	v, err := oleutil.GetProperty(d, prop)
	if err != nil {
		return false, err
	}
	defer func() { _ = v.Clear() }()
	b, _ := v.Value().(bool)
	return b, nil
}

// rebootPending reads the places Windows records a restart it is waiting for.
func rebootPending() bool {
	for _, k := range []string{
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`,
	} {
		if key, err := registry.OpenKey(registry.LOCAL_MACHINE, k, registry.QUERY_VALUE); err == nil {
			_ = key.Close()
			return true
		}
	}
	if key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE); err == nil {
		defer func() { _ = key.Close() }()
		if v, _, err := key.GetStringsValue("PendingFileRenameOperations"); err == nil && len(v) > 0 {
			return true
		}
	}
	return false
}

// Volume finds a volume by drive letter.
func (SystemManager) Volume(ctx context.Context, letter string) (*VolumeInfo, error) {
	var out *VolumeInfo
	err := withVolume("", letter, func(vol *ole.IDispatch) error {
		id, err := str(vol, "DeviceID")
		if err != nil {
			return err
		}
		status, err := num(vol, "ConversionStatus")
		if err != nil {
			return err
		}
		ids, err := protectorIDs(vol)
		if err != nil {
			return err
		}
		all, err := allProtectorCount(vol)
		if err != nil {
			return err
		}
		l, _ := str(vol, "DriveLetter")
		out = &VolumeInfo{ID: id, Mount: l, Status: conversionStatus[status], Protectors: ids, AnyProtectors: all > 0}
		return nil
	})
	if err != nil && err.Error() == "the volume is not there" {
		return nil, ctx.Err()
	}
	return out, err
}

// allProtectorCount counts a volume's protectors of every type (GetKeyProtectors
// with type 0).
func allProtectorCount(vol *ole.IDispatch) (int, error) {
	out, release, err := exec(vol, "GetKeyProtectors", map[string]any{"KeyProtectorType": 0})
	if err != nil {
		return 0, err
	}
	defer release()
	v, err := oleutil.GetProperty(out, "VolumeKeyProtectorID")
	if err != nil {
		return 0, err
	}
	defer func() { _ = v.Clear() }()
	arr := v.ToArray()
	if arr == nil {
		return 0, nil
	}
	n, err := arr.TotalElements(0)
	return int(n), err
}

// AddRecoveryPassword adds a numerical-password protector with a password
// Windows generates (an empty NumericalPassword).
func (SystemManager) AddRecoveryPassword(ctx context.Context, volumeID string) (string, error) {
	var pid string
	err := withVolume(volumeID, "", func(vol *ole.IDispatch) error {
		// NumericalPassword is left out (NULL) so that BitLocker makes the
		// password: an empty string is refused as a malformed password
		// (0x80310035, FVE_E_INVALID_PASSWORD_FORMAT; CI run 20).
		out, release, err := exec(vol, "ProtectKeyWithNumericalPassword", map[string]any{"FriendlyName": "EasyRMM recovery password"})
		if err != nil {
			return err
		}
		defer release()
		pid, err = str(out, "VolumeKeyProtectorID")
		return err
	})
	if err == nil && pid == "" {
		err = errors.New("no protector ID came back")
	}
	return pid, err
}

// DeleteProtector removes a protector by its ID.
func (SystemManager) DeleteProtector(ctx context.Context, volumeID, protectorID string) error {
	return withVolume(volumeID, "", func(vol *ole.IDispatch) error {
		_, release, err := exec(vol, "DeleteKeyProtector", map[string]any{"VolumeKeyProtectorID": protectorID})
		if err != nil {
			return err
		}
		release()
		return nil
	})
}

// AddTPMProtector adds the TPM protector with the default platform validation
// profile.
func (SystemManager) AddTPMProtector(ctx context.Context, volumeID string) error {
	return withVolume(volumeID, "", func(vol *ole.IDispatch) error {
		_, release, err := exec(vol, "ProtectKeyWithTPM", map[string]any{"FriendlyName": "EasyRMM TPM protector"})
		if err != nil {
			return err
		}
		release()
		return nil
	})
}

// StartEncryption starts encrypting the volume with the system's default method.
func (SystemManager) StartEncryption(ctx context.Context, volumeID string, usedSpaceOnly bool) error {
	flags := int32(0)
	if usedSpaceOnly {
		flags = encryptUsedSpaceOnly
	}
	return withVolume(volumeID, "", func(vol *ole.IDispatch) error {
		_, release, err := exec(vol, "Encrypt", map[string]any{"EncryptionMethod": int32(0), "EncryptionFlags": flags})
		if err != nil {
			return err
		}
		release()
		return nil
	})
}
