//go:build windows

package escrow

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// The one exception to the agent inventory's no-WMI rule (ADR-0081, section
// 5): BitLocker's recovery passwords are read through WMI in this process,
// never through manage-bde (localized text through a pipe) and never through a
// script (Group Policy's PowerShell transcription would write the output to
// disk).
const (
	namespace = `root\CIMV2\Security\MicrosoftVolumeEncryption`
	// protectorNumericalPassword is KeyProtectorType 3.
	protectorNumericalPassword = 3
	sFalse                     = 1 // CoInitializeEx: already initialized on this thread
)

// SystemReader reads BitLocker through WMI.
type SystemReader struct{}

// conversionStatus names Win32_EncryptableVolume.ConversionStatus.
var conversionStatus = map[int64]string{
	0: "decrypted", 1: "encrypted", 2: "encrypting", 3: "decrypting", 4: "encryption paused", 5: "decryption paused",
}

// wmi is a connection to the BitLocker namespace on a thread that stays the
// same until close, as COM wants.
type wmi struct {
	locator *ole.IDispatch
	svc     *ole.IDispatch
	closers []func()
}

func connect() (*wmi, error) {
	runtime.LockOSThread()
	w := &wmi{}
	inited := true
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		var oe *ole.OleError
		if !errors.As(err, &oe) || oe.Code() != sFalse {
			runtime.UnlockOSThread()
			return nil, fmt.Errorf("starting COM: %w", err)
		}
		inited = false // someone else's initialisation; leave it
	}
	w.closers = append(w.closers, func() {
		if inited {
			ole.CoUninitialize()
		}
		runtime.UnlockOSThread()
	})
	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		w.close()
		return nil, fmt.Errorf("opening WMI: %w", err)
	}
	w.closers = append(w.closers, func() { unknown.Release() })
	if w.locator, err = unknown.QueryInterface(ole.IID_IDispatch); err != nil {
		w.close()
		return nil, fmt.Errorf("opening WMI: %w", err)
	}
	w.closers = append(w.closers, func() { w.locator.Release() })
	v, err := oleutil.CallMethod(w.locator, "ConnectServer", "", namespace)
	if err != nil {
		w.close()
		return nil, fmt.Errorf("connecting to BitLocker's WMI namespace: %w", err)
	}
	w.svc = v.ToIDispatch()
	w.closers = append(w.closers, func() { w.svc.Release() })
	return w, nil
}

// close releases everything in reverse order.
func (w *wmi) close() {
	for i := len(w.closers) - 1; i >= 0; i-- {
		w.closers[i]()
	}
	w.closers = nil
}

// volumes calls f with each Win32_EncryptableVolume.
func (w *wmi) volumes(f func(vol *ole.IDispatch) (stop bool, err error)) error {
	v, err := oleutil.CallMethod(w.svc, "ExecQuery", "SELECT * FROM Win32_EncryptableVolume")
	if err != nil {
		return fmt.Errorf("listing volumes: %w", err)
	}
	defer func() { _ = v.Clear() }()
	set := v.ToIDispatch()
	stopped := false
	return oleutil.ForEach(set, func(item *ole.VARIANT) error {
		if stopped {
			return nil
		}
		d := item.ToIDispatch()
		stop, err := f(d)
		stopped = stop
		return err
	})
}

func str(d *ole.IDispatch, prop string) (string, error) {
	v, err := oleutil.GetProperty(d, prop)
	if err != nil {
		return "", err
	}
	defer func() { _ = v.Clear() }()
	if v.VT == ole.VT_NULL || v.VT == ole.VT_EMPTY {
		return "", nil
	}
	return v.ToString(), nil
}

func num(d *ole.IDispatch, prop string) (int64, error) {
	v, err := oleutil.GetProperty(d, prop)
	if err != nil {
		return 0, err
	}
	defer func() { _ = v.Clear() }()
	return v.Val, nil
}

// exec calls a method of Win32_EncryptableVolume with named in-parameters and
// returns the out-parameters object, with the method's own return value
// checked.
func exec(vol *ole.IDispatch, method string, in map[string]any) (*ole.IDispatch, func(), error) {
	methods, err := oleutil.GetProperty(vol, "Methods_")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = methods.Clear() }()
	m, err := oleutil.CallMethod(methods.ToIDispatch(), "Item", method)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = m.Clear() }()
	inP, err := oleutil.GetProperty(m.ToIDispatch(), "InParameters")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = inP.Clear() }()
	inst, err := oleutil.CallMethod(inP.ToIDispatch(), "SpawnInstance_")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = inst.Clear() }()
	for k, v := range in {
		if _, err := oleutil.PutProperty(inst.ToIDispatch(), k, v); err != nil {
			return nil, nil, err
		}
	}
	out, err := oleutil.CallMethod(vol, "ExecMethod_", method, inst.ToIDispatch())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", method, err)
	}
	od := out.ToIDispatch()
	release := func() { _ = out.Clear() }
	rc, err := num(od, "ReturnValue")
	if err != nil {
		release()
		return nil, nil, err
	}
	if rc != 0 {
		release()
		return nil, nil, fmt.Errorf("%s returned 0x%X", method, uint32(rc)) //nolint:gosec // an HRESULT
	}
	return od, release, nil
}

// protectorIDs lists a volume's numerical-password protector IDs.
func protectorIDs(vol *ole.IDispatch) ([]string, error) {
	out, release, err := exec(vol, "GetKeyProtectors", map[string]any{"KeyProtectorType": protectorNumericalPassword})
	if err != nil {
		return nil, err
	}
	defer release()
	v, err := oleutil.GetProperty(out, "VolumeKeyProtectorID")
	if err != nil {
		return nil, err
	}
	defer func() { _ = v.Clear() }()
	arr := v.ToArray()
	if arr == nil {
		return nil, nil
	}
	return arr.ToStringArray(), nil
}

// Volumes lists the volumes with BitLocker on them and their
// numerical-password protectors. No password is read.
func (SystemReader) Volumes(ctx context.Context) ([]Volume, error) {
	w, err := connect()
	if err != nil {
		return nil, err
	}
	defer w.close()
	var out []Volume
	err = w.volumes(func(vol *ole.IDispatch) (bool, error) {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		id, err := str(vol, "DeviceID")
		if err != nil {
			return false, err
		}
		status, err := num(vol, "ConversionStatus")
		if err != nil {
			return false, err
		}
		letter, _ := str(vol, "DriveLetter")
		ids, err := protectorIDs(vol)
		if err != nil {
			return false, err
		}
		if status == 0 && len(ids) == 0 {
			return false, nil // BitLocker is not on this volume
		}
		out = append(out, Volume{ID: id, Mount: letter, Status: conversionStatus[status], Protectors: ids})
		return false, nil
	})
	return out, err
}

// RecoveryPassword reads one protector's numerical password. The BSTR WMI
// returns is overwritten before it is freed; the Go string the COM layer
// makes of it cannot be, which is why the process is the only place the
// password ever is (ADR-0081: zeroing is best-effort).
func (SystemReader) RecoveryPassword(ctx context.Context, volumeID, protectorID string) ([]byte, error) {
	w, err := connect()
	if err != nil {
		return nil, err
	}
	defer w.close()
	var pw []byte
	found := false
	err = w.volumes(func(vol *ole.IDispatch) (bool, error) {
		if ctx.Err() != nil {
			return true, ctx.Err()
		}
		id, err := str(vol, "DeviceID")
		if err != nil || id != volumeID {
			return false, err
		}
		found = true
		out, release, err := exec(vol, "GetKeyProtectorNumericalPassword", map[string]any{"VolumeKeyProtectorID": protectorID})
		if err != nil {
			return true, err
		}
		defer release()
		v, err := oleutil.GetProperty(out, "NumericalPassword")
		if err != nil {
			return true, err
		}
		pw = []byte(v.ToString())
		wipeBSTR(v)
		_ = v.Clear()
		return true, nil
	})
	if err == nil && !found {
		err = errors.New("the volume is not there")
	}
	return pw, err
}

// wipeBSTR overwrites a BSTR variant's characters in place.
func wipeBSTR(v *ole.VARIANT) {
	if v.VT != ole.VT_BSTR || v.Val == 0 {
		return
	}
	p := *(*unsafe.Pointer)(unsafe.Pointer(&v.Val)) // the BSTR's pointer, as the variant stores it
	n := ole.SysStringLen((*int16)(p))
	clear(unsafe.Slice((*uint16)(p), n))
}
