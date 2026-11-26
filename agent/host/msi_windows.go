package host

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	msiDLL                    = windows.NewLazySystemDLL("msi.dll")
	procMsiEnumRelatedProduct = msiDLL.NewProc("MsiEnumRelatedProductsW")
)

// msiInstalled reports whether a product of the upgrade code is installed.
func msiInstalled(upgradeCode string) bool {
	code, err := windows.UTF16PtrFromString(upgradeCode)
	if err != nil || procMsiEnumRelatedProduct.Find() != nil {
		return false
	}
	var product [39]uint16
	r, _, _ := procMsiEnumRelatedProduct.Call(uintptr(unsafe.Pointer(code)), 0, 0, uintptr(unsafe.Pointer(&product[0])))
	return r == 0 // ERROR_SUCCESS
}
