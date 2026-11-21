package inventory

import (
	"encoding/binary"
	"strings"
)

// The parsers here read the SCSI vital product data pages Linux hands out
// in sysfs as raw bytes. They are plain Go, tested on every platform.

// parseVPD89 returns the IDENTIFY DEVICE data a SATA disk's ATA Information
// VPD page (89h) holds from byte 60, which the SCSI/ATA translation layer
// fills from the drive: its 512 bytes, when the page is whole and holds
// IDENTIFY DEVICE's answer (command code ECh at byte 56).
func parseVPD89(b []byte) ([]byte, bool) {
	const end = 60 + 512
	if len(b) < end || b[1] != 0x89 || 4+int(binary.BigEndian.Uint16(b[2:4])) < end || b[56] != 0xEC {
		return nil, false
	}
	return b[60:end], true
}

// ataIdentityStrings reads the serial number (words 10 to 19) and firmware
// revision (words 23 to 26) of IDENTIFY DEVICE data. ATA strings hold two
// characters a word, the first in the word's high byte.
func ataIdentityStrings(id []byte) (serial, firmware string) {
	return ataString(id[20:40]), ataString(id[46:54])
}

func ataString(b []byte) string {
	s := make([]byte, 0, len(b))
	for i := 0; i+1 < len(b); i += 2 {
		s = append(s, b[i+1], b[i])
	}
	return printable(s)
}

// parseVPD80 reads the Unit Serial Number VPD page (80h): its length at
// bytes 2 and 3, then the serial number.
func parseVPD80(b []byte) string {
	if len(b) < 4 || b[1] != 0x80 {
		return ""
	}
	n := min(int(binary.BigEndian.Uint16(b[2:4])), len(b)-4)
	return printable(b[4 : 4+n])
}

// printable keeps a field's printable ASCII, its spaces squeezed.
func printable(b []byte) string {
	s := strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7E {
			return ' '
		}
		return r
	}, string(b))
	return strings.Join(strings.Fields(s), " ")
}
