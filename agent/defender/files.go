package defender

import (
	"errors"
	"io/fs"
	"os"
)

func removeFile(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
