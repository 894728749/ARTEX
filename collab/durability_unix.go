//go:build !windows

package collab

import "os"

func persistRename(source, target string) error { return os.Rename(source, target) }
func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
