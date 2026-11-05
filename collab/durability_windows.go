package collab

import "golang.org/x/sys/windows"

// Windows does not support fsync on a read-only directory handle. Flush the
// temporary file first (the caller does that), then request a write-through
// same-volume move instead of reporting a failed write after it was persisted.
func persistRename(source, target string) error {
	s, err := windows.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(s, t, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}

// A crash can resurrect an acknowledged file after deletion. Replay remains
// safe because the receiving inbox retains the immutable command identity.
func syncDir(string) error { return nil }
