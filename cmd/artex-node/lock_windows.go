//go:build windows

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

type nodeFileLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireNodeLock(path string) (*nodeFileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	l := &nodeFileLock{file: f}
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &l.overlapped)
	if err != nil {
		_ = f.Close()
		return nil, errors.New("another artex-node process holds the execution lock")
	}
	return l, nil
}

func (l *nodeFileLock) Close() error {
	_ = windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	return l.file.Close()
}
