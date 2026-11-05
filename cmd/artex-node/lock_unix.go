//go:build !windows

package main

import (
	"errors"
	"os"
	"syscall"
)

type nodeFileLock struct{ file *os.File }

func acquireNodeLock(path string) (*nodeFileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("another artex-node process holds the execution lock")
	}
	return &nodeFileLock{file: f}, nil
}

func (l *nodeFileLock) Close() error {
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	return l.file.Close()
}
