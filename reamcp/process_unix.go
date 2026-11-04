//go:build !windows

package reamcp

import (
	"os/exec"
	"syscall"
)

func configureProcess(cmd *exec.Cmd)  { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func killProcess(cmd *exec.Cmd) error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
