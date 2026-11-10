//go:build !windows && !darwin

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func readSetupSecret(r *bufio.Reader, input io.Reader, out io.Writer) (string, error) {
	f, ok := input.(*os.File)
	if !ok {
		fmt.Fprint(out, "Secret: ")
		s, e := r.ReadString('\n')
		return strings.TrimSpace(s), e
	}
	oldp, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	if err != nil {
		fmt.Fprint(out, "Secret: ")
		s, e := r.ReadString('\n')
		return strings.TrimSpace(s), e
	}
	old := *oldp
	noEcho := old
	noEcho.Lflag &^= unix.ECHO
	if err := unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, &noEcho); err != nil {
		return "", err
	}
	fmt.Fprint(out, "Secret (input hidden): ")
	s, e := r.ReadString('\n')
	_ = unix.IoctlSetTermios(int(f.Fd()), unix.TCSETS, &old)
	fmt.Fprintln(out)
	return strings.TrimSpace(s), e
}
