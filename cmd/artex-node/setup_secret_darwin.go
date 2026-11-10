//go:build darwin

package main

import (
	"bufio"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strings"
)

func readSetupSecret(r *bufio.Reader, input io.Reader, out io.Writer) (string, error) {
	f, ok := input.(*os.File)
	if !ok {
		fmt.Fprint(out, "Secret: ")
		s, e := r.ReadString('\n')
		return strings.TrimSpace(s), e
	}
	old, err := unix.IoctlGetTermios(int(f.Fd()), unix.TIOCGETA)
	if err != nil {
		fmt.Fprint(out, "Secret: ")
		s, e := r.ReadString('\n')
		return strings.TrimSpace(s), e
	}
	next := *old
	next.Lflag &^= unix.ECHO
	if err = unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, &next); err != nil {
		return "", err
	}
	defer unix.IoctlSetTermios(int(f.Fd()), unix.TIOCSETA, old)
	fmt.Fprint(out, "Secret (input hidden): ")
	s, e := r.ReadString('\n')
	fmt.Fprintln(out)
	return strings.TrimSpace(s), e
}
