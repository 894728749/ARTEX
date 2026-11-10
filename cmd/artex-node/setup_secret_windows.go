//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func readSetupSecret(r *bufio.Reader, input io.Reader, out io.Writer) (string, error) {
	f, ok := input.(*os.File)
	if !ok {
		fmt.Fprint(out, "Secret: ")
		s, e := r.ReadString('\n')
		return strings.TrimSpace(s), e
	}
	h, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return "", err
	}
	var mode uint32
	if err = windows.GetConsoleMode(h, &mode); err != nil {
		fmt.Fprint(out, "Secret: ")
		s, e := r.ReadString('\n')
		return strings.TrimSpace(s), e
	}
	if err = windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return "", err
	}
	fmt.Fprint(out, "Secret (input hidden): ")
	s, e := r.ReadString('\n')
	_ = windows.SetConsoleMode(h, mode)
	fmt.Fprintln(out)
	_ = f
	return strings.TrimSpace(s), e
}
