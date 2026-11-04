package main

import (
 "fmt"
 "syscall"
 "time"
)

func main() {
 tick:=syscall.NewLazyDLL("kernel32.dll").NewProc("GetTickCount64")
 for i:=0;i<100;i++ {value,_,_:=tick.Call();fmt.Printf("ARTEX_WINDOWS_FIXTURE %d\n",value);time.Sleep(100*time.Millisecond)}
}
