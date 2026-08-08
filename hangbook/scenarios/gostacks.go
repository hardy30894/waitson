package main

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

// noinline keeps c, b, a as real frames: the unwinder is what is under
// test here, and runtime.Stack must describe the same physical stack.
//
//go:noinline
func c(ch chan int) { <-ch }

//go:noinline
func b(ch chan int) { c(ch) }

//go:noinline
func a(ch chan int) { b(ch) }

// The runtime's own view of every stack lands in gostacks.txt; the harness
// holds waitson's reconstruction against it, frame for frame.
func main() {
	fmt.Println("READY", os.Getpid())
	ch := make(chan int)
	go a(ch)
	time.Sleep(300 * time.Millisecond)
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	os.WriteFile("/tmp/hb/gostacks.txt", buf[:n], 0644)
	// A live timer keeps the runtime's own deadlock panic quiet so the
	// blocked chain stays alive to be diagnosed.
	for {
		time.Sleep(time.Hour)
	}
}
