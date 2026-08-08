package main

import (
	"fmt"
	"net"
	"os"
)

func worker(ch chan int) {
	ch <- 1
}

func main() {
	fmt.Println("READY", os.Getpid())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	// An accept in flight keeps the runtime's own deadlock panic quiet,
	// so the stuck channel plumbing below stays alive to be diagnosed.
	go func() {
		ln.Accept()
	}()
	ch := make(chan int)
	for i := 0; i < 3; i++ {
		go worker(ch)
	}
	done := make(chan int)
	<-done
}
