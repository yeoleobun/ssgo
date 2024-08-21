package main

import (
	"context"
	"fmt"
	"iter"
	"sync"
	"time"
)

func Range(start, end int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for start < end && yield(start) {
			start += 1
		}
	}
}

const FourK = 4 * 1024

func main() {
	// ctx, cancel := context.WithCancel(context.Background())
	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		i := 0
	outer:
		for {

			select {
			case <-ctx.Done():
				break outer
			default:
				fmt.Println(i)
				time.Sleep(time.Second)
			}
			i += 1
		}
		wg.Done()
	}()
	wg.Wait()
}
