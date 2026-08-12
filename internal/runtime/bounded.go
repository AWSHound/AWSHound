package runtime

import "sync"

// BoundedParallel runs fn(0), …, fn(n-1) concurrently, but with at most max in
// flight at once. A max <= 0 means unbounded. It is the account-level throttle
// that bounds how many accounts' heavy data are resident simultaneously (§9 of
// docs/authorization-tensor.md), replacing the collect fan-out's spawn-all
// wg.Add(len(boots)).
func BoundedParallel(max, n int, fn func(i int)) {
	if n <= 0 {
		return
	}
	var wg sync.WaitGroup
	wg.Add(n)
	if max <= 0 {
		for i := 0; i < n; i++ {
			go func(i int) { defer wg.Done(); fn(i) }(i)
		}
		wg.Wait()
		return
	}
	sem := make(chan struct{}, max)
	for i := 0; i < n; i++ {
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}
