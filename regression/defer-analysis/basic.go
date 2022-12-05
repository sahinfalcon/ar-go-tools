package main

// Functions that substitute for arbitrary behavior
func arbitrary() bool
func external(int) int

// Basic function, one defer, one return
func f1() int {
	i := 1
	defer func() { i = 3 }()
	i = 4
	return external(i)
}

// Test a branch before a defer. Should be a return with no stacks, and one with one stack
func f2() int {
	if arbitrary() {
		return 0
	}
	defer func() {}()
	return 1
}

// Test loop with no defer
func f3() int {
	i := 1
	defer func() { println(i) }()
	i = 4
	if arbitrary() {
		external(5)
	}
	for i = 0; i < 10; i++ {
		external(i)
	}
	defer external(2)
	return i
}

// Should be 3 possible stacks.
func f4() (err error) {
	if arbitrary() {
		if arbitrary() {
			defer external(3)
		} else {
			defer external(4)
		}
	}
	return nil
}

// Unbounded set, should fail
func f5() (err error) {
	for i := 0; i < 10; i++ {
		defer func() {
			err = *new(error)
		}()
	}
	return nil
}

// Test an exponential blowup (2^4 = 16 sets)
func f6() (err error) {
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	if arbitrary() {
		defer func() {}()
	}
	return nil
}

// Test a branch with a defer.
func f7() int {
	if arbitrary() {
		defer external(3)
	}
	defer func() {}()
	return 1
}
