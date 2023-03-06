package main

// fmt.Sprintf is marked as source in config.yaml
import (
	"fmt"
	random "math/rand"
)

type Foo struct {
	Data string
}

// Bar is marked as source in config.yaml
type Bar struct {
	BarData string
}

type SomeStruct struct {
	DataField string
	OtherData string
}

func (f Foo) zoo() bool {
	return len(f.Data) > 0
}

func mkBar() Bar {
	return Bar{BarData: "stuff"}
}

func mkSomeStruct() SomeStruct {
	return SomeStruct{DataField: "data", OtherData: "0"}
}

func sink1(interface{}) {
}

func sink2(ss *SomeStruct) {
	fmt.Println(ss.DataField)
}

func sink3(s string) {
	fmt.Println(s)
}

// ignore helper for ignoring unused variables
func ignore(...interface{}) {}

func part2() {
	y := Bar{BarData: "tainted"} // @Source(bar0)
	y = mkBar()
	z := SomeStruct{DataField: y.BarData}
	sink3(z.DataField) // @Sink(bar0)
	a := z.DataField
	b := z.OtherData
	sink3(a)         // @Sink(bar0)
	k := mkBar()     // @Source(bar01)
	sink3(k.BarData) // @Sink(bar01)
	v := "something"
	k.BarData = v
	sink3(v)
	ignore(a, b)
}

func testChan() {
	y := mkBar() // @Source(chan)
	c := make(chan string)
	c <- y.BarData
	x := <-c
	sink3(x) // @Sink(chan)
}

func testChan2() {
	c := make(chan string)
	x := "_"
	if random.Int() > 10 {
		y := mkBar() // @Source(chan2)
		c <- y.BarData
		x = <-c
	}
	sink3(x) // @Sink(chan2)
}

func testChan3() {
	c := make(chan string, 11)
	c <- "notaint"
	sink3(<-c) // should not appear as sink receiving tainted value
	for i := 0; i < 10; i++ {
		y := mkBar() // @Source(bar3)
		c <- y.BarData
	}
	for i := 0; i < 10; i++ {
		x := <-c
		sink3(x) // @Sink(bar3)
	}
}

func testFlow1() {
	y := Bar{BarData: "tainted"} // @Source(bar4)
	y = mkBar()
	z := SomeStruct{DataField: y.BarData}
	a := ""
	if random.Int() > 10 {
		for i := 0; i < 10; i++ {
			sink3(a) // @Sink(bar4)
			if random.Int() > 10 {
				a = z.DataField
			}
		}
	} else {
		sink3(a) // not sink
	}
}

func testFieldSensitivity() {
	x := mkSomeStruct()
	x.DataField = fmt.Sprintf("tainted") // @Source(xdata2)
	x.OtherData = "1"
	sink1(x.OtherData) // @Sink(xdata2) TODO: field sensitivity
	sink1(x.DataField) // @Sink(xdata2)
}

func simple1() {
	s := fmt.Sprintf("taintedstuff-%s", "fortest") // @Source(simple1)
	x := Foo{Data: s}
	sink1(x)             // @Sink(simple1)
	if b := x.zoo(); b { // @Source(simple11)
		fmt.Println(x.Data)
		sink1(b) // @Sink(simple11)
	}
}

func testFlow2() {
	a := ""
	if random.Int() > 10 {
		for i := 0; i < 10; i++ {
			sink3(a) // @Sink(bar1)
			if random.Int() > 10 {
				y := Bar{BarData: "tainted"} // @Source(bar1)
				y = mkBar()
				z := SomeStruct{DataField: y.BarData}
				a = z.DataField
			}
		}
	} else {
		sink3(a) // not sink
	}
}

func testAliasing1() {
	a := ""
	b := &a
	*b = fmt.Sprintf("x") // @Source(aliasing4)
	sink3(a)              // @Sink(aliasing4)
}

type example struct {
	ptr *string
}

func testAliasing2() {
	a := ""
	b := example{ptr: &a}
	*b.ptr = fmt.Sprintf("x") // @Source(aliasing3)
	sink3(a)                  // @Sink(aliasing3)
}

func testSlice() {
	a := []string{"a"}
	a = append(a, fmt.Sprintf("taint")) // @Source(slice1)
	sink3(a[1])                         // @Sink(slice1)
}

type nestedStruct struct {
	Ex example
	A  string
}

func testNestedStructAliasing() {
	foo := []string{"a"}
	barex := example{&foo[0]}
	n := nestedStruct{Ex: barex, A: "b"}
	foo[0] = fmt.Sprintf("tainted") // @Source(aliasing0)
	sink3(n.A)                      // @Sink(aliasing0) TODO: field sensitivity
	sink3(*n.Ex.ptr)                // @Sink(aliasing0)
}

func testMap() {
	a := make(map[int]string)
	a[0] = "a"
	sink3(a[0])                 // ok
	a[1] = fmt.Sprintf("taint") // @Source(map1)
	sink3(a[0])                 // @Sink(map1)
	a[2] = "b"
	sink3(a[2]) // @Sink(map1) (entire map is considered tainted)
}

func testMapAndFieldSensitivity() {
	a := make(map[int]string)
	x := mkSomeStruct()
	x.DataField = "a"
	x.OtherData = "1"
	a[0] = x.DataField
	sink3(a[0])                           // ok
	x.DataField = fmt.Sprintf("taintedx") // @Source(mapf)
	a[1] = x.DataField
	sink1(a[1]) // @Sink(mapf)
}

func testReturnTaintedValue() string {
	a := make(map[int]string)
	x := mkSomeStruct()
	if random.Int() > 2 {
		x.DataField = "a"
		x.OtherData = "1"
		a[0] = x.DataField
	} else {
		x.DataField = fmt.Sprintf("tainted")
		a[1] = x.DataField
	}
	return a[1]
}

func testLongFunction() string {
	var ar [10]string
	xl := mkSomeStruct()
	for i := 0; i < 10; i++ {
		if random.Int() > 2 {
			xl.DataField = "ar"
			xl.OtherData = "1"
			ar[i] = xl.DataField
		} else {
			xl.DataField = fmt.Sprintf("tainted-value") // @Source(func1)
			ar[i] = xl.DataField
		}
	}
	sink1(ar[1]) // @Sink(func1)
	s := ar[1]
	ex := example{ptr: &s}
	switch *(ex.ptr) {
	case "tainted-value":
		sink3(*(ex.ptr)) // @Sink(func1)
		return "xl"
	default:
		return *(ex.ptr)
	}
}

func testMapAndField2() {
	a := make(map[int]string)
	x := mkSomeStruct()
	x.DataField = fmt.Sprintf("tainted-testMapAndField2") // @Source(xdata)
	x.OtherData = "b"
	a[0] = x.OtherData // not tainted
	sink1(a[0])        // @Sink(xdata) TODO: field sensitivity
	a[1] = x.DataField // tainted
	sink1(a[1])        // @Sink(xdata)
}

func testMultipleSources1() {
	b := mkBar()                // @Source(n2)
	s := fmt.Sprintf("Tainted") // @Source(n1)
	t := b.BarData
	sink3(s + t) // @Sink(n1,n2)
}

func testMultipleSources2() {
	var a []string
	if random.Int() > 10 {
		a = append(a, fmt.Sprintf("tainted")) // @Source(nm1)
	} else {
		x := mkBar() // @Source(nm2)
		a = append(a, x.BarData)
	}
	sink1(a[0]) // @Sink(nm1, nm2)
}

func testMultipleSources3() {
	a := make([]*string, 2)
	b := "ok"
	a[0] = &b
	if random.Int() > 10 {
		b = fmt.Sprintf("tainted") // @Source(m1)
	} else {
		for i := 0; i < 10; i++ {
			b = fmt.Sprintf("tainted too") // @Source(m3)
			if b == "ok" {
				x := mkBar() //@Source(m2)
				b = b + x.BarData
			} else {
				b = *a[0] + "0"
			}
		}
	}
	sink1(*a[0]) // @Sink(m1,m2,m3)
}

func main() {
	simple1()
	part2()
	testFlow1()
	testFlow2()
	testChan()
	testChan2()
	testChan3()
	testFieldSensitivity()
	testAliasing1()
	testAliasing2()
	testSlice()
	testMap()
	testNestedStructAliasing()
	testMapAndFieldSensitivity()
	testMapAndField2()
	ignore(testReturnTaintedValue())
	ignore(testLongFunction())
	testMultipleSources1()
	testMultipleSources2()
	testMultipleSources3()
}
