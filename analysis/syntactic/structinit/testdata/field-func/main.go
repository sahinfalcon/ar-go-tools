// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
)

type target struct {
	f func() int
}

type nested struct {
	target
}

type nestedPtr struct {
	*target
}

func Func() int {
	return 1
}

func invalid() int {
	return 1
}

func testWrites() {
	ex1 := target{f: nil} // @InvalidWrite(target)
	fmt.Println(ex1)

	ex2 := &target{f: nil} // @InvalidWrite(target)
	fmt.Println(ex2)

	ex3 := target{f: Func} // ok
	fmt.Println(ex3)

	f := Func
	ex4 := target{f: f} // ok
	fmt.Println(ex4)

	ex5 := target{f: invalid} // @InvalidWrite(target)
	fmt.Println(ex5)

	g := invalid
	ex6 := target{g} // @InvalidWrite(target)
	fmt.Println(ex6)

	ex7 := target{func() int { return Func() }} // @InvalidWrite(target)
	fmt.Println(ex7)
}

func testNestedWrites() {
	ex1 := nested{target{f: invalid}} // @InvalidWrite(target)
	fmt.Println(ex1)

	ex2 := &nested{target{f: invalid}} // @InvalidWrite(target)
	fmt.Println(ex2)

	ex3 := nestedPtr{&target{f: invalid}} // @InvalidWrite(target)
	fmt.Println(ex3)

	ex4 := &nestedPtr{&target{f: invalid}} // @InvalidWrite(target)
	fmt.Println(ex4)

	ex5 := nested{target{f: Func}} // ok
	fmt.Println(ex5)

	ex6 := &nested{target{f: Func}} // ok
	fmt.Println(ex6)

	ex7 := nestedPtr{&target{f: Func}} // ok
	fmt.Println(ex7)

	ex8 := &nestedPtr{&target{f: Func}} // ok
	fmt.Println(ex8)
}

func main() {
	testWrites()
	testNestedWrites()
}
