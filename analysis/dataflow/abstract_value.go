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

package dataflow

import (
	"fmt"
	"io"
	"maps"
	"strings"

	"golang.org/x/tools/go/ssa"
)

// maxAccessPathLength bound the maximum length of an access path TODO: make this a config option
// this value does not affect soundness
const maxAccessPathLength = 4

type MarkWithAccessPath struct {
	Mark       *Mark
	AccessPath string
}

type ValueWithAccessPath struct {
	Value         ssa.Value
	Instruction   ssa.Instruction
	Path          string
	FromProcEntry bool
}

type AbstractValue struct {
	value           ssa.Value
	isPathSensitive bool
	marks           map[*Mark]bool
	accessMarks     map[string]map[*Mark]bool
}

func NewAbstractValue(v ssa.Value, pathSensitive bool) *AbstractValue {
	if pathSensitive {
		return &AbstractValue{
			value:           v,
			accessMarks:     map[string]map[*Mark]bool{},
			marks:           nil,
			isPathSensitive: true,
		}
	} else {
		return &AbstractValue{
			value:           v,
			accessMarks:     nil,
			marks:           map[*Mark]bool{},
			isPathSensitive: false,
		}
	}
}

func (a *AbstractValue) PathMappings() map[string]map[*Mark]bool {
	if a.isPathSensitive {
		return a.accessMarks
	} else {
		return map[string]map[*Mark]bool{"": a.marks}
	}
}

func (a *AbstractValue) GetValue() ssa.Value {
	return a.value
}

func (a *AbstractValue) add(path string, mark *Mark) {
	if a.isPathSensitive {
		if _, ok := a.accessMarks[path]; !ok {
			a.accessMarks[path] = map[*Mark]bool{}
		}
		a.accessMarks[path][mark] = true
	} else {
		a.marks[mark] = true
	}
}

// MarksAt returns all the marks on the abstract value for a certain path. For example, if the value is marked at
// ".field" by [m] and at "[*]" by [m'] then MarksAt(".field") will return "[m]" and MarksAt("[*]") will return "[m']".
// MarksAt("") will return [m,m']
// if the value is marked at "", by m”, then MarksAt(".field") will return "[m,m”]"
func (a *AbstractValue) MarksAt(path string) []MarkWithAccessPath {
	if path == "" || !a.isPathSensitive {
		return a.AllMarks()
	}
	marks := []MarkWithAccessPath{}
	for p, m := range a.accessMarks {
		// Logic for matching paths
		relAccessPath, ok := strings.CutPrefix(p, path)
		if p == "" {
			relAccessPath = p
			ok = true
		}
		// If path matches, then add the marks with the right path
		if ok {
			for mark := range m {
				marks = append(marks, MarkWithAccessPath{mark, relAccessPath})
			}
		}
	}
	return marks
}

func (a *AbstractValue) AllMarks() []MarkWithAccessPath {
	if a == nil {
		return []MarkWithAccessPath{}
	}
	var x []MarkWithAccessPath
	if a.isPathSensitive {
		for path, marks := range a.accessMarks {
			for mark := range marks {
				x = append(x, MarkWithAccessPath{mark, path})
			}
		}
	} else {
		for mark := range a.marks {
			x = append(x, MarkWithAccessPath{mark, ""})
		}
	}
	return x
}

func (a *AbstractValue) mergeInto(b *AbstractValue) bool {
	if a == nil {
		return false
	}
	modified := false
	if a.isPathSensitive {
		if b.isPathSensitive {
			// merge a path-sensitive value into a path-sensitive one
			// paths need to be transferred
			for path, aMarks := range a.accessMarks {
				if bMarks, ok := b.accessMarks[path]; !ok {
					b.accessMarks[path] = maps.Clone(aMarks)
					modified = true
				} else {
					for m := range aMarks {
						if !bMarks[m] {
							bMarks[m] = true
							modified = true
						}
					}
				}
			}
		} else {
			// merge into a non-access-path-sensitive value
			// access path information gets lost
			for _, m := range a.AllMarks() {
				if !b.marks[m.Mark] {
					modified = true
					b.marks[m.Mark] = true
				}
			}
		}
	} else {
		if b.isPathSensitive {
			// transfer the marks of a to the root of b (path "")
			for mark := range a.marks {
				if bRootMapping, ok := b.accessMarks[""]; !ok {
					b.accessMarks[""] = map[*Mark]bool{mark: true}
				} else if !bRootMapping[mark] {
					modified = true
					b.accessMarks[""][mark] = true
				}
			}
		} else {
			// both a not path-sensitive
			for mark := range a.marks {
				if !b.marks[mark] {
					b.marks[mark] = true
					modified = true
				}
			}
		}
	}
	return modified
}

// HasMarkAt returns a boolean indicating whether the abstractValue has a mark at the given path.
func (a *AbstractValue) HasMarkAt(path string, m *Mark) bool {
	if !a.isPathSensitive {
		return a.marks[m]
	} else {
		for _, m2 := range a.MarksAt(path) {
			if m2.Mark == m {
				return true
			}
		}
		return false
	}
}

// Show writes information about the value on the writer
func (a *AbstractValue) Show(w io.Writer) {
	if !a.isPathSensitive {
		for mark := range a.marks {
			fmt.Fprintf(w, "   %s = %s marked by <%s>", a.value.Name(), a.value, mark.String())
		}
	} else {
		for path, marks := range a.accessMarks {
			fmt.Fprintf(w, "   %s = %s .%s marked by ", a.value.Name(), a.value, path)
			for mark := range marks {
				fmt.Fprintf(w, " <%s> ", mark)
			}
			fmt.Fprintf(w, "\n")
		}
	}
}

func pathLen(path string) int {
	return 1 + strings.Count(path, "[*]") + strings.Count(path, ".")
}

func pathTrimLast(path string) string {
	if path == "" {
		return ""
	}
	if prefix, ok := strings.CutSuffix(path, "[*]"); ok {
		return prefix
	}
	n := strings.LastIndex(path, ".")
	if n > 0 {
		return path[n:]
	} else {
		return path
	}
}

func pathPrependField(path string, fieldName string) string {
	if pathLen(path) > maxAccessPathLength {
		path = pathTrimLast(path)
	}
	return "." + fieldName + path
}

func pathPrependIndexing(path string) string {
	if pathLen(path) > maxAccessPathLength {
		path = pathTrimLast(path)
	}
	return "[*]" + path
}

func pathAppendField(path string, fieldName string) string {
	if pathLen(path) > maxAccessPathLength {
		return path
	}
	return path + "." + fieldName
}

func pathAppendIndexing(path string) string {
	if pathLen(path) > maxAccessPathLength {
		return path
	}
	return path + "[*]"
}

func pathMatchField(path string, fieldName string) (string, bool) {
	if path == "" {
		return "", true
	}
	return strings.CutPrefix(path, "."+fieldName)
}

func pathMatchIndex(path string) (string, bool) {
	if path == "" {
		return "", true
	}
	return strings.CutPrefix(path, "[*]")
}
