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

// Package structinit implements the struct initialization syntactic analysis.
package structinit

import (
	"fmt"
	"go/constant"
	"go/token"
	"go/types"
	"strings"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
)

// AnalysisResult is the result of the struct-init analysis.
type AnalysisResult struct {
	// InitInfos is a mapping from the named struct type to its initialization
	// information.
	InitInfos map[*types.Named]InitInfo
}

// InitInfo is the initialization information for a struct.
type InitInfo struct {
	// ZeroAllocs is a list of the zero-value allocations of the struct.
	ZeroAllocs []ZeroAlloc
	// InvalidWrites is a mapping of the struct field to all the invalid writes
	// to that field.
	InvalidWrites map[*types.Var][]InvalidWrite
	// fieldToConst is a mapping of the struct field to the named const
	// specifying the value it should be initialized to according to the spec.
	fieldToConst map[*types.Var]*ssa.NamedConst
}

// ZeroAlloc is an empty (zero) allocation of a struct.
type ZeroAlloc struct {
	// Alloc is the allocation instruction.
	Alloc ssa.Instruction
	// Pos is the position of the instruction.
	Pos token.Position
}

// InvalidWrite is a write to a field of the struct of value Got that is not the
// configured value (Want).
type InvalidWrite struct {
	// Got is the value actually written.
	Got constant.Value
	// Want is the configured value that should have been written.
	Want constant.Value
	// Instr is the instruction performing the write.
	Instr ssa.Instruction
	// Pos is the position of the instruction.
	Pos token.Position
}

// Analyze runs the analysis on prog.
func Analyze(cfg *config.Config, prog *ssa.Program, pkgs []*packages.Package) (AnalysisResult, error) {
	state, err := dataflow.NewInitializedAnalyzerState(prog, pkgs, config.NewLogGroup(cfg), cfg)
	if err != nil {
		return AnalysisResult{}, fmt.Errorf("failed to initialize analyzer state: %v", err)
	}

	program := state.Program
	fns := state.ReachableFunctions()
	if len(fns) == 0 {
		return AnalysisResult{}, fmt.Errorf("no functions found")
	}

	logger := state.Logger
	logger.Infof("Analyzing %d reachable functions...\n", len(fns))

	res := AnalysisResult{InitInfos: make(map[*types.Named]InitInfo)}
	specs := structInitSpecs(cfg)

	allocs := allStructAllocs(fns, specs)
	infos, err := initInfos(state, allocs, specs)
	res.InitInfos = infos
	if err != nil {
		return res, err
	}
	logger.Debugf("initInfos: %+v\n", res.InitInfos)
	for _, info := range res.InitInfos {
		logger.Debugf("fieldToConst:\n")
		for f, c := range info.fieldToConst {
			logger.Debugf("\t%v -> %v\n", f, c)
		}
	}

	for _, alloc := range allocs {
		if isConfiguredZeroAlloc(res, alloc) {
			pos := findAllocPosition(program.Fset, alloc.instr)
			logger.Infof("found zero alloc: %v at %v\n", alloc.instr, pos)
			is := res.InitInfos[alloc.typs.named]
			is.ZeroAllocs = append(is.ZeroAllocs, ZeroAlloc{Alloc: alloc.instr, Pos: pos})
			res.InitInfos[alloc.typs.named] = is
		}
	}

	for fn := range fns {
		lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
			if instr == nil || instr.Parent() == nil || !instr.Pos().IsValid() {
				return
			}
			if summaries.IsStdPackageName(lang.PackageNameFromFunction(instr.Parent())) {
				return
			}

			switch instr := instr.(type) {
			case *ssa.Store:
				pos := program.Fset.Position(instr.Pos())
				if write, ok := isInvalidWrite(res, instr, pos); ok {
					namedType := write.structTypes.named
					logger.Infof("found invalid write of value %v (wanted %v) to struct field %v.%v at %v\n", write.write.Got, write.write.Want, namedType, write.fieldType.Name(), pos)
					writes := res.InitInfos[namedType].InvalidWrites[write.fieldType]
					res.InitInfos[namedType].InvalidWrites[write.fieldType] = append(writes, write.write)
				}
			}
		})
	}

	return res, nil
}

func structInitSpecs(cfg *config.Config) []config.StructInitSpec {
	var res []config.StructInitSpec
	for _, sspec := range cfg.SyntacticProblems {
		for _, stspec := range sspec.StructInitProblems {
			res = append(res, stspec)
		}
	}

	return res
}

func initInfos(state *dataflow.AnalyzerState, allocs []alloced, specs []config.StructInitSpec) (map[*types.Named]InitInfo, error) {
	res := make(map[*types.Named]InitInfo)
	initialized := make(map[config.CodeIdentifier]bool)

	for _, alloc := range allocs {
		for _, spec := range specs {
			if initialized[spec.Struct] {
				continue
			}

			structTypes, ok := isStructType(alloc.val.Type())
			if !ok {
				continue
			}

			structType := structTypes.strct
			// match the name of the struct, not the struct type itself
			if !spec.Struct.MatchType(structTypes.named) {
				continue
			}

			if _, ok := res[structTypes.named]; ok {
				return res, fmt.Errorf("InitInfo for struct %v should have already been initialized", structTypes.named)
			}

			info, err := newInitInfo(spec, structType, state)
			if err != nil {
				return res, fmt.Errorf("failed to create InitInfo: %v", err)
			}

			res[structTypes.named] = info
			initialized[spec.Struct] = true
		}
	}

	return res, nil
}

func newInitInfo(spec config.StructInitSpec, structType *types.Struct, state *dataflow.AnalyzerState) (InitInfo, error) {
	invalidWrites := make(map[*types.Var][]InvalidWrite)
	fieldToConst := make(map[*types.Var]*ssa.NamedConst)
	for _, fieldSpec := range spec.FieldsSet {
		var field *types.Var
		for i := 0; i < structType.NumFields(); i++ {
			f := structType.Field(i)
			if fieldSpec.Field == "" {
				return InitInfo{}, fmt.Errorf("field name in fields-set spec should not be empty: %+v", fieldSpec)
			}
			if fieldSpec.Field == f.Name() {
				field = f
				break
			}
		}
		if field == nil {
			return InitInfo{}, fmt.Errorf("failed to find field %v in struct %v from spec: %+v", fieldSpec.Field, structType, spec)
		}

		invalidWrites[field] = []InvalidWrite{}

		c, ok := findNamedConst(state.Program, fieldSpec.Value)
		if !ok {
			return InitInfo{}, fmt.Errorf("failed to find a named constant %v in spec: %+v", fieldSpec.Value, spec)
		}

		fieldToConst[field] = c
	}

	return InitInfo{
		ZeroAllocs:    []ZeroAlloc{},
		InvalidWrites: invalidWrites,
		fieldToConst:  fieldToConst,
	}, nil
}

// isConfiguredZeroAlloc returns true if the struct allocated in alloc is a
// potential zero-allocation of a struct in res.InitInfos.
func isConfiguredZeroAlloc(res AnalysisResult, alloc alloced) bool {
	for structNamed := range res.InitInfos {
		if matchStructType(alloc.typs.named, structNamed) {
			switch instr := alloc.instr.(type) {
			case *ssa.Alloc:
				if isZeroAlloc(instr) {
					return true
				}
			case *ssa.MakeInterface:
				// TODO confirm:
				// struct converted to an interface will either have been
				// explicitly allocated previously or is initialized to the zero
				// value in the instruction itself
				return true
			}
		}
	}

	return false
}

// isZeroAlloc returns false if there are any writes to any field or sub-field
// of the struct with types s allocated in alloc in the alloc instruction's
// block.
// This means that isZeroAlloc underapproximates zero-allocations because it
// does not analyze all writes in the program.
func isZeroAlloc(alloc *ssa.Alloc) bool {
	fieldAddrs := fieldAddrsOfAlloc(alloc)
	instrs := alloc.Block().Instrs

	for _, instr := range instrs {
		if store, ok := instr.(*ssa.Store); ok {
			if addr, ok := store.Addr.(*ssa.FieldAddr); ok {
				if _, ok := fieldAddrs[addr]; ok {
					return false
				}
			}
		}
	}

	return true
}

// fieldAddrsOfAlloc returns all the instructions that address a field or
// sub-field of the struct allocated in alloc.
func fieldAddrsOfAlloc(alloc *ssa.Alloc) map[*ssa.FieldAddr]struct{} {
	instrs := alloc.Block().Instrs
	fieldAddrs := make(map[*ssa.FieldAddr]struct{})
	vals := map[ssa.Value]struct{}{alloc: {}}
	for _, instr := range instrs {
		if addr, ok := instr.(*ssa.FieldAddr); ok {
			if _, ok := vals[addr.X]; ok {
				fieldAddrs[addr] = struct{}{}
				if _, ok := isStructType(addr.Type()); ok {
					// if the struct field being addressed is a struct,
					// track all future addresses to it
					vals[addr] = struct{}{}
				}
			}
		}
	}

	return fieldAddrs
}

// structTypes contains both the named struct type
// (e.g., "[...]syntactic/structinit.structTypes") and its
// underlying struct type (e.g. "struct { strct: [...] }").
type structTypes struct {
	strct *types.Struct
	named *types.Named
}

// isStructType returns the named and underlying types of t
// if it is a struct or pointer to a struct.
func isStructType(t types.Type) (structTypes, bool) {
	if t.Underlying() == nil {
		return structTypes{}, false
	}

	typ := t
	if ptr, ok := t.Underlying().(*types.Pointer); ok {
		typ = ptr.Elem()
	}
	if n, ok := typ.(*types.Named); ok {
		if s, ok := n.Underlying().(*types.Struct); ok {
			return structTypes{strct: s, named: n}, true
		}
	}

	return structTypes{}, false
}

// alloced is a struct value that was allocated.
// The value either is the result of an allocation instruction or the struct
// that was converted to an interface.
type alloced struct {
	val   ssa.Value       // val is the allocated value.
	typs  structTypes     // typs are the types of val.
	instr ssa.Instruction // instr is the allocation instruction.
}

// allStructAllocs returns all the instructions in fns that can allocate a value.
// An allocation instruction is not always explicit:
// MakeInterface instructions can also "allocate" a value.
func allStructAllocs(fns map[*ssa.Function]bool, specs []config.StructInitSpec) []alloced {
	var allocs []alloced

	for fn := range fns {
		lang.IterateInstructions(fn, func(_ int, instr ssa.Instruction) {
			if instr == nil || instr.Parent() == nil {
				return
			}
			// don't analyze the standard library
			if summaries.IsStdPackageName(lang.PackageNameFromFunction(instr.Parent())) {
				return
			}

			if val, ok := instr.(ssa.Value); ok {
				for _, spec := range specs {
					if isFiltered(spec, val) {
						return
					}
				}
			}

			switch instr := instr.(type) {
			case *ssa.Alloc:
				typs, ok := isStructType(instr.Type())
				if !ok {
					return
				}
				allocs = append(allocs, alloced{val: instr, instr: instr, typs: typs})

			case *ssa.MakeInterface:
				if c, ok := instr.X.(*ssa.Const); ok && c.Value == nil {
					typs, ok := isStructType(instr.X.Type())
					if !ok {
						return
					}
					allocs = append(allocs, alloced{val: instr.X, instr: instr, typs: typs})
				}
			}

			return
		})
	}

	return allocs
}

// matchStructType returns true if named struct type target is either s or one of
// s's fields.
func matchStructType(s types.Type, target *types.Named) bool {
	if s == target {
		return true
	}

	if st, ok := s.Underlying().(*types.Struct); ok {
		for i := 0; i < st.NumFields(); i++ {
			field := st.Field(i)
			if matchStructType(field.Type(), target) { // recursive call
				return true
			}
		}
	}

	return false
}

// findAllocPosition returns the best approximation of instr's position.
// This is kind of a hack because MakeInterface instructions don't have
// positions, so this returns the position of the first store instruction that
// stores the interface value.
func findAllocPosition(fset *token.FileSet, instr ssa.Instruction) token.Position {
	if instr.Pos().IsValid() {
		return fset.Position(instr.Pos())
	}

	if mk, ok := instr.(*ssa.MakeInterface); ok {
		for _, ref := range *mk.Referrers() {
			if s, ok := ref.(*ssa.Store); ok {
				if s.Val == mk && s.Pos().IsValid() {
					return fset.Position(s.Pos())
				}
			}
		}
	}

	panic(fmt.Errorf("invalid instruction type: %T", instr))
}

type writeToField struct {
	structTypes structTypes
	fieldType   *types.Var
	write       InvalidWrite
}

func isInvalidWrite(res AnalysisResult, store *ssa.Store, pos token.Position) (writeToField, bool) {
	field, ok := store.Addr.(*ssa.FieldAddr)
	if !ok {
		return writeToField{}, false
	}

	structTypes, ok := isStoreToStructPtr(field.X)
	if !ok {
		return writeToField{}, false
	}

	infos, ok := res.InitInfos[structTypes.named]
	if !ok {
		return writeToField{}, false
	}

	fieldType := structTypes.strct.Field(field.Field)
	wantConst, ok := infos.fieldToConst[fieldType]
	if !ok {
		// field not in spec
		return writeToField{}, false
	}

	gotConst, ok := store.Val.(*ssa.Const)
	if !ok {
		return writeToField{}, false
	}

	if gotConst == nil || gotConst.Value == nil {
		panic(fmt.Errorf("unexpected nil constant %+v in store instruction to field %v: %v", gotConst, field, store))
	}
	// compare the underlying constant values
	if gotConst.Value == wantConst.Value.Value {
		return writeToField{}, false
	}

	return writeToField{
		structTypes: structTypes,
		fieldType:   fieldType,
		write: InvalidWrite{
			Got:   gotConst.Value,
			Want:  wantConst.Value.Value,
			Instr: store,
			Pos:   pos,
		},
	}, true
}

func isStoreToStructPtr(v ssa.Value) (structTypes, bool) {
	if ptr, ok := v.Type().(*types.Pointer); ok {
		if n, ok := ptr.Elem().(*types.Named); ok {
			if s, ok := n.Underlying().(*types.Struct); ok {
				return structTypes{strct: s, named: n}, true
			}
		}
	}

	return structTypes{}, false
}

func findNamedConst(program *ssa.Program, valCi config.CodeIdentifier) (*ssa.NamedConst, bool) {
	pkgs := program.AllPackages()
	for _, pkg := range pkgs {
		for _, mem := range pkg.Members {
			if c, ok := mem.(*ssa.NamedConst); ok {
				if valCi.MatchConst(c) && c.Value != nil {
					return c, true
				}
			}
		}
	}

	return nil, false
}

// ReportResults writes res to a string and returns true if the analysis should fail.
func ReportResults(res AnalysisResult) (string, bool) {
	failed := false

	w := &strings.Builder{}
	w.WriteString("\nstruct-init analysis results:\n")
	w.WriteString("-----------------------------\n")
	for structName, info := range res.InitInfos {
		w.WriteString(fmt.Sprintf("initialization information for %v:\n", formatutil.Bold(structName)))
		if len(info.ZeroAllocs) == 0 {
			w.WriteString(fmt.Sprintf("\t%v\n", formatutil.Green("no zero-allocations found")))
		}
		for _, alloc := range info.ZeroAllocs {
			w.WriteString(fmt.Sprintf("\t%s: %v at %v\n", formatutil.Red("zero-allocation"), alloc.Alloc, alloc.Pos))
			failed = true
		}

		if len(info.InvalidWrites) == 0 {
			w.WriteString(fmt.Sprintf("\t%v\n", formatutil.Green("no invalid writes found")))
		}
		for field, writes := range info.InvalidWrites {
			w.WriteString(fmt.Sprintf("\t%s of field %v:\n", formatutil.Red("invalid writes"), field.Name()))
			for _, write := range writes {
				w.WriteString(fmt.Sprintf("\t\t%v (got %v, want %v) at %v\n", write.Instr, write.Got, write.Want, write.Pos))
				failed = true
			}
		}
	}

	return w.String(), failed
}

// isFiltered returns true if v is filtered according to spec.
func isFiltered(spec config.StructInitSpec, v ssa.Value) bool {
	for _, filter := range spec.Filters {
		if filter.Type != "" {
			if filter.MatchType(v.Type()) {
				return true
			}
		}

		f := v.Parent()
		if f != nil && filter.Method != "" && filter.Package != "" {
			if filter.MatchPackageAndMethod(f) {
				return true
			}
		}
	}

	return false
}
