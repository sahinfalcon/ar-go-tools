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
	"slices"

	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/dataflow"
	"github.com/awslabs/ar-go-tools/analysis/lang"
	"github.com/awslabs/ar-go-tools/analysis/summaries"
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
	// specifiying the value it should be initialized to according to the spec.
	fieldToConst map[*types.Var]*ssa.NamedConst
}

// ZeroAlloc is an empty (zero) allocation of a struct.
type ZeroAlloc struct {
	// Alloc is the allocation instruction.
	Alloc *ssa.Alloc
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
	infos, err := initInfos(state, specs)
	res.InitInfos = infos
	if err != nil {
		return res, err
	}
	logger.Tracef("initInfos: %+v\n", res.InitInfos)
	for _, info := range res.InitInfos {
		logger.Tracef("fieldToConst:\n")
		for f, c := range info.fieldToConst {
			logger.Tracef("\t%v -> %v\n", f, c)
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

			pos := program.Fset.Position(instr.Pos())
			switch instr := instr.(type) {
			case *ssa.Alloc:
				if structTypes, ok := addZeroAlloc(res, instr); ok {
					logger.Tracef("found zero alloc: %v at %v\n", instr, pos)
					infos := res.InitInfos[structTypes.named]
					infos.ZeroAllocs = append(infos.ZeroAllocs, ZeroAlloc{Alloc: instr, Pos: pos})
					res.InitInfos[structTypes.named] = infos
				}
			case *ssa.Store:
				if write, ok := isInvalidWrite(res, instr, pos); ok {
					logger.Tracef("found invalid write: %v at %v\n", instr, pos)
					namedType := write.structTypes.named
					writes := res.InitInfos[namedType].InvalidWrites[write.fieldType]
					res.InitInfos[namedType].InvalidWrites[write.fieldType] = append(writes, write.write)
				}
			}
		})
	}

	return res, nil
}

func initInfos(state *dataflow.AnalyzerState, specs []config.StructInitSpec) (map[*types.Named]InitInfo, error) {
	res := make(map[*types.Named]InitInfo)
	fns := state.ReachableFunctions()
	initialized := make(map[config.CodeIdentifier]bool)
	for fn := range fns {
		if err := lang.IterateInstructionsFallible(fn, func(_ int, instr ssa.Instruction) error {
			if alloc, ok := instr.(*ssa.Alloc); ok {
				for _, spec := range specs {
					if initialized[spec.Struct] {
						continue
					}

					structTypes, ok := isAllocOfStructPtr(alloc)
					if !ok {
						continue
					}

					structType := structTypes.strct
					// match the name of the struct, not the struct type itself
					if !spec.Struct.MatchType(structTypes.named) {
						continue
					}

					if _, ok := res[structTypes.named]; ok {
						return fmt.Errorf("InitInfo for struct %v should have already been initialized", structTypes.named)
					}

					info, err := newInitInfo(spec, structType, state)
					if err != nil {
						return fmt.Errorf("failed to create InitInfo: %v", err)
					}

					res[structTypes.named] = info
					initialized[spec.Struct] = true
				}
			}

			return nil
		}); err != nil {
			return res, err
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

func addZeroAlloc(res AnalysisResult, alloc *ssa.Alloc) (structTypes, bool) {
	s, ok := isAllocOfStructPtr(alloc)
	if !ok {
		return s, false
	}

	for structNamed := range res.InitInfos {
		if s.named == structNamed {
			if isZeroAlloc(alloc) {
				return s, true
			}
		}
	}

	return s, false
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

func structInitSpecs(cfg *config.Config) []config.StructInitSpec {
	var res []config.StructInitSpec
	for _, sspec := range cfg.SyntacticProblems {
		for _, stspec := range sspec.StructInitProblems {
			res = append(res, stspec)
		}
	}

	return res
}

// structTypes contains both the named struct type (e.g., "[...]syntactic/structinit.structTypes") and its
// underlying struct type (e.g. "struct { strct: [...] }").
type structTypes struct {
	strct *types.Struct
	named *types.Named
}

func isAllocOfStructPtr(alloc *ssa.Alloc) (structTypes, bool) {
	typ := alloc.Type().Underlying().(*types.Pointer).Elem() // always safe for allocs
	if n, ok := typ.(*types.Named); ok {
		if s, ok := n.Underlying().(*types.Struct); ok {
			return structTypes{strct: s, named: n}, true
		}
	}

	return structTypes{}, false
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

func isZeroAlloc(alloc *ssa.Alloc) bool {
	var fieldAddrs []*ssa.FieldAddr
	instrs := alloc.Block().Instrs

	for _, instr := range instrs {
		if fieldAddr, ok := instr.(*ssa.FieldAddr); ok {
			if fieldAddr.X == alloc {
				fieldAddrs = append(fieldAddrs, fieldAddr)
			}
		}
	}

	for _, instr := range instrs {
		if store, ok := instr.(*ssa.Store); ok {
			if addr, ok := store.Addr.(*ssa.FieldAddr); ok {
				if slices.Contains(fieldAddrs, addr) {
					return false
				}
			}
		}
	}

	return true
}

func fieldOfStructPtr(fieldAddr *ssa.FieldAddr, structCi config.CodeIdentifier, spec config.FieldsSetSpec) (*types.Struct, *types.Var, bool) {
	strct := fieldAddr.X
	if ptr, ok := strct.Type().(*types.Pointer); ok {
		if named, ok := ptr.Elem().(*types.Named); ok {
			if s, ok := named.Underlying().(*types.Struct); ok {
				if structCi.MatchType(s) {
					field := s.Field(fieldAddr.Field)
					if field != nil && field.IsField() && field.Name() == spec.Field {
						return s, field, true
					}
				}
			}
		}
	}

	return nil, nil, false
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
