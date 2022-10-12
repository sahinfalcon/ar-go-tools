// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.

package analysis

import (
	"fmt"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/static"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/pointer"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
	"os"
)

type SsaInfo struct {
	Prog     *ssa.Program
	Packages []*ssa.Package
	Mains    []*ssa.Package
}

const CallgraphPkgLoadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedExportFile |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedTypesSizes |
	packages.NeedModule

type CallgraphAnalysisMode uint64

const (
	PointerAnalysis        CallgraphAnalysisMode = iota // PointerAnalysis is over-approximating (slow)
	StaticAnalysis                                      // StaticAnalysis is under-approximating (fast)
	ClassHierarchyAnalysis                              // ClassHierarchyAnalysis is a coarse over-approximation (fast)
	RapidTypeAnalysis                                   // RapidTypeAnalysis TODO: review
	VariableTypeAnalysis                                // VariableTypeAnalysis TODO: review
)

// ComputeCallgraph computes the call graph of prog using the provided mode.
func (mode CallgraphAnalysisMode) ComputeCallgraph(prog *ssa.Program) (*callgraph.Graph, error) {
	switch mode {
	case PointerAnalysis:
		// Build the callgraph using the pointer analysis. This function returns only the
		// callgraph, and not the entire pointer analysis result.
		// Pointer analysis is using Andersen's analysis. The documentation claims that
		// the analysis is sound if the program does not use reflection or unsafe Go.
		ptrCfg := &pointer.Config{
			Mains:          ssautil.MainPackages(prog.AllPackages()),
			BuildCallGraph: true,
		}
		result, err := pointer.Analyze(ptrCfg)
		if err != nil { // not a user-input problem if it fails, see Analyze doc.
			return nil, fmt.Errorf("pointer analysis failed: %w", err)
		}
		return result.CallGraph, nil
	case StaticAnalysis:
		// Build the callgraph using only static analysis.
		return static.CallGraph(prog), nil
	case ClassHierarchyAnalysis:
		// Build the callgraph using the Class Hierarchy Analysis
		// See the documentation, and
		// "Optimization of Object-Oriented Programs Using Static Class Hierarchy Analysis",
		// J. Dean, D. Grove, and C. Chambers, ECOOP'95.
		return cha.CallGraph(prog), nil
	case VariableTypeAnalysis:
		// Need to review how to use variable type analysis properly
		roots := make(map[*ssa.Function]bool)
		mains := ssautil.MainPackages(prog.AllPackages())
		for _, m := range mains {
			// Look at all init and main functions in main packages
			roots[m.Func("init")] = true
			roots[m.Func("main")] = true
		}
		cg := static.CallGraph(prog)
		return vta.CallGraph(roots, cg), nil
	case RapidTypeAnalysis:
		// Build the callgraph using rapid type analysis
		// See the documentation, and
		// "Fast Analysis of C++ Virtual Function Calls", D.Bacon & P. Sweeney, OOPSLA'96
		var roots []*ssa.Function
		mains := ssautil.MainPackages(prog.AllPackages())
		for _, m := range mains {
			// Start at all init and main functions in main packages
			roots = append(roots, m.Func("init"), m.Func("main"))
		}
		return rta.Analyze(roots, true).CallGraph, nil
	default:
		fmt.Fprint(os.Stderr, "Unsupported callgraph analysis mode.")
		return nil, nil
	}
}
