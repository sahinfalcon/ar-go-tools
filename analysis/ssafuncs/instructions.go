// Package ssafuncs provides functions to operate on the SSA representation of a program.
// It provides an interface to implement visitors for SSA instructions.
package ssafuncs

import (
	"golang.org/x/tools/go/ssa"
)

// This implementation is inspired from the Go ssa interpreter
// https://cs.opensource.google/go/x/tools/+/refs/tags/v0.2.0:go/ssa/interp/interp.go
// Its main use is to provide "documentation" on what are the SSA instructions

// An InstrOp must implement methods for ALL possible SSA instructions
type InstrOp interface {
	DoDebugRef(*ssa.DebugRef)
	DoUnOp(*ssa.UnOp)
	DoBinOp(*ssa.BinOp)
	DoCall(*ssa.Call)
	DoChangeInterface(*ssa.ChangeInterface)
	DoChangeType(*ssa.ChangeType)
	DoConvert(*ssa.Convert)
	DoSliceArrayToPointer(*ssa.SliceToArrayPointer)
	DoMakeInterface(*ssa.MakeInterface)
	DoExtract(*ssa.Extract)
	DoSlice(*ssa.Slice)
	DoReturn(*ssa.Return)
	DoRunDefers(*ssa.RunDefers)
	DoPanic(*ssa.Panic)
	DoSend(*ssa.Send)
	DoStore(*ssa.Store)
	DoIf(*ssa.If)
	DoJump(*ssa.Jump)
	DoDefer(*ssa.Defer)
	DoGo(*ssa.Go)
	DoMakeChan(*ssa.MakeChan)
	DoAlloc(*ssa.Alloc)
	DoMakeSlice(*ssa.MakeSlice)
	DoMakeMap(*ssa.MakeMap)
	DoRange(*ssa.Range)
	DoNext(*ssa.Next)
	DoFieldAddr(*ssa.FieldAddr)
	DoField(*ssa.Field)
	DoIndexAddr(*ssa.IndexAddr)
	DoIndex(*ssa.Index)
	DoLookup(*ssa.Lookup)
	DoMapUpdate(*ssa.MapUpdate)
	DoTypeAssert(*ssa.TypeAssert)
	DoMakeClosure(*ssa.MakeClosure)
	DoPhi(*ssa.Phi)
	DoSelect(*ssa.Select)
}

// InstrSwitch is mainly a map from the different instructions to the methods of the visitor.
func InstrSwitch(visitor InstrOp, instr ssa.Instruction) {
	switch instr := instr.(type) {
	case *ssa.DebugRef:
	// no-op
	case *ssa.UnOp:
		visitor.DoUnOp(instr)
	case *ssa.BinOp:
		visitor.DoBinOp(instr)
	case *ssa.Call:
		visitor.DoCall(instr)
	case *ssa.ChangeInterface:
		visitor.DoChangeInterface(instr)
	case *ssa.ChangeType:
		visitor.DoChangeType(instr)
	case *ssa.Convert:
		visitor.DoConvert(instr)
	case *ssa.SliceToArrayPointer:
		visitor.DoSliceArrayToPointer(instr)
	case *ssa.Extract:
		visitor.DoExtract(instr)
	case *ssa.Slice:
		visitor.DoSlice(instr)
	case *ssa.Return:
		visitor.DoReturn(instr)
	case *ssa.RunDefers:
		visitor.DoRunDefers(instr)
	case *ssa.Panic:
		visitor.DoPanic(instr)
	case *ssa.Send:
		visitor.DoSend(instr)
	case *ssa.Store:
		visitor.DoStore(instr)
	case *ssa.If:
		visitor.DoIf(instr)
	case *ssa.Jump:
		visitor.DoJump(instr)
	case *ssa.Defer:
		visitor.DoDefer(instr)
	case *ssa.Go:
		visitor.DoGo(instr)
	case *ssa.MakeChan:
		visitor.DoMakeChan(instr)
	case *ssa.Alloc:
		visitor.DoAlloc(instr)
	case *ssa.MakeSlice:
		visitor.DoMakeSlice(instr)
	case *ssa.MakeMap:
		visitor.DoMakeMap(instr)
	case *ssa.Range:
		visitor.DoRange(instr)
	case *ssa.Next:
		visitor.DoNext(instr)
	case *ssa.FieldAddr:
		visitor.DoFieldAddr(instr)
	case *ssa.Field:
		visitor.DoField(instr)
	case *ssa.IndexAddr:
		visitor.DoIndexAddr(instr)
	case *ssa.Index:
		visitor.DoIndex(instr)
	case *ssa.Lookup:
		visitor.DoLookup(instr)
	case *ssa.MapUpdate:
		visitor.DoMapUpdate(instr)
	case *ssa.TypeAssert:
		visitor.DoTypeAssert(instr)
	case *ssa.MakeClosure:
		visitor.DoMakeClosure(instr)
	case *ssa.MakeInterface:
		visitor.DoMakeInterface(instr)
	case *ssa.Phi:
		visitor.DoPhi(instr)
	case *ssa.Select:
		visitor.DoSelect(instr)
	default:
		panic(instr)
	}
}

// Utilities for working with blocks and instructions

// LastInstr returns the last instruction in a block. There is always a last instruction for a reachable block.
// Returns nil for an empty block (a block can be empty if it is non-reachable)
func LastInstr(block *ssa.BasicBlock) ssa.Instruction {
	if len(block.Instrs) == 0 {
		return nil
	} else {
		return block.Instrs[len(block.Instrs)-1]
	}
}

// FirstInstr returns the first instruction in a block. There is always a first instruction for a reachable block.
// Returns nil for an empty block (a block can be empty if it is non-reachable)
func FirstInstr(block *ssa.BasicBlock) ssa.Instruction {
	if len(block.Instrs) == 0 {
		return nil
	} else {
		return block.Instrs[0]
	}
}
