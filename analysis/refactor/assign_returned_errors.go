package refactor

import (
	"go/ast"
	"go/token"
	"go/types"

	ac "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/astfuncs"
	"github.com/dave/dst"
	"github.com/dave/dst/decorator"
	"github.com/dave/dst/dstutil"
	"golang.org/x/tools/go/types/typeutil"
)

func anonLhsOfTuple(t *types.Tuple, errId *dst.Ident) []dst.Expr {
	var s []dst.Expr
	for i := 0; i < t.Len()-1; i++ {
		s = append(s, dst.NewIdent("_"))
	}
	s = append(s, errId)
	return s
}

// ReturnsError returns a pair of a tuple of types and a boolean such that the boolean is true whenever the signature
// is the signature of a function returning some error.
func ReturnsError(signature types.Object) (*types.Tuple, bool) {
	switch t := signature.(type) {
	case *types.Func:
		sig := t.Type().(*types.Signature) // cannot fail
		resultType := sig.Results()
		if resultType.Len() > 0 {
			lastRes := resultType.At(resultType.Len() - 1)
			if lastRes.Type().String() == "error" {
				return resultType, true
			}
		}
	}
	return nil, false
}

func assignErrorsTransform(funcInfo *ac.FuncInfo, c *dstutil.Cursor) bool {
	n := c.Node()

	switch x := n.(type) {
	case *dst.ExprStmt:
		if callx, ok := x.X.(*dst.CallExpr); ok {
			// TODO: figure out how to get the closes scope to get fresh variables
			scope, errIdent := funcInfo.NewIdent(n, "err")
			if scope != nil {
				scope.Insert(types.NewVar(token.NoPos, funcInfo.Package.Types, errIdent, nil))
			}
			assignmentToken := token.DEFINE
			callExpr := funcInfo.Decorator.Ast.Nodes[callx].(*ast.CallExpr)
			if retTuple, hasErr := ReturnsError(typeutil.Callee(funcInfo.Package.TypesInfo, callExpr)); hasErr {
				// replace f(..) by  ..., err = f()
				c.Replace(
					&dst.AssignStmt{
						Tok: assignmentToken,
						Lhs: anonLhsOfTuple(retTuple, dst.NewIdent(errIdent)),
						Rhs: []dst.Expr{callx},
						Decs: dst.AssignStmtDecorations{
							NodeDecs: *(n.Decorations()), // copy the existing decorations over
							Tok:      nil,
						},
					})
				// add if err != nil { panic(false) } after
				c.InsertAfter(
					&dst.IfStmt{
						Init: nil,
						// Condition: err != nil
						Cond: &dst.BinaryExpr{
							X:  dst.NewIdent(errIdent),
							Op: token.NEQ,
							Y:  dst.NewIdent("nil"),
						},
						// Body: panic(false)
						Body: &dst.BlockStmt{
							List: []dst.Stmt{
								&dst.ExprStmt{X: ac.NewPanic(ac.NewFalse())},
							},
						},
						// Else empty
						Else: nil,
					})
			}
			return true
		}

	}
	return true
}

// AssignUnhandledErrors transforms the program by refactoring calls to functions that return errors to assignments
// to fresh variables that contain errors
func AssignUnhandledErrors(packages []*decorator.Package) {
	WithScope(packages, assignErrorsTransform)
}
