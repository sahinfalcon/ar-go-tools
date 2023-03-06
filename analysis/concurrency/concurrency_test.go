package concurrency

import (
	"log"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"testing"

	. "git.amazon.com/pkg/ARG-GoAnalyzer/analysis/functional"
	"git.amazon.com/pkg/ARG-GoAnalyzer/analysis/utils"
)

func loadConcurrencyTestResult(t *testing.T, subDir string) AnalysisResult {
	// Change directory to the testdata folder to be able to load packages
	_, filename, _, _ := runtime.Caller(0)
	dir := path.Join(path.Dir(filename), "../../testdata/src/concurrency/", subDir)
	err := os.Chdir(dir)
	if err != nil {
		panic(err)
	}

	program, cfg := utils.LoadTest(t, ".", []string{})
	ar, err := Analyze(log.New(os.Stdout, "[TEST] ", log.Flags()), cfg, program)
	if err != nil {
		t.Fatalf("taint analysis returned error %v", err)
	}
	// Remove reports - comment if you want to inspect
	os.RemoveAll(cfg.ReportsDir)
	return ar
}

func TestTrivial(t *testing.T) {
	ar := loadConcurrencyTestResult(t, "trivial")

	for goInstr, id := range ar.GoCalls {
		t.Logf("%d : %s @ %s", id, goInstr, ar.Cache.Program.Fset.Position(goInstr.Pos()))
	}

	res := make(map[string]string, len(ar.NodeColors))
	for node, color := range ar.NodeColors {

		e := strings.Join(Map(SetToSlice(color), func(i uint32) string { return strconv.Itoa(int(i)) }), ",")
		t.Logf("Node %s - %s", node.String(), e)

		if (node.Func.Name() == "main" || node.Func.Name() == "init") && (len(color) != 1 || !color[0]) {
			t.Fatalf("main should be top-level (color 0)")
		}

		res[node.Func.Name()] = e
	}
	if res["f1"] != res["f11"] {
		t.Fatalf("f1 and f11 should be in the same thread, but they have color %s and %s", res["f1"], res["f11"])
	}
	if !strings.Contains(res["f13"], res["f2"]) {
		t.Fatalf("f13 should be in f2's thread, but got f2:%s and f3:%s", res["f2"], res["f3"])
	}
}
