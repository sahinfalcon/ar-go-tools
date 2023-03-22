package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/awslabs/argot/analysis"
	"github.com/awslabs/argot/analysis/refactor"
	"github.com/dave/dst/decorator"
	"golang.org/x/tools/go/packages"
)

func main() {
	flag.Parse()

	config := &packages.Config{
		Mode:  analysis.PkgLoadMode,
		Tests: false,
	}

	// load, parse and type check the given packages
	loadedPackages, err := decorator.Load(config, flag.Args()...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load packages: %s", err)
		os.Exit(1)
	}
	refactor.AssignUnhandledErrors(loadedPackages)
}
