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

package syntactic

import (
	"fmt"
	"log"
	"os"

	"github.com/awslabs/ar-go-tools/analysis"
	"github.com/awslabs/ar-go-tools/analysis/config"
	"github.com/awslabs/ar-go-tools/analysis/syntactic/structinit"
	"github.com/awslabs/ar-go-tools/cmd/argot/tools"
	"github.com/awslabs/ar-go-tools/internal/formatutil"
	"golang.org/x/tools/go/ssa"
)

// Usage is the usage info for the syntactic analyses.
const Usage = ` Perform syntactic checks on your packages.
Usage:
  argot syntactic [options] <package path(s)>
Examples:
  % argot syntactic -config config.yaml package...
`

// Run runs the syntactic analyses.
func Run(flags tools.CommonFlags) error {
	logger := log.New(os.Stdout, "", log.Flags())

	cfg, err := tools.LoadConfig(flags.ConfigPath)
	if err != nil {
		return err
	}

	// Override config parameters with command-line parameters
	if flags.Verbose {
		cfg.LogLevel = int(config.DebugLevel)
	}
	logger.Printf(formatutil.Faint("Reading sources") + "\n")

	if len(cfg.SyntacticProblems) == 0 {
		return fmt.Errorf("no syntactic problems in config file")
	}

	opts := analysis.LoadProgramOptions{
		BuildMode:     ssa.InstantiateGenerics,
		LoadTests:     flags.WithTest,
		ApplyRewrites: false,
		Platform:      "",
		PackageConfig: nil,
	}
	prog, pkgs, err := analysis.LoadProgram(opts, flags.FlagSet.Args())
	if err != nil {
		return fmt.Errorf("failed to load program: %v", err)
	}

	for _, syn := range cfg.SyntacticProblems {
		if len(syn.StructInitProblems) > 0 {
			logger.Printf("starting struct init analysis...\n")
			res, err := structinit.Analyze(cfg, prog, pkgs)
			if err != nil {
				return fmt.Errorf("struct init analysis error: %v", err)
			}

			s, failed := structinit.ReportResults(res)
			logger.Println(s)
			if failed {
				os.Exit(1)
			}
		}
	}

	return nil
}
