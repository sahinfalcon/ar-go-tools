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

/*
Package syntactic implements the front-end to the Argot syntactic tool which
runs different syntactic checks on your code.

Usage:

	argot syntactic [flags] -config config.yaml main.go

The flags are:

	-config path      a path to the configuration file containing definitions for syntactic problems

	-verbose=false    setting verbose mode, overrides config file options if set
*/
package syntactic
