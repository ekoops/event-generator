// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/spf13/cobra"

	"github.com/falcosecurity/event-generator/events"
	// register event collections
	_ "github.com/falcosecurity/event-generator/events/k8saudit"
	_ "github.com/falcosecurity/event-generator/events/syscall"
)

// NewList instantiates the list subcommand.
func NewList() *cobra.Command {
	c := &cobra.Command{
		Use:   "list [regexp]",
		Short: "List available actions",
		Long: `Without arguments it lists all actions, otherwise only those actions matching the given regular expression.
`,
		Args:              cobra.MaximumNArgs(1),
		DisableAutoGenTag: true,
	}

	flags := c.Flags()
	flags.Bool("all", false, "List all actions, including those disabled by default")

	c.RunE = func(c *cobra.Command, args []string) error {

		all, err := flags.GetBool("all")
		if err != nil {
			return err
		}

		var evts map[string]events.Action
		if len(args) == 0 {
			evts = events.All()
		} else {

			reg, err := regexp.Compile(args[0])
			if err != nil {
				return err
			}

			evts = events.ByRegexp(reg)
			if len(evts) == 0 {
				return fmt.Errorf(`no events matching '%s'`, args[0])
			}
		}

		var actions []string
		for action := range evts {
			if !all && events.Disabled(action) {
				continue
			}
			actions = append(actions, action)
		}

		if len(actions) == 0 {
			return fmt.Errorf(`no enabled events matching '%s'`, args[0])
		}

		sort.Strings(actions)

		for _, v := range actions {
			fmt.Println(v)
		}

		return nil
	}

	return c
}
