// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025 The Falco Authors
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

package connect

import (
	"context"
	"reflect"

	"golang.org/x/sys/unix"

	"github.com/falcosecurity/event-generator/pkg/test/step"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall"
	"github.com/falcosecurity/event-generator/pkg/test/step/syscall/base"
)

type connectSyscall struct {
	*base.Syscall
	// args represents arguments that can be provided by value or by binding.
	args struct {
		FD      int           `field_type:"fd"`
		Address unix.Sockaddr `field_type:"socket_address"`
	}
	// bindOnlyArgs represents arguments that can only be provided by binding.
	bindOnlyArgs struct{}
	Ret          int `field_type:"-"`
}

// New creates a new connect system call test step.
func New(name string, rawArgs map[string]any, fieldBindings []*step.FieldBinding) (syscall.Syscall, error) {
	c := &connectSyscall{}
	argsContainer := reflect.ValueOf(&c.args).Elem()
	bindOnlyArgsContainer := reflect.ValueOf(&c.bindOnlyArgs).Elem()
	retValContainer := reflect.ValueOf(c).Elem()
	var err error
	c.Syscall, err = base.New(name, rawArgs, fieldBindings, argsContainer, bindOnlyArgsContainer, retValContainer)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (c *connectSyscall) Run(_ context.Context) error {
	if err := c.CheckUnboundArgField(); err != nil {
		return err
	}

	if err := unix.Connect(c.args.FD, c.args.Address); err != nil {
		return err
	}

	c.Ret = 0
	return nil
}
