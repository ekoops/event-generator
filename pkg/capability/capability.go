// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 The Falco Authors
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

package capability

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
	"kernel.org/pub/linux/libs/security/libcap/cap"
)

// Parse the provided capabilities string and returns the parsed capability state. The provided capabilities must be
// encoded using the syntax specified in cap_from_text(3).
func Parse(capabilities string) (*cap.Set, error) {
	return cap.FromText(capabilities)
}

// RunWithSecBitNoRootEnabled runs the provided function with the thread secure bit SECBIT_NOROOT enabled.
func RunWithSecBitNoRootEnabled(f func() error) (err error) {
	runtime.LockOSThread()
	secureBits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("error retrieving thread secure bits: %w", err)
	}

	secureBitsPlusSecBitNoRoot := secureBits | int(cap.SecbitNoRoot)
	if secureBits == secureBitsPlusSecBitNoRoot {
		return runFuncAndWrapErr(f)
	}

	if err := unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(secureBitsPlusSecBitNoRoot), 0, 0, 0); err != nil {
		return fmt.Errorf("error setting thread secure bits: %w", err)
	}
	defer func() {
		if e := unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(secureBits), 0, 0, 0); e != nil {
			e = fmt.Errorf("error restoring secure bits: %w", err)
			if err != nil {
				err = fmt.Errorf("%w; %w", err, e)
			} else {
				err = e
			}
		}
	}()

	return runFuncAndWrapErr(f)
}

// RunWithSecBitNoRootDisabled runs the provided function with the thread secure bit SECBIT_NOROOT disable.
func RunWithSecBitNoRootDisabled(f func() error) (err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	secureBits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("error retrieving thread secure bits: %w", err)
	}

	secureBitsMinusSecBitNoRoot := secureBits & ^int(cap.SecbitNoRoot)
	if secureBits == secureBitsMinusSecBitNoRoot {
		return runFuncAndWrapErr(f)
	}

	if err := unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(secureBitsMinusSecBitNoRoot), 0, 0, 0); err != nil {
		return fmt.Errorf("error setting thread secure bits: %w", err)
	}
	defer func() {
		if e := unix.Prctl(unix.PR_SET_SECUREBITS, uintptr(secureBits), 0, 0, 0); e != nil {
			e = fmt.Errorf("error restoring secure bits: %w", err)
			if err != nil {
				err = fmt.Errorf("%w; %w", err, e)
			} else {
				err = e
			}
		}
	}()

	return runFuncAndWrapErr(f)
}

// runFuncAndWrapErr runs the provided function and wraps the returned error with FuncError.
func runFuncAndWrapErr(f func() error) error {
	if err := f(); err != nil {
		return &FuncError{err: err}
	}
	return nil
}

// FuncError wraps the error produced by the execution of the function provided to RunWithSecBitNoRootEnabled and
// RunWithSecBitNoRootDisabled.
type FuncError struct {
	err error
}

func (e *FuncError) Error() string {
	return e.err.Error()
}