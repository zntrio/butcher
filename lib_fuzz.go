// Licensed to Butcher under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Butcher licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build gofuzz
// +build gofuzz

package butcher

// Fuzz usage:
//
//	go get github.com/dvyukov/go-fuzz/...
//
//	go-fuzz-build github.com/zntrio/butcher && go-fuzz -bin=./butcher-fuzz.zip -workdir=/tmp/butcher-fuzz
func Fuzz(data []byte) int {
	hResult, err := Hash(data)
	if err != nil {
		if hResult != "" {
			panic("hResult != '' on error")
		}
		return 2
	}
	valid, err := Verify([]byte(hResult), data)
	if err != nil {
		if valid {
			panic("valid is true on error")
		}
		return 2
	}
	return 1
}
