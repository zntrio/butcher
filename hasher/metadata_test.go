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

package hasher

import (
	"strings"
	"testing"
)

func TestMetadata_Decode(t *testing.T) {
	tcl := []struct {
		name        string
		expectedErr bool
	}{
		{
			name:        "hAMBWCAURSV6zNwJgY9MtRymp",
			expectedErr: true,
		},
		{
			name:        "hAMBWCAURSV6zNwJgY9MtRymp+jWqQdq4Q0fhhhczHIJ84hLFFhApev/iws0lknOXrn6S7oHHfURSraeIa8ysojC8WRIFFaZoRi/h3Um/ykq1G76kIWC5I/Fe05qM66CDBHOqEGPSA",
			expectedErr: false,
		},
		{
			name:        "hAEBWCBnIz1y1hBbnAwny+oWiR2r+YTcUDJkZ8NCr46Solr9zlhABAqWOJwohFZk0Oz2HvzdK4IjKwTyZx+wYLJxixhQH86ehBI666XiIkRXAK9p3/vH98we+awVEdBZGNLnuka3/g",
			expectedErr: false,
		},
		{
			name:        "hAIBWCAE69ESLmWerPebeBHAD8KyDncqt+1U+QF3LscPP5AV2VhA3G2KtkK5jwvfeZ8MD+PFWJiA0ufq8ZrBbEe7IeqcHORQrOPaElDM4R6AiVCKU2YQAL1PvFf3wYJVDAQz6pnjew",
			expectedErr: false,
		},
	}

	for _, tc := range tcl {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Decode(strings.NewReader(tc.name))
			if err != nil && !tc.expectedErr {
				t.Errorf("error raised, got %v", err)
			}
			if m != nil && tc.expectedErr {
				t.Errorf("metadata should be nil, got %v", m)
			}
			if m == nil && tc.expectedErr == false {
				t.Errorf("metadata should not be nil, got %v", m)
			}
		})
	}
}
