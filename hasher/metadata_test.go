/*
 * The MIT License (MIT)
 * Copyright (c) 2019 Thibault NORMAND
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

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
