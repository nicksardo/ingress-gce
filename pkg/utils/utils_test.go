/*
Copyright 2017 The Kubernetes Authors.

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

package utils

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"
)

func TestTrimFieldsEvenly(t *testing.T) {
	longString := "01234567890123456789012345678901234567890123456789"
	testCases := []struct {
		desc   string
		fields []string
		expect []string
		max    int
	}{
		{
			"no change",
			[]string{longString},
			[]string{longString},
			100,
		},
		{
			"equal to max and no change",
			[]string{longString, longString},
			[]string{longString, longString},
			100,
		},
		{
			"equally trimmed to half",
			[]string{longString, longString},
			[]string{longString[:25], longString[:25]},
			50,
		},
		{
			"trimmed to only 10",
			[]string{longString, longString, longString},
			[]string{longString[:4], longString[:3], longString[:3]},
			10,
		},
		{
			"trimmed to only 3",
			[]string{longString, longString, longString},
			[]string{longString[:1], longString[:1], longString[:1]},
			3,
		},
		{
			"one long field with one short field",
			[]string{longString, longString[:1]},
			[]string{longString[:1], ""},
			1,
		},
		{
			"one long field with one short field and trimmed to 5",
			[]string{longString, longString[:1]},
			[]string{longString[:5], ""},
			5,
		},
	}

	for _, tc := range testCases {
		res := trimFieldsEvenly(tc.max, tc.fields...)
		if len(res) != len(tc.expect) {
			t.Fatalf("%s: expect length == %d, got %d", tc.desc, len(tc.expect), len(res))
		}

		totalLen := 0
		for i := range res {
			totalLen += len(res[i])
			if res[i] != tc.expect[i] {
				t.Errorf("%s: the %d field is expected to be %q, but got %q", tc.desc, i, tc.expect[i], res[i])
			}
		}

		if tc.max < totalLen {
			t.Errorf("%s: expect totalLen to be less than %d, but got %d", tc.desc, tc.max, totalLen)
		}
	}
}

func TestResourcePathOfURL(t *testing.T) {
	testCases := []struct {
		url      string
		expected string
	}{
		{
			"global/backendServices/foo",
			"global/backendServices/foo",
		},
		{
			"https://www.googleapis.com/compute/v1/projects/foo/global/backendServices/foo",
			"global/backendServices/foo",
		},
		{
			"https://www.googleapis.com/compute/v1/projects/foo/asdf/zones/us-central1-c/backendServices/foo",
			"",
		},
	}

	for _, tc := range testCases {
		res, _ := ResourcePath(tc.url)
		if res != tc.expected {
			t.Errorf("Expected result after url trim to be %v, but got %v", tc.expected, res)
		}
	}
}

func TestToNamespacedName(t *testing.T) {
	cases := []struct {
		input   string
		wantErr bool
		wantOut types.NamespacedName
	}{
		{
			input:   "kube-system/default-http-backend",
			wantOut: types.NamespacedName{Namespace: "kube-system", Name: "default-http-backend"},
		},
		{
			input:   "abc",
			wantErr: true,
		},
		{
			input:   "",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			gotOut, gotErr := ToNamespacedName(tc.input)
			if tc.wantErr != (gotErr != nil) {
				t.Errorf("ToNamespacedName(%v) = _, %v, want err? %v", tc.input, gotErr, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			if gotOut != tc.wantOut {
				t.Errorf("ToNamespacedName(%v) = %v, want %v", tc.input, gotOut, tc.wantOut)
			}
		})
	}
}

func TestEqualResourcePaths(t *testing.T) {
	testCases := map[string]struct {
		a        string
		b        string
		expected bool
	}{
		"partial vs full": {
			a:        "https://www.googleapis.com/compute/beta/projects/project-id/zones/us-central1-a/instanceGroups/example-group",
			b:        "zones/us-central1-a/instanceGroups/example-group",
			expected: true,
		},
		"full vs full": {
			a:        "https://www.googleapis.com/compute/beta/projects/project-id/zones/us-central1-a/instanceGroups/example-group",
			b:        "https://www.googleapis.com/compute/beta/projects/project-id/zones/us-central1-a/instanceGroups/example-group",
			expected: true,
		},
		"diff projects and versions": {
			a:        "https://www.googleapis.com/compute/v1/projects/project-A/zones/us-central1-a/instanceGroups/example-group",
			b:        "https://www.googleapis.com/compute/beta/projects/project-B/zones/us-central1-a/instanceGroups/example-group",
			expected: true,
		},
		"diff name": {
			a:        "https://www.googleapis.com/compute/v1/projects/project-A/zones/us-central1-a/instanceGroups/example-groupA",
			b:        "https://www.googleapis.com/compute/beta/projects/project-B/zones/us-central1-a/instanceGroups/example-groupB",
			expected: false,
		},
		"diff location": {
			a:        "https://www.googleapis.com/compute/v1/projects/project-A/zones/us-central1-a/instanceGroups/example-group",
			b:        "https://www.googleapis.com/compute/beta/projects/project-B/zones/us-central1-b/instanceGroups/example-group",
			expected: false,
		},
		"diff resource": {
			a:        "https://www.googleapis.com/compute/v1/projects/project-A/zones/us-central1-a/backendServices/example-group",
			b:        "https://www.googleapis.com/compute/beta/projects/project-B/zones/us-central1-b/instanceGroups/example-group",
			expected: false,
		},
		"bad input a": {
			a:        "/project-A/zones/us-central1-a/backendServices/example-group",
			b:        "https://www.googleapis.com/compute/beta/projects/project-B/zones/us-central1-b/instanceGroups/example-group",
			expected: false,
		},
		"bad input b": {
			a:        "https://www.googleapis.com/compute/beta/projects/project-B/zones/us-central1-b/instanceGroups/example-group",
			b:        "/project-A/zones/us-central1-a/backendServices/example-group",
			expected: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			if got := EqualResourcePaths(tc.a, tc.b); got != tc.expected {
				t.Errorf("EqualResourcePathsOfURLs(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.expected)
			}
		})
	}
}
