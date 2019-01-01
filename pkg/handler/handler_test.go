package handler

import (
	"testing"
)

func TestPathCheckerRegex(t *testing.T) {
	tests := []struct {
		path    string
		allowed bool
	}{
		{
			path:    "build/my_repo/2548/pull-with_underscore_and./1079687257834655744",
			allowed: true,
		},
		{
			path:    "wrong-prefix/my_repo/2548/pull-with_underscore_and./1079687257834655744",
			allowed: false,
		},
		{
			path:    "build/my_repo/2548/pull-without-id",
			allowed: false,
		},
		{
			path:    "build/my_repo/no-pr-number/pull-with_underscore_and./1079687257834655744",
			allowed: false,
		},
	}

	for _, test := range tests {
		matches := pathChecker.MatchString(test.path)
		if matches != test.allowed {
			t.Errorf("expected pathChecker regex to match string '%s': %t but was %t", test.path, test.allowed, matches)
		}
	}

}
