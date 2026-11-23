//go:build !unix

package doctor

import "errors"

var errNoProbe = errors.New("not checked on this platform")

func mayWrite(string) error { return errNoProbe }

func freeBytes(string) (uint64, error) { return 0, errNoProbe }
