//go:build !unix

package cmd

import (
	"context"
	"errors"
	"os/exec"
)

func reissueSignals(ctx context.Context) <-chan struct{} {
	out := make(chan struct{})
	go func() { <-ctx.Done(); close(out) }()
	return out
}

func requestReissue(int) error {
	return errors.New("reissue by signal is not supported on this platform; restart the console process")
}

func openInBrowser(ctx context.Context, url string) error {
	return exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url).Start() //nolint:gosec // G204: fixed opener, loopback URL
}
