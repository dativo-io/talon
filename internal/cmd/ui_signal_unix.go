//go:build unix

package cmd

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
)

// reissueSignals delivers one value per SIGUSR1 until ctx ends.
func reissueSignals(ctx context.Context) <-chan struct{} {
	out := make(chan struct{}, 1)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(sig)
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-sig:
				select {
				case out <- struct{}{}:
				default:
				}
			}
		}
	}()
	return out
}

// requestReissue sends SIGUSR1 to the console process.
func requestReissue(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(syscall.SIGUSR1)
}

func openInBrowser(ctx context.Context, url string) error {
	name, args := "xdg-open", []string{url}
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	return exec.CommandContext(ctx, name, args...).Start() //nolint:gosec // G204: fixed opener binary, the URL is the console's own loopback address
}
