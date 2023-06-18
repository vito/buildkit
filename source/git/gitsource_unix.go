//go:build !windows
// +build !windows

package git

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/docker/docker/pkg/reexec"
	"github.com/moby/sys/mount"
	"golang.org/x/sys/unix"
)

const (
	gitCmd = "umask-git"
)

func init() {
	reexec.Register(gitCmd, gitMain)
}

func gitMain() {
	// Need standard user umask for git process.
	unix.Umask(0022)

	if extraHosts, found := os.LookupEnv("EXTRA_HOSTS"); found {
		// Override /etc/hosts by bind-mounting over it in a separate mount
		// namespace.

		// Unsharing is per-thread, so we have to pin this goroutine to the
		// current thread for any of this to behave predictably.
		runtime.LockOSThread()

		// Create a mount namespace, which the sub-process will inherit.
		syscall.Unshare(syscall.CLONE_NEWNS)

		// Bind-mount over /etc/hosts.
		if err := overrideHosts(extraHosts); err != nil {
			panic(err)
		}
	}

	// Reexec git command
	cmd := exec.Command(os.Args[1], os.Args[2:]...) //nolint:gosec // reexec
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: unix.SIGTERM,
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	// Forward all signals
	sigc := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigc)
	go func() {
		for {
			select {
			case sig := <-sigc:
				if cmd.Process == nil {
					continue
				}
				switch sig {
				case unix.SIGINT, unix.SIGTERM, unix.SIGKILL:
					_ = unix.Kill(-cmd.Process.Pid, sig.(unix.Signal))
				default:
					_ = cmd.Process.Signal(sig)
				}
			case <-done:
				return
			}
		}
	}()

	err := cmd.Run()
	close(done)
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			switch status := exiterr.Sys().(type) {
			case unix.WaitStatus:
				os.Exit(status.ExitStatus())
			case syscall.WaitStatus:
				os.Exit(status.ExitStatus())
			}
		}
		os.Exit(1)
	}
	os.Exit(0)
}

func overrideHosts(extraHosts string) error {
	currentHosts, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return fmt.Errorf("read current hosts: %w", err)
	}

	hostsOverride, err := os.CreateTemp("", "buildkit-git-extra-hosts")
	if err != nil {
		return fmt.Errorf("create hosts override: %w", err)
	}

	_, err = hostsOverride.Write(currentHosts)
	if err != nil {
		return fmt.Errorf("write current hosts: %w", err)
	}

	_, err = fmt.Fprintln(hostsOverride)
	if err != nil {
		return fmt.Errorf("write newline: %w", err)
	}

	_, err = fmt.Fprintln(hostsOverride, extraHosts)
	if err != nil {
		return fmt.Errorf("write extra hosts: %w", err)
	}

	err = mount.Mount(hostsOverride.Name(), "/etc/hosts", "none", "bind,ro")
	if err != nil {
		return fmt.Errorf("mount hosts override: %w", err)
	}

	return nil
}

func runProcessGroup(ctx context.Context, cmd *exec.Cmd) error {
	cmd.Path = reexec.Self()
	cmd.Args = append([]string{gitCmd}, cmd.Args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	waitDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = unix.Kill(-cmd.Process.Pid, unix.SIGTERM)
			go func() {
				select {
				case <-waitDone:
				case <-time.After(10 * time.Second):
					_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
				}
			}()
		case <-waitDone:
		}
	}()
	err := cmd.Wait()
	close(waitDone)
	return err
}
