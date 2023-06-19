//go:build !windows
// +build !windows

package git

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
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

	extraHosts := os.Getenv("EXTRA_HOSTS")
	searchDomains := os.Getenv("SEARCH_DOMAINS")

	if extraHosts != "" || searchDomains != "" {
		// Unshare the mount namespace so we can override /etc/hosts and/or
		// /etc/resolv.conf.

		// Unsharing is per-thread, so we have to pin this goroutine to the
		// current thread for any of this to behave predictably.
		runtime.LockOSThread()

		// Create a mount namespace, which the sub-process will inherit.
		syscall.Unshare(syscall.CLONE_NEWNS)
	}

	if extraHosts != "" {
		cleanup, err := overrideHosts(extraHosts)
		if err != nil {
			panic(err)
		}
		defer cleanup()
	}

	if searchDomains != "" {
		cleanup, err := overrideSearch(strings.Fields(searchDomains))
		if err != nil {
			panic(err)
		}
		defer cleanup()
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

func overrideHosts(extraHosts string) (func(), error) {
	currentHosts, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return nil, fmt.Errorf("read current hosts: %w", err)
	}

	override, err := os.CreateTemp("", "buildkit-git-extra-hosts")
	if err != nil {
		return nil, fmt.Errorf("create hosts override: %w", err)
	}

	cleanup := func() {
		_ = override.Close()
		_ = os.Remove(override.Name())
	}

	if err := replaceHosts(override, currentHosts, extraHosts); err != nil {
		cleanup()
		return nil, err
	}

	return cleanup, nil
}

func replaceHosts(override *os.File, currentHosts []byte, extraHosts string) error {
	if _, err := override.Write(currentHosts); err != nil {
		return fmt.Errorf("write current hosts: %w", err)
	}

	if _, err := fmt.Fprintln(override); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}

	if _, err := fmt.Fprintln(override, extraHosts); err != nil {
		return fmt.Errorf("write extra hosts: %w", err)
	}

	if err := override.Close(); err != nil {
		return fmt.Errorf("close hosts override: %w", err)
	}

	if err := mount.Mount(override.Name(), "/etc/hosts", "none", "bind,ro"); err != nil {
		return fmt.Errorf("mount hosts override: %w", err)
	}

	return nil
}

func overrideSearch(searchDomains []string) (func(), error) {
	src, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	defer src.Close()

	override, err := os.CreateTemp("", "buildkit-git-resolv")
	if err != nil {
		return nil, fmt.Errorf("create hosts override: %w", err)
	}

	cleanup := func() {
		_ = override.Close()
		_ = os.Remove(override.Name())
	}

	log.Println("!!! OVERRIDING SEARCH", searchDomains)

	if err := replaceSearch(override, src, searchDomains); err != nil {
		cleanup()
		return nil, err
	}

	return cleanup, nil
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

func replaceSearch(dst *os.File, src io.Reader, searchDomains []string) error {
	srcScan := bufio.NewScanner(src)

	var replaced bool
	for srcScan.Scan() {
		if !strings.HasPrefix(srcScan.Text(), "search") {
			fmt.Fprintln(dst, srcScan.Text())
			continue
		}

		oldDomains := strings.Fields(srcScan.Text())[1:]

		newDomains := append([]string{}, searchDomains...)
		newDomains = append(newDomains, oldDomains...)
		fmt.Fprintln(dst, "search", strings.Join(newDomains, " "))
		replaced = true
	}

	if !replaced {
		fmt.Fprintln(dst, "search", strings.Join(searchDomains, " "))
	}

	if err := mount.Mount(dst.Name(), "/etc/resolv.conf", "none", "bind,ro"); err != nil {
		return fmt.Errorf("mount resolv.conf override: %w", err)
	}

	return nil
}
