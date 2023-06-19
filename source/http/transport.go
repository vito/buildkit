package http

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/go-multierror"
	"github.com/moby/buildkit/executor/oci"
	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/upload"
	"github.com/pkg/errors"
)

func newTransport(rt http.RoundTripper, sm *session.Manager, dns *oci.DNSConfig, g session.Group, hosts string, searchDomains string) http.RoundTripper {
	hostsMap := map[string]string{}
	for _, pair := range strings.Split(hosts, "\n") {
		fields := strings.Fields(pair)
		if len(fields) < 2 {
			continue
		}
		ip, hosts := fields[0], fields[1:]
		for _, host := range hosts {
			hostsMap[host] = ip
		}
	}

	domains := strings.Fields(searchDomains)

	var resolver *net.Resolver
	if dns == nil {
		resolver = net.DefaultResolver
	} else {
		dialer := net.Dialer{}
		resolver = &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				var errs error
				for _, ns := range dns.Nameservers {
					log.Println("!!! TRYING NS", ns)
					conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ns, "53"))
					if err != nil {
						errs = multierror.Append(errs, err)
						continue
					}

					return conn, nil
				}

				return nil, errs
			},
		}
	}

	return &sessionHandler{rt: rt, sm: sm, resolver: resolver, g: g, hosts: hostsMap, searchDomains: domains}
}

type sessionHandler struct {
	sm *session.Manager
	rt http.RoundTripper

	resolver *net.Resolver

	g             session.Group
	hosts         map[string]string
	searchDomains []string
}

func (h *sessionHandler) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "buildkit-session" {
		return h.handleSession(req)
	}

	id := identity.NewID()

	var remapped bool
	if len(h.hosts) > 0 {
		log.Println("!!! RT EXTRA HOSTS", id, req.URL.Host, h.hosts)

		if host, port, err := net.SplitHostPort(req.URL.Host); err == nil {
			remap, found := h.hosts[host]
			if found {
				req.URL.Host = net.JoinHostPort(remap, port)
				remapped = true
			}
		} else {
			remap, found := h.hosts[req.URL.Host]
			if found {
				req.URL.Host = remap
				remapped = true
			}
		}
		log.Println("!!! RT REMAPPED HOSTS", id, req.URL.Host, h.hosts)
	}

	if !remapped && strings.Count(req.URL.Host, ".") == 0 && len(h.searchDomains) > 0 {
		log.Println("!!! RT SEARCH DOMAINS", id, req.URL.Host, h.searchDomains)

		if host, port, err := net.SplitHostPort(req.URL.Host); err == nil {
			ip, err := h.lookup(req.Context(), host)
			if err != nil {
				return nil, err
			}

			req.URL.Host = net.JoinHostPort(ip.String(), port)
			remapped = true
		} else {
			ip, err := h.lookup(req.Context(), req.URL.Host)
			if err != nil {
				return nil, err
			}

			req.URL.Host = ip.String()
			remapped = true
		}
		log.Println("!!! RT REMAPPED DOMAINS", id, req.URL.Host, h.searchDomains)
	} else {
		log.Println("!!! RT NO SEARCH DOMAINS", id, req.URL.Host, h.searchDomains)
	}

	return h.rt.RoundTrip(req)
}

func (h *sessionHandler) lookup(ctx context.Context, target string) (net.IP, error) {
	log.Println("!!! RT LOOKUP", target)

	cat := exec.Command("cat", "/etc/resolv.conf")
	cat.Stdout = os.Stderr
	cat.Stderr = os.Stderr
	cat.Run()

	var errs error
	for _, domain := range append([]string{""}, h.searchDomains...) {
		qualified := target

		if domain != "" {
			qualified += "." + domain
		}

		ips, err := h.resolver.LookupIPAddr(ctx, qualified)
		log.Println("!!! LOOKUP", qualified, ips)
		if err != nil {
			errs = multierror.Append(errs, err)
			continue
		}

		if len(ips) > 0 {
			return ips[0].IP, nil
		}
	}
	if errs != nil {
		return nil, errs
	}

	return nil, errors.Errorf("no IPs found for %s", target)
}

func (h *sessionHandler) handleSession(req *http.Request) (*http.Response, error) {
	if req.Method != "GET" {
		return nil, errors.Errorf("invalid request")
	}

	var resp *http.Response
	err := h.sm.Any(context.TODO(), h.g, func(ctx context.Context, _ string, caller session.Caller) error {
		up, err := upload.New(context.TODO(), caller, req.URL)
		if err != nil {
			return err
		}

		pr, pw := io.Pipe()
		go func() {
			_, err := up.WriteTo(pw)
			pw.CloseWithError(err)
		}()

		resp = &http.Response{
			Status:        "200 OK",
			StatusCode:    200,
			Body:          pr,
			ContentLength: -1,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}
