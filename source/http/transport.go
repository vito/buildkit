package http

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/moby/buildkit/identity"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/upload"
	"github.com/pkg/errors"
)

func newTransport(rt http.RoundTripper, sm *session.Manager, g session.Group, hosts string) http.RoundTripper {
	hostsMap := map[string]string{}
	for _, pair := range strings.Split(hosts, "\n") {
		fields := strings.Fields(pair)
		if len(fields) < 2 {
			continue
		}
		hostsMap[fields[0]] = fields[1]
	}
	return &sessionHandler{rt: rt, sm: sm, g: g, hosts: hostsMap}
}

type sessionHandler struct {
	sm *session.Manager
	rt http.RoundTripper
	g  session.Group

	hosts map[string]string
}

func (h *sessionHandler) RoundTrip(req *http.Request) (*http.Response, error) {
	id := identity.NewID()

	log.Println("!!!!!!!! RT EXTRA HOSTS", id, req.URL.Host, h.hosts)

	if host, port, err := net.SplitHostPort(req.URL.Host); err == nil {
		remap, found := h.hosts[host]
		if found {
			req.URL.Host = net.JoinHostPort(remap, port)
		}
	} else {
		remap, found := h.hosts[req.URL.Host]
		if found {
			req.URL.Host = remap
		}
	}

	log.Println("!!!!!!!! RT REMAPPED", id, req.URL.Host, h.hosts)

	if req.URL.Host != "buildkit-session" {
		return h.rt.RoundTrip(req)
	}

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
