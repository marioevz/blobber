package validator_proxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

type ValidatorProxy struct {
	host string
	port int

	id     int
	target *url.URL

	srv    *http.Server
	cancel context.CancelFunc
}

type ResponseCallback func(request *http.Request, response []byte) (bool, error)

func NewProxy(
	ctx context.Context,
	id int,
	host string,
	port int,
	destination string,
	responseCallbacks map[string]ResponseCallback,
) (*ValidatorProxy, error) {
	proxy := &ValidatorProxy{
		host: host,
		port: port,
	}

	router := mux.NewRouter()

	var err error
	proxy.target, err = url.Parse(destination)
	if err != nil {
		return nil, err
	}

	reverseProxy := httputil.NewSingleHostReverseProxy(proxy.target)
	for method, callback := range responseCallbacks {
		router.HandleFunc(method, proxyHandler(proxy.target, reverseProxy, callback))
	}
	router.PathPrefix("/").Handler(reverseProxy)

	proxy.srv = &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%d", host, port),
	}

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		if err := proxy.Start(ctx); err != nil && err != context.Canceled {
			panic(err)
		}
	}()
	proxy.cancel = cancel

	return proxy, nil
}

func (p *ValidatorProxy) ID() int {
	return p.id
}

func (p *ValidatorProxy) Port() int {
	return p.port
}

func (p *ValidatorProxy) Address() string {
	return fmt.Sprintf("http://%s:%d", p.host, p.port)
}

func proxyHandler(url *url.URL, p *httputil.ReverseProxy, callback ResponseCallback) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// we need to buffer the body if we want to read it here and send it
		// in the request.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// you can reassign the body if you need to parse it as multipart
		r.Body = io.NopCloser(bytes.NewReader(body))

		fullUrl := url.JoinPath(r.URL.Path)
		proxyReq, err := http.NewRequest(r.Method, fullUrl.String(), bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		q := proxyReq.URL.Query()

		// Copy the query parameters from the original request to the proxy request.
		for k, v := range r.URL.Query() {
			q.Add(k, v[0])
		}
		proxyReq.URL.RawQuery = q.Encode()

		// We may want to filter some headers, otherwise we could just use a shallow copy
		// proxyReq.Header = req.Header
		proxyReq.Header = make(http.Header)
		fields := make(logrus.Fields)
		fields["fullUrl"] = fullUrl.String()
		for h, val := range r.Header {
			if h == "Accept-Encoding" {
				// Remove encoding from the request so we are able to decode it
				continue
			}
			if h == "Accept" {
				// Modify the accept header to only accept json
				val = []string{"application/json"}
			}
			fields[h] = val
			proxyReq.Header[h] = val
		}
		logrus.WithFields(fields).Debug("Proxying request")

		client := &http.Client{}
		proxyRes, err := client.Do(proxyReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		// Forward the headers from the destination response to our proxy response.
		for k, vv := range proxyRes.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		// We optionally Spoof the response as desired.
		modifiedResp, err := io.ReadAll(proxyRes.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if override, err := callback(r, modifiedResp); err != nil {
			logrus.WithError(err).Error("Could not execute callback, returning response to validator client")
		} else if override {
			logrus.WithFields(logrus.Fields{
				"method": r.Method,
				"url":    r.URL.String(),
			}).Debug("Overriding response")
			http.Error(w, "overriding response", http.StatusInternalServerError)
			return
		}

		if err = proxyRes.Body.Close(); err != nil {
			logrus.WithError(err).Error("Could not do client proxy")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Set the modified response as the proxy response body.
		proxyRes.Body = io.NopCloser(bytes.NewBuffer(modifiedResp))

		// Pipe the proxy response to the original caller.
		if _, err = io.Copy(w, proxyRes.Body); err != nil {
			logrus.WithError(err).Error("Could not copy proxy request body")
			return
		}
	}
}

func (p *ValidatorProxy) Cancel() error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

// Start a proxy server.
func (p *ValidatorProxy) Start(ctx context.Context) error {
	p.srv.BaseContext = func(listener net.Listener) context.Context {
		return ctx
	}

	fields := logrus.Fields{
		"validator_proxy_id": p.id,
		"port":               p.port,
		// "pubkey":             p.pkBeacon.String(),
		"listening_endpoint": p.Address(),
	}
	logrus.WithFields(fields).Info("Proxy now listening")
	go func() {
		if err := p.srv.ListenAndServe(); err != nil {
			logrus.WithFields(logrus.Fields{
				"validator_proxy_id": p.id,
			}).Error(err)
		}
	}()
	for {
		<-ctx.Done()
		return p.srv.Shutdown(ctx)
	}
}
