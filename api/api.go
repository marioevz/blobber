package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
)

type BlobberApi struct {
	host string
	port int

	srv    *http.Server
	cancel context.CancelFunc
}

type ApiHandlerCallback func(request *http.Request, body []byte) (interface{}, error)

func NewBlobberApi(
	ctx context.Context,
	host string,
	port int,
	apiHandlerCallbacks map[string]ApiHandlerCallback,
) (*BlobberApi, error) {
	api := &BlobberApi{
		host: host,
		port: port,
	}

	router := mux.NewRouter()

	for method, callback := range apiHandlerCallbacks {
		router.HandleFunc(method, api.proxyHandler(callback))
	}

	api.srv = &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%d", host, port),
	}

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		if err := api.Start(ctx); err != nil && err != context.Canceled {
			panic(err)
		}
	}()
	api.cancel = cancel

	return api, nil
}

func (p *BlobberApi) Port() int {
	return p.port
}

func (p *BlobberApi) Address() string {
	return fmt.Sprintf("http://%s:%d", p.host, p.port)
}

func (v *BlobberApi) proxyHandler(callback ApiHandlerCallback) func(http.ResponseWriter, *http.Request) {
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

		rspData, err := callback(r, body)
		if err != nil {
			logrus.WithError(err).Error("Could not execute api callback")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if rspData != nil {
			w.Header().Set("Content-Type", "application/json")

			err := json.NewEncoder(w).Encode(rspData)
			if err != nil {
				logrus.WithError(err).Error("error encoding api response")
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
			}
		}
	}
}

func (p *BlobberApi) Cancel() error {
	if p.cancel != nil {
		p.cancel()
	}
	return nil
}

// Start a proxy server.
func (p *BlobberApi) Start(ctx context.Context) error {
	p.srv.BaseContext = func(listener net.Listener) context.Context {
		return ctx
	}

	fields := logrus.Fields{
		"package":            "api",
		"port":               p.port,
		"listening_endpoint": p.Address(),
	}
	logrus.WithFields(fields).Info("API now listening")
	go func() {
		if err := p.srv.ListenAndServe(); err != nil {
			logrus.WithFields(logrus.Fields{
				"package": "api",
			}).Error(err)
		}
	}()
	for {
		<-ctx.Done()
		return p.srv.Shutdown(ctx)
	}
}
