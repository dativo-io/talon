package otel

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestMiddlewareWithStatus(t *testing.T) {
	mw := MiddlewareWithStatus()
	// 200 response
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// 500 response (exercises span.SetStatus error path)
	h500 := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	req = httptest.NewRequest(http.MethodGet, "/err", nil)
	rec = httptest.NewRecorder()
	h500.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestMiddlewareWithStatus_ChiRouteContext(t *testing.T) {
	r := chi.NewRouter()
	mw := MiddlewareWithStatus()
	r.Use(mw)
	r.Get("/v1/triggers/{name}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/triggers/foo", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
