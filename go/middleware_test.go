package assayverify

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func middlewareFor(t *testing.T, mutate func(*Options)) (http.Handler, *int, *string) {
	jwk, _, _, created := firstVector(t)
	o := Options{
		Providers: []string{testProvider},
		JWKS:      staticJWKS(t, jwk), ReplayStore: NewMemoryReplayStore(10),
		Now: func() time.Time { return time.Unix(created, 0) },
	}
	if mutate != nil {
		mutate(&o)
	}
	mw, err := Middleware(o)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	seen := ""
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		seen = string(b)
		w.WriteHeader(204)
	}))
	return h, &calls, &seen
}

func serve(h http.Handler, r *http.Request, body []byte) *httptest.ResponseRecorder {
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	r.ContentLength = int64(len(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestMiddlewareAccepts(t *testing.T) {
	h, calls, seen := middlewareFor(t, nil)
	_, r, body, _ := firstVector(t)
	rec := serve(h, r, body)
	if rec.Code != 204 || *calls != 1 || *seen != string(body) {
		t.Fatalf("code=%d calls=%d body=%q", rec.Code, *calls, *seen)
	}
}

func TestMiddlewareRejectsTampered(t *testing.T) {
	h, calls, _ := middlewareFor(t, nil)
	_, r, _, _ := firstVector(t)
	rec := serve(h, r, []byte(`{"q":"evil"}`))
	if rec.Code != 401 || *calls != 0 {
		t.Fatalf("code=%d calls=%d", rec.Code, *calls)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatal(ct)
	}
	if got := rec.Body.String(); got != `{"error":"invalid_assay_signature","reason":"DIGEST_MISMATCH"}` {
		t.Fatal(got)
	}
}

func TestMiddlewarePayloadTooLarge(t *testing.T) {
	h, calls, _ := middlewareFor(t, func(o *Options) { o.MaxBodyBytes = 4 })
	_, r, body, _ := firstVector(t)
	rec := serve(h, r, body)
	if rec.Code != 413 || rec.Body.String() != `{"error":"payload_too_large"}` || *calls != 0 {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body.String())
	}
	// Unknown length (chunked) is capped too.
	_, r2, body2, _ := firstVector(t)
	r2.Body = io.NopCloser(strings.NewReader(string(body2)))
	r2.ContentLength = -1
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, r2)
	if rec.Code != 413 {
		t.Fatalf("chunked code=%d", rec.Code)
	}
}

func TestMiddlewareReplay(t *testing.T) {
	h, _, _ := middlewareFor(t, nil)
	_, r, body, _ := firstVector(t)
	if rec := serve(h, r, body); rec.Code != 204 {
		t.Fatal(rec.Code)
	}
	if rec := serve(h, r, body); rec.Code != 401 || !strings.Contains(rec.Body.String(), "REPLAYED") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestMiddlewareStoreErrorFailsClosed(t *testing.T) {
	h, calls, _ := middlewareFor(t, func(o *Options) { o.ReplayStore = errStore{} })
	_, r, body, _ := firstVector(t)
	if rec := serve(h, r, body); rec.Code != 500 || *calls != 0 {
		t.Fatalf("code=%d", rec.Code)
	}
}

func TestMiddlewareWrongProvider(t *testing.T) {
	h, calls, _ := middlewareFor(t, func(o *Options) { o.Providers = []string{"prov-other"} })
	_, r, body, _ := firstVector(t)
	rec := serve(h, r, body)
	if rec.Code != 401 || *calls != 0 {
		t.Fatalf("code=%d calls=%d", rec.Code, *calls)
	}
	if got := rec.Body.String(); got != `{"error":"invalid_assay_signature","reason":"WRONG_PROVIDER"}` {
		t.Fatal(got)
	}
}
