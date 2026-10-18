package assayverify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type vecRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    *string           `json:"body"`
}

func loadJSON(t *testing.T, name string, v any) {
	t.Helper()
	b, err := os.ReadFile("../test-vectors/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
}

// toRequest builds a server-side style request: RequestURI as sent, Host from the
// "host" header (empty when absent, so the URL host is used).
func (v vecRequest) toRequest(extra map[string]string) (*http.Request, []byte) {
	r := &http.Request{Method: v.Method, RequestURI: v.URL, Header: http.Header{}}
	for k, val := range v.Headers {
		if strings.EqualFold(k, "host") {
			r.Host = val
			continue
		}
		r.Header.Set(k, val)
	}
	for k, val := range extra {
		r.Header.Set(k, val)
	}
	var body []byte
	if v.Body != nil {
		body = []byte(*v.Body)
	}
	return r, body
}

func staticJWKS(t *testing.T, jwk any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": []any{jwk}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPositiveVectors(t *testing.T) {
	var f struct {
		PublicKeyJWK map[string]any `json:"publicKeyJwk"`
		KeyID        string         `json:"keyId"`
		Cases        []struct {
			Name    string     `json:"name"`
			Request vecRequest `json:"request"`
			Params  struct {
				Created int64 `json:"created"`
			} `json:"params"`
			Expected struct {
				Headers map[string]string `json:"headers"`
			} `json:"expected"`
		} `json:"cases"`
	}
	loadJSON(t, "v1.json", &f)
	if len(f.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			created := c.Params.Created
			v, err := New(Options{
				JWKS:        staticJWKS(t, f.PublicKeyJWK),
				ReplayStore: NewMemoryReplayStore(10),
				Now:         func() time.Time { return time.Unix(created, 0) },
			})
			if err != nil {
				t.Fatal(err)
			}
			r, body := c.Request.toRequest(c.Expected.Headers)
			kid, callID, reason, err := v.Verify(r, body)
			if err != nil || reason != "" {
				t.Fatalf("reason=%q err=%v", reason, err)
			}
			if kid != f.KeyID || callID != "c-1" {
				t.Fatalf("kid=%q call=%q", kid, callID)
			}
		})
	}
}

func TestNegativeVectors(t *testing.T) {
	type step struct {
		Request        vecRequest `json:"request"`
		Now            int64      `json:"now"`
		ExpectedReason string     `json:"expectedReason"`
	}
	var f struct {
		PublicKeyJWK map[string]any `json:"publicKeyJwk"`
		Cases        []struct {
			Name     string `json:"name"`
			Sequence []step `json:"sequence"`
			step
		} `json:"cases"`
	}
	loadJSON(t, "negative.json", &f)
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			steps := c.Sequence
			if len(steps) == 0 {
				steps = []step{c.step}
			}
			var now atomic.Int64
			v, err := New(Options{
				JWKS:        staticJWKS(t, f.PublicKeyJWK),
				ReplayStore: NewMemoryReplayStore(10),
				Now:         func() time.Time { return time.Unix(now.Load(), 0) },
			})
			if err != nil {
				t.Fatal(err)
			}
			for i, s := range steps {
				now.Store(s.Now)
				r, body := s.Request.toRequest(nil)
				_, _, reason, err := v.Verify(r, body)
				if err != nil {
					t.Fatal(err)
				}
				got := string(reason)
				if got == "" {
					got = "OK"
				}
				if got != s.ExpectedReason {
					t.Fatalf("step %d: got %s want %s", i, got, s.ExpectedReason)
				}
			}
		})
	}
}

// signedCase returns the first positive vector with its signature headers applied.
func firstVector(t *testing.T) (map[string]any, *http.Request, []byte, int64) {
	t.Helper()
	var f struct {
		PublicKeyJWK map[string]any `json:"publicKeyJwk"`
		Cases        []struct {
			Request  vecRequest `json:"request"`
			Params   struct{ Created int64 }
			Expected struct{ Headers map[string]string }
		} `json:"cases"`
	}
	loadJSON(t, "v1.json", &f)
	c := f.Cases[0]
	r, body := c.Request.toRequest(c.Expected.Headers)
	return f.PublicKeyJWK, r, body, c.Params.Created
}

func newFirst(t *testing.T, mutate func(*Options)) (*Verifier, *http.Request, []byte) {
	jwk, r, body, created := firstVector(t)
	o := Options{JWKS: staticJWKS(t, jwk), ReplayStore: NewMemoryReplayStore(10), Now: func() time.Time { return time.Unix(created, 0) }}
	if mutate != nil {
		mutate(&o)
	}
	v, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return v, r, body
}

func TestRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *http.Request)
		want   RejectReason
	}{
		{"double-slash target", func(r *http.Request) { r.RequestURI = "//evil.test/v1/search?q=a%20b" }, ReasonMalformed},
		{"relative target", func(r *http.Request) { r.RequestURI = "v1/search" }, ReasonMalformed},
		{"expires before created", func(r *http.Request) {
			r.Header.Set("Signature-Input", strings.Replace(r.Header.Get("Signature-Input"), "expires=1760700300", "expires=1760699000", 1))
		}, ReasonExpired},
		{"garbage signature", func(r *http.Request) { r.Header.Set("Signature", "assay=nonsense") }, ReasonMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, r, body := newFirst(t, nil)
			c.mutate(r)
			_, _, reason, err := v.Verify(r, body)
			if err != nil || reason != c.want {
				t.Fatalf("got %q err=%v want %q", reason, err, c.want)
			}
		})
	}
}

func TestAuthorityOption(t *testing.T) {
	v, r, body := newFirst(t, func(o *Options) { o.Authority = "API.Example.test" })
	r.Host = "internal:8080"
	if _, _, reason, err := v.Verify(r, body); err != nil || reason != "" {
		t.Fatalf("reason=%q err=%v", reason, err)
	}
}

func TestBadKeyLengthIsSkipped(t *testing.T) {
	jwk, r, body, created := firstVector(t)
	bad, _ := json.Marshal(map[string]any{"keys": []any{
		map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": jwk["kid"], "x": "AAAA"},
	}})
	v, err := New(Options{JWKS: bad, ReplayStore: NewMemoryReplayStore(10), Now: func() time.Time { return time.Unix(created, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	_, _, reason, err := v.Verify(r, body)
	if err != nil || reason != ReasonUnknownKey {
		t.Fatalf("got %q err=%v", reason, err)
	}
}

func TestDefaultReplayStoreIsShared(t *testing.T) {
	jwk, r, body, created := firstVector(t)
	mk := func() *Verifier {
		v, err := New(Options{JWKS: staticJWKS(t, jwk), Now: func() time.Time { return time.Unix(created, 0) }})
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if _, _, reason, _ := mk().Verify(r, body); reason != "" {
		t.Fatal(reason)
	}
	if _, _, reason, _ := mk().Verify(r, body); reason != ReasonReplayed {
		t.Fatalf("second verifier: %q", reason)
	}
}

type errStore struct{}

func (errStore) CheckAndStore(context.Context, string, time.Duration) (bool, error) {
	return false, context.DeadlineExceeded
}

func TestReplayStoreErrorFailsClosed(t *testing.T) {
	v, r, body := newFirst(t, func(o *Options) { o.ReplayStore = errStore{} })
	if _, _, _, err := v.Verify(r, body); err == nil {
		t.Fatal("expected error")
	}
}

func TestMemoryReplayStoreLRU(t *testing.T) {
	s := NewMemoryReplayStore(2)
	ctx := context.Background()
	for _, n := range []string{"a", "b", "c"} {
		if ok, _ := s.CheckAndStore(ctx, n, time.Minute); !ok {
			t.Fatal(n)
		}
	}
	if ok, _ := s.CheckAndStore(ctx, "c", time.Minute); ok {
		t.Fatal("c should be seen")
	}
	if ok, _ := s.CheckAndStore(ctx, "a", time.Minute); !ok {
		t.Fatal("a should have been evicted")
	}
}

func TestJWKSFetchBackoffAndRecovery(t *testing.T) {
	jwk, r, body, created := firstVector(t)
	var hits atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		if fail.Load() {
			http.Error(w, "nope", 500)
			return
		}
		w.Write(staticJWKS(t, jwk))
	}))
	defer srv.Close()
	var now atomic.Int64
	now.Store(created)
	v, err := New(Options{JWKSURL: srv.URL + "/k.json", ReplayStore: NewMemoryReplayStore(10), Now: func() time.Time { return time.Unix(now.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, reason, _ := v.Verify(r, body); reason != ReasonUnknownKey {
		t.Fatal(reason)
	}
	if _, _, reason, _ := v.Verify(r, body); reason != ReasonUnknownKey || hits.Load() != 1 {
		t.Fatalf("backoff: %q hits=%d", reason, hits.Load())
	}
	fail.Store(false)
	now.Store(created + 6)
	if _, _, reason, _ := v.Verify(r, body); reason != "" || hits.Load() != 2 {
		t.Fatalf("recovery: %q hits=%d", reason, hits.Load())
	}
}

func TestParseDictionaryRejectsJunk(t *testing.T) {
	for _, s := range []string{"assay=(\"a\"", "assay=(\"a\"), ", "=x", "assay=:!!:"} {
		if _, err := parseDictionary(s); err == nil {
			t.Errorf("%q should fail", s)
		}
	}
}
