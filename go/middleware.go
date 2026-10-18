package assayverify

import (
	"bytes"
	"io"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// Middleware returns net/http middleware that verifies every request. Rejected
// requests get 401 with {"error":"invalid_assay_signature","reason":"<CODE>"};
// bodies over MaxBodyBytes get 413 before verification. Accepted requests reach
// the handler with r.Body restored.
func Middleware(opts Options) (func(http.Handler) http.Handler, error) {
	v, err := New(opts)
	if err != nil {
		return nil, err
	}
	max := opts.MaxBodyBytes
	if max <= 0 {
		max = DefaultMaxBodyBytes
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body []byte
			// A body is present when one was declared (even length 0), the
			// transfer is chunked, or bytes arrive (Go sets -1 for unknown).
			if r.Body != nil && (r.ContentLength != 0 || len(r.TransferEncoding) > 0) {
				if r.ContentLength > max {
					writeJSON(w, http.StatusRequestEntityTooLarge, `{"error":"payload_too_large"}`)
					return
				}
				b, err := io.ReadAll(io.LimitReader(r.Body, max+1))
				_ = r.Body.Close()
				if err != nil {
					writeJSON(w, http.StatusBadRequest, `{"error":"bad_request"}`)
					return
				}
				if int64(len(b)) > max {
					writeJSON(w, http.StatusRequestEntityTooLarge, `{"error":"payload_too_large"}`)
					return
				}
				body = b
			}
			_, _, reason, err := v.Verify(r, body)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, `{"error":"assay_verify_failed"}`)
				return
			}
			if reason != "" {
				writeJSON(w, http.StatusUnauthorized, `{"error":"invalid_assay_signature","reason":"`+string(reason)+`"}`)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			next.ServeHTTP(w, r)
		})
	}, nil
}
