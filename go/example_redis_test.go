package assayverify_test

import (
	"context"
	"net/http"
	"time"

	assayverify "github.com/assay-ai/assay-provider-verify/go"
)

// redisClient is the part of go-redis (github.com/redis/go-redis/v9) this
// example needs: *redis.Client satisfies it through the small adapter below.
type redisClient interface {
	// SetNX stores key only when it does not exist and reports whether it did.
	SetNX(ctx context.Context, key string, value any, ttl time.Duration) (bool, error)
}

// redisReplayStore shares nonces between instances. Redis errors are returned,
// so verification fails closed.
type redisReplayStore struct {
	client redisClient
	prefix string
}

func (s redisReplayStore) CheckAndStore(ctx context.Context, nonce string, ttl time.Duration) (bool, error) {
	if ttl < time.Second {
		ttl = time.Second
	}
	return s.client.SetNX(ctx, s.prefix+nonce, "1", ttl)
}

// With go-redis v9, wrap the client so its *BoolCmd becomes (bool, error):
//
//	type goRedis struct{ *redis.Client }
//
//	func (g goRedis) SetNX(ctx context.Context, k string, v any, ttl time.Duration) (bool, error) {
//		return g.Client.SetNX(ctx, k, v, ttl).Result()
//	}
//
//	store := redisReplayStore{client: goRedis{redis.NewClient(&redis.Options{Addr: "localhost:6379"})}, prefix: "assay:nonce:"}
func Example_redisReplayStore() {
	var client redisClient // your adapter, see above
	mw, err := assayverify.Middleware(assayverify.Options{
		ReplayStore: redisReplayStore{client: client, prefix: "assay:nonce:"},
	})
	if err != nil {
		panic(err)
	}
	_ = http.ListenAndServe(":8080", mw(http.DefaultServeMux))
}
