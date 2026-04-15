package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	cacheRedis "idp-server/internal/infrastructure/cache/redis"
	"idp-server/internal/infrastructure/storage"

	goredis "github.com/redis/go-redis/v9"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	redisAddr := readEnv("REDIS_ADDR", "")
	if redisAddr == "" {
		redisAddr = buildRedisAddrFromEnv()
	}
	if redisAddr == "" {
		log.Fatal("missing redis configuration: set REDIS_ADDR or REDIS_HOST")
	}

	rdb, err := storage.NewRedis(ctx, redisAddr, strings.TrimSpace(os.Getenv("REDIS_PASSWORD")), readEnvInt("REDIS_DB", 0))
	if err != nil {
		log.Fatalf("connect redis: %v", err)
	}
	defer rdb.Close()

	keyBuilder := cacheRedis.NewKeyBuilder(readEnv("REDIS_KEY_PREFIX", "idp"), readEnv("APP_ENV", "dev"))
	dlqStream := readEnv("AUDIT_DLQ_STREAM", keyBuilder.AuditDLQStream())
	mainStream := readEnv("AUDIT_STREAM", keyBuilder.AuditStream())
	start := readEnv("AUDIT_DLQ_REPLAY_START", "-")
	end := readEnv("AUDIT_DLQ_REPLAY_END", "+")
	count := int64(readEnvInt("AUDIT_DLQ_REPLAY_COUNT", 100))

	messages, err := rdb.XRangeN(ctx, dlqStream, start, end, count).Result()
	if err != nil {
		log.Fatalf("read dlq: %v", err)
	}

	replayed := 0
	for _, message := range messages {
		values := map[string]any{
			"event_id":      stringify(message.Values["event_id"]),
			"event_type":    stringify(message.Values["event_type"]),
			"client_id":     stringify(message.Values["client_id"]),
			"user_id":       stringify(message.Values["user_id"]),
			"subject":       stringify(message.Values["subject"]),
			"session_id":    stringify(message.Values["session_id"]),
			"ip_address":    stringify(message.Values["ip_address"]),
			"user_agent":    stringify(message.Values["user_agent"]),
			"metadata_json": stringify(message.Values["metadata_json"]),
			"created_at":    stringify(message.Values["created_at"]),
		}
		if strings.TrimSpace(values["event_id"].(string)) == "" || strings.TrimSpace(values["event_type"].(string)) == "" {
			log.Printf("skip malformed dlq event dlq_id=%s", message.ID)
			continue
		}
		if _, err := rdb.XAdd(ctx, &goredis.XAddArgs{
			Stream: mainStream,
			Values: values,
		}).Result(); err != nil {
			log.Printf("replay audit dlq failed dlq_id=%s err=%v", message.ID, err)
			continue
		}
		replayed++
	}

	log.Printf("replayed %d audit event(s) from %s to %s", replayed, dlqStream, mainStream)
}

func readEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func readEnvInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return value
}

func buildRedisAddrFromEnv() string {
	host := strings.TrimSpace(os.Getenv("REDIS_HOST"))
	port := readEnv("REDIS_PORT", "6379")
	if host == "" {
		return ""
	}
	return host + ":" + port
}

func stringify(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return fmt.Sprintf("%v", typed)
	}
}
