package auditstream

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditdomain "idp-server/internal/domain/audit"
	"idp-server/internal/ports/repository"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
)

var enqueueAuditEventScript = goredis.NewScript(`
local inserted = redis.call("SET", KEYS[1], ARGV[1], "NX", "EX", ARGV[2])
if not inserted then
	return ""
end

return redis.call(
	"XADD",
	KEYS[2],
	"*",
	"event_id", ARGV[1],
	"event_type", ARGV[3],
	"client_id", ARGV[4],
	"user_id", ARGV[5],
	"subject", ARGV[6],
	"session_id", ARGV[7],
	"ip_address", ARGV[8],
	"user_agent", ARGV[9],
	"metadata_json", ARGV[10],
	"created_at", ARGV[11]
)
`)

type AsyncRepository struct {
	reader    repository.AuditEventRepository
	producer  *Producer
	syncWrite bool
}

func NewAsyncRepository(reader repository.AuditEventRepository, producer *Producer, syncWrite bool) *AsyncRepository {
	return &AsyncRepository{
		reader:    reader,
		producer:  producer,
		syncWrite: syncWrite,
	}
}

func (r *AsyncRepository) Create(ctx context.Context, model *auditdomain.Model) error {
	if model == nil {
		return fmt.Errorf("missing audit event")
	}
	ensureEventID(model)
	if r.syncWrite || r.producer == nil {
		if r.reader == nil {
			return fmt.Errorf("missing audit repository")
		}
		return r.reader.Create(ctx, model)
	}
	return r.producer.Publish(ctx, model)
}

func (r *AsyncRepository) List(ctx context.Context, input repository.ListAuditEventsInput) ([]*auditdomain.Model, error) {
	if r.reader == nil {
		return nil, fmt.Errorf("missing audit repository")
	}
	return r.reader.List(ctx, input)
}

type Producer struct {
	rdb        *goredis.Client
	stream     string
	dedupTTL   time.Duration
	dedupKeyFn func(string) string
}

func NewProducer(rdb *goredis.Client, stream string, dedupTTL time.Duration, dedupKeyFn func(string) string) *Producer {
	return &Producer{
		rdb:        rdb,
		stream:     strings.TrimSpace(stream),
		dedupTTL:   dedupTTL,
		dedupKeyFn: dedupKeyFn,
	}
}

func (p *Producer) Publish(ctx context.Context, model *auditdomain.Model) error {
	if p == nil || p.rdb == nil {
		return fmt.Errorf("missing redis producer")
	}
	if model == nil {
		return fmt.Errorf("missing audit event")
	}
	ensureEventID(model)
	dedupKey := buildDedupKey(model.EventID, p.dedupKeyFn)
	args := buildStreamArgs(model, ttlSeconds(p.dedupTTL))
	result, err := enqueueAuditEventScript.Run(ctx, p.rdb, []string{dedupKey, p.stream}, args...).Text()
	if err != nil {
		return fmt.Errorf("enqueue audit event: %w", err)
	}
	if result == "" {
		return nil
	}
	return nil
}

func ensureEventID(model *auditdomain.Model) {
	if model == nil {
		return
	}
	if strings.TrimSpace(model.EventID) == "" {
		model.EventID = uuid.NewString()
	}
}

func ttlSeconds(value time.Duration) int64 {
	if value <= 0 {
		return int64((24 * time.Hour) / time.Second)
	}
	return int64(value / time.Second)
}

func buildDedupKey(eventID string, dedupKeyFn func(string) string) string {
	if dedupKeyFn != nil {
		return dedupKeyFn(eventID)
	}
	return "audit:dedup:" + strings.TrimSpace(eventID)
}

func buildStreamArgs(model *auditdomain.Model, dedupTTLSeconds int64) []any {
	return []any{
		strings.TrimSpace(model.EventID),
		dedupTTLSeconds,
		strings.TrimSpace(model.EventType),
		formatNullableInt64(model.ClientID),
		formatNullableInt64(model.UserID),
		strings.TrimSpace(model.Subject),
		formatNullableInt64(model.SessionID),
		strings.TrimSpace(model.IPAddress),
		strings.TrimSpace(model.UserAgent),
		strings.TrimSpace(model.MetadataJSON),
		formatCreatedAt(model.CreatedAt),
	}
}

func formatNullableInt64(value *int64) string {
	if value == nil || *value <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", *value)
}

func formatCreatedAt(value time.Time) string {
	if value.IsZero() {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	return value.UTC().Format(time.RFC3339Nano)
}
