package auditstream

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	auditdomain "idp-server/internal/domain/audit"
	"idp-server/internal/ports/repository"

	goredis "github.com/redis/go-redis/v9"
)

type ConsumerConfig struct {
	Stream          string
	DLQStream       string
	Group           string
	Consumer        string
	BatchSize       int64
	BlockTimeout    time.Duration
	ReclaimIdle     time.Duration
	RetryTTL        time.Duration
	MaxRetryCount   int64
	ReclaimInterval time.Duration
}

type Consumer struct {
	rdb        *goredis.Client
	writer     repository.AuditEventRepository
	cfg        ConsumerConfig
	retryKeyFn func(eventID string) string
}

func NewConsumer(rdb *goredis.Client, writer repository.AuditEventRepository, cfg ConsumerConfig, retryKeyFn func(eventID string) string) *Consumer {
	return &Consumer{
		rdb:        rdb,
		writer:     writer,
		cfg:        normalizeConsumerConfig(cfg),
		retryKeyFn: retryKeyFn,
	}
}

func (c *Consumer) Start(ctx context.Context) error {
	if c == nil || c.rdb == nil {
		return fmt.Errorf("missing audit consumer redis client")
	}
	if c.writer == nil {
		return fmt.Errorf("missing audit consumer writer")
	}
	if err := c.ensureGroup(ctx); err != nil {
		return err
	}

	go c.readLoop(ctx)
	go c.reclaimLoop(ctx)
	return nil
}

func (c *Consumer) ensureGroup(ctx context.Context) error {
	err := c.rdb.XGroupCreateMkStream(ctx, c.cfg.Stream, c.cfg.Group, "0").Err()
	if err == nil || strings.Contains(err.Error(), "BUSYGROUP") {
		return nil
	}
	return fmt.Errorf("create audit stream group: %w", err)
}

func (c *Consumer) readLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		streams, err := c.rdb.XReadGroup(ctx, &goredis.XReadGroupArgs{
			Group:    c.cfg.Group,
			Consumer: c.cfg.Consumer,
			Streams:  []string{c.cfg.Stream, ">"},
			Count:    c.cfg.BatchSize,
			Block:    c.cfg.BlockTimeout,
		}).Result()
		if err != nil {
			if err == goredis.Nil || ctx.Err() != nil {
				continue
			}
			log.Printf("audit_stream read failed group=%s consumer=%s err=%v", c.cfg.Group, c.cfg.Consumer, err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		for _, stream := range streams {
			c.processMessages(ctx, stream.Messages)
		}
	}
}

func (c *Consumer) reclaimLoop(ctx context.Context) {
	ticker := time.NewTicker(c.cfg.ReclaimInterval)
	defer ticker.Stop()

	var start string
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start = "0-0"
			for {
				result, next, err := c.rdb.XAutoClaim(ctx, &goredis.XAutoClaimArgs{
					Stream:   c.cfg.Stream,
					Group:    c.cfg.Group,
					Consumer: c.cfg.Consumer,
					MinIdle:  c.cfg.ReclaimIdle,
					Start:    start,
					Count:    c.cfg.BatchSize,
				}).Result()
				if err != nil {
					if err != goredis.Nil && ctx.Err() == nil {
						log.Printf("audit_stream reclaim failed group=%s consumer=%s err=%v", c.cfg.Group, c.cfg.Consumer, err)
					}
					break
				}
				if len(result) == 0 {
					break
				}
				c.processMessages(ctx, result)
				if next == "" || next == "0-0" {
					break
				}
				start = next
			}
		}
	}
}

func (c *Consumer) processMessages(ctx context.Context, messages []goredis.XMessage) {
	for _, message := range messages {
		model, err := decodeMessage(message)
		if err != nil {
			c.moveToDLQ(ctx, message, nil, fmt.Errorf("decode message: %w", err), true)
			continue
		}
		if err := c.writer.Create(ctx, model); err != nil {
			retryCount := c.incrementRetry(ctx, model.EventID)
			if retryCount >= c.cfg.MaxRetryCount {
				c.moveToDLQ(ctx, message, model, err, false)
				continue
			}
			log.Printf("audit_stream persist failed event_id=%s retry=%d err=%v", model.EventID, retryCount, err)
			continue
		}
		c.clearRetry(ctx, model.EventID)
		if err := c.rdb.XAck(ctx, c.cfg.Stream, c.cfg.Group, message.ID).Err(); err != nil {
			log.Printf("audit_stream ack failed event_id=%s message_id=%s err=%v", model.EventID, message.ID, err)
		}
	}
}

func (c *Consumer) moveToDLQ(ctx context.Context, message goredis.XMessage, model *auditdomain.Model, cause error, malformed bool) {
	fields := map[string]any{
		"stream_message_id": message.ID,
		"failed_at":         time.Now().UTC().Format(time.RFC3339Nano),
		"error":             strings.TrimSpace(cause.Error()),
		"malformed":         strconv.FormatBool(malformed),
	}
	for key, value := range message.Values {
		fields[key] = stringify(value)
	}
	if model != nil {
		fields["event_id"] = model.EventID
		fields["retry_count"] = strconv.FormatInt(c.readRetry(ctx, model.EventID), 10)
	}
	if _, err := c.rdb.XAdd(ctx, &goredis.XAddArgs{
		Stream: c.cfg.DLQStream,
		Values: fields,
	}).Result(); err != nil {
		log.Printf("audit_stream dlq write failed message_id=%s err=%v", message.ID, err)
		return
	}
	if err := c.rdb.XAck(ctx, c.cfg.Stream, c.cfg.Group, message.ID).Err(); err != nil {
		log.Printf("audit_stream ack after dlq failed message_id=%s err=%v", message.ID, err)
		return
	}
	if model != nil {
		c.clearRetry(ctx, model.EventID)
	}
}

func (c *Consumer) incrementRetry(ctx context.Context, eventID string) int64 {
	if strings.TrimSpace(eventID) == "" {
		return c.cfg.MaxRetryCount
	}
	key := c.retryKey(eventID)
	count, err := c.rdb.Incr(ctx, key).Result()
	if err != nil {
		log.Printf("audit_stream retry increment failed event_id=%s err=%v", eventID, err)
		return c.cfg.MaxRetryCount
	}
	if c.cfg.RetryTTL > 0 {
		_ = c.rdb.Expire(ctx, key, c.cfg.RetryTTL).Err()
	}
	return count
}

func (c *Consumer) readRetry(ctx context.Context, eventID string) int64 {
	if strings.TrimSpace(eventID) == "" {
		return 0
	}
	value, err := c.rdb.Get(ctx, c.retryKey(eventID)).Int64()
	if err != nil {
		return 0
	}
	return value
}

func (c *Consumer) clearRetry(ctx context.Context, eventID string) {
	if strings.TrimSpace(eventID) == "" {
		return
	}
	if err := c.rdb.Del(ctx, c.retryKey(eventID)).Err(); err != nil {
		log.Printf("audit_stream retry clear failed event_id=%s err=%v", eventID, err)
	}
}

func normalizeConsumerConfig(cfg ConsumerConfig) ConsumerConfig {
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 16
	}
	if cfg.BlockTimeout <= 0 {
		cfg.BlockTimeout = 2 * time.Second
	}
	if cfg.ReclaimIdle <= 0 {
		cfg.ReclaimIdle = 30 * time.Second
	}
	if cfg.ReclaimInterval <= 0 {
		cfg.ReclaimInterval = 15 * time.Second
	}
	if cfg.RetryTTL <= 0 {
		cfg.RetryTTL = 24 * time.Hour
	}
	if cfg.MaxRetryCount <= 0 {
		cfg.MaxRetryCount = 10
	}
	return cfg
}

func (c *Consumer) retryKey(eventID string) string {
	if c.retryKeyFn != nil {
		return c.retryKeyFn(eventID)
	}
	return "audit:retry:" + strings.TrimSpace(eventID)
}

func decodeMessage(message goredis.XMessage) (*auditdomain.Model, error) {
	eventID := strings.TrimSpace(readStringField(message.Values, "event_id"))
	eventType := strings.TrimSpace(readStringField(message.Values, "event_type"))
	if eventID == "" || eventType == "" {
		return nil, fmt.Errorf("missing required audit stream fields")
	}
	model := &auditdomain.Model{
		EventID:      eventID,
		EventType:    eventType,
		Subject:      strings.TrimSpace(readStringField(message.Values, "subject")),
		IPAddress:    strings.TrimSpace(readStringField(message.Values, "ip_address")),
		UserAgent:    strings.TrimSpace(readStringField(message.Values, "user_agent")),
		MetadataJSON: strings.TrimSpace(readStringField(message.Values, "metadata_json")),
	}
	if value, ok, err := parseOptionalInt64(message.Values, "client_id"); err != nil {
		return nil, err
	} else if ok {
		model.ClientID = &value
	}
	if value, ok, err := parseOptionalInt64(message.Values, "user_id"); err != nil {
		return nil, err
	} else if ok {
		model.UserID = &value
	}
	if value, ok, err := parseOptionalInt64(message.Values, "session_id"); err != nil {
		return nil, err
	} else if ok {
		model.SessionID = &value
	}
	if raw := strings.TrimSpace(readStringField(message.Values, "created_at")); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		model.CreatedAt = parsed
	}
	return model, nil
}

func parseOptionalInt64(values map[string]any, key string) (int64, bool, error) {
	raw := strings.TrimSpace(readStringField(values, key))
	if raw == "" {
		return 0, false, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse %s: %w", key, err)
	}
	return value, true, nil
}

func readStringField(values map[string]any, key string) string {
	value, ok := values[key]
	if !ok {
		return ""
	}
	return stringify(value)
}

func stringify(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	case fmt.Stringer:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}
