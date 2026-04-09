package redis

import (
	"context"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type MFARepository struct {
	rdb *goredis.Client
	key *KeyBuilder
}

func NewMFARepository(rdb *goredis.Client, key *KeyBuilder) *MFARepository {
	return &MFARepository{rdb: rdb, key: key}
}

func (r *MFARepository) SaveTOTPEnrollment(ctx context.Context, entry cacheport.TOTPEnrollmentEntry, ttl time.Duration) error {
	key := r.key.TOTPEnrollment(entry.SessionID)
	pipe := r.rdb.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{
		"session_id":       entry.SessionID,
		"user_id":          entry.UserID,
		"secret":           entry.Secret,
		"provisioning_uri": entry.ProvisioningURI,
		"expires_at":       formatTime(entry.ExpiresAt),
	})
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *MFARepository) GetTOTPEnrollment(ctx context.Context, sessionID string) (*cacheport.TOTPEnrollmentEntry, error) {
	values, err := r.rdb.HGetAll(ctx, r.key.TOTPEnrollment(sessionID)).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	return &cacheport.TOTPEnrollmentEntry{
		SessionID:       values["session_id"],
		UserID:          values["user_id"],
		Secret:          values["secret"],
		ProvisioningURI: values["provisioning_uri"],
		ExpiresAt:       parseTime(values["expires_at"]),
	}, nil
}

func (r *MFARepository) DeleteTOTPEnrollment(ctx context.Context, sessionID string) error {
	return r.rdb.Del(ctx, r.key.TOTPEnrollment(sessionID)).Err()
}

func (r *MFARepository) ReserveTOTPStepUse(ctx context.Context, userID, purpose string, step int64, ttl time.Duration) (bool, error) {
	ok, err := r.rdb.SetNX(ctx, r.key.TOTPStepUsed(userID, purpose, step), "1", ttl).Result()
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (r *MFARepository) SaveMFAChallenge(ctx context.Context, entry cacheport.MFAChallengeEntry, ttl time.Duration) error {
	key := r.key.MFAChallenge(entry.ChallengeID)
	pipe := r.rdb.TxPipeline()
	pipe.HSet(ctx, key, map[string]any{
		"challenge_id":         entry.ChallengeID,
		"user_id":              entry.UserID,
		"subject":              entry.Subject,
		"username":             entry.Username,
		"ip_address":           entry.IPAddress,
		"user_agent":           entry.UserAgent,
		"return_to":            entry.ReturnTo,
		"redirect_uri":         entry.RedirectURI,
		"mfa_mode":             entry.MFAMode,
		"push_status":          entry.PushStatus,
		"push_code":            entry.PushCode,
		"approver_user_id":     entry.ApproverUserID,
		"decided_at":           formatTime(entry.DecidedAt),
		"passkey_session_json": entry.PasskeySessionJSON,
		"expires_at":           formatTime(entry.ExpiresAt),
	})
	pipe.Expire(ctx, key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (r *MFARepository) GetMFAChallenge(ctx context.Context, challengeID string) (*cacheport.MFAChallengeEntry, error) {
	values, err := r.rdb.HGetAll(ctx, r.key.MFAChallenge(challengeID)).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return nil, nil
	}
	return &cacheport.MFAChallengeEntry{
		ChallengeID:        values["challenge_id"],
		UserID:             values["user_id"],
		Subject:            values["subject"],
		Username:           values["username"],
		IPAddress:          values["ip_address"],
		UserAgent:          values["user_agent"],
		ReturnTo:           values["return_to"],
		RedirectURI:        values["redirect_uri"],
		MFAMode:            values["mfa_mode"],
		PushStatus:         values["push_status"],
		PushCode:           values["push_code"],
		ApproverUserID:     values["approver_user_id"],
		DecidedAt:          parseTime(values["decided_at"]),
		PasskeySessionJSON: values["passkey_session_json"],
		ExpiresAt:          parseTime(values["expires_at"]),
	}, nil
}

func (r *MFARepository) DeleteMFAChallenge(ctx context.Context, challengeID string) error {
	return r.rdb.Del(ctx, r.key.MFAChallenge(challengeID)).Err()
}
