package redis

import (
	"context"
	"fmt"
	"strconv"
	"time"

	cacheport "idp-server/internal/ports/cache"

	goredis "github.com/redis/go-redis/v9"
)

type MFARepository struct {
	rdb     *goredis.Client
	key     *KeyBuilder
	scripts *scriptSet
}

func NewMFARepository(rdb *goredis.Client, key *KeyBuilder) *MFARepository {
	scripts, err := loadScripts()
	if err != nil {
		panic(err)
	}
	return &MFARepository{
		rdb:     rdb,
		key:     key,
		scripts: scripts,
	}
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
	ok, err := r.rdb.SetNX(ctx, r.key.TOTPStepUsed(userID, purpose, step), "1", ttl).Result() //nolint:staticcheck
	if err != nil {
		return false, err
	}
	return ok, nil
}

func (r *MFARepository) SaveMFAChallenge(ctx context.Context, entry cacheport.MFAChallengeEntry, ttl time.Duration) error {
	key := r.key.MFAChallenge(entry.ChallengeID)
	stateMask := cacheport.NormalizeMFAChallengeStateMask(entry.StateMask, entry.MFAMode, entry.PushStatus, entry.PasskeySessionJSON)
	expectedVer := int64(entry.StateVersion)
	cmd := runScript(
		ctx,
		r.scripts.saveMFAChallenge,
		r.rdb,
		[]string{key},
		entry.ChallengeID,
		entry.UserID,
		entry.Subject,
		entry.Username,
		entry.IPAddress,
		entry.UserAgent,
		entry.ReturnTo,
		entry.RedirectURI,
		cacheport.MFAModeFromStateMask(stateMask, entry.MFAMode),
		cacheport.MFAPushStatusFromStateMask(stateMask, entry.PushStatus),
		entry.PushCode,
		entry.ApproverUserID,
		formatTime(entry.DecidedAt),
		entry.PasskeySessionJSON,
		formatTime(entry.ExpiresAt),
		durationSeconds(ttl),
		strconv.FormatUint(uint64(stateMask), 10),
		strconv.FormatInt(expectedVer, 10),
	)
	result, err := cmd.Result()
	if err != nil {
		return err
	}

	values, ok := result.([]any)
	if !ok || len(values) == 0 {
		return fmt.Errorf("save mfa challenge: unexpected lua response %T", result)
	}

	code := toInt64(values[0])
	switch code {
	case 1:
		return nil
	case -2:
		return cacheport.ErrStateVersionConflict
	case -3:
		return cacheport.ErrInvalidStateTransition
	default:
		return fmt.Errorf("save mfa challenge: unexpected lua code %d", code)
	}
}

func (r *MFARepository) GetMFAChallenge(ctx context.Context, challengeID string) (*cacheport.MFAChallengeEntry, error) {
	values, err := r.rdb.HMGet(
		ctx,
		r.key.MFAChallenge(challengeID),
		"challenge_id",
		"user_id",
		"subject",
		"username",
		"ip_address",
		"user_agent",
		"return_to",
		"redirect_uri",
		"mfa_mode",
		"push_status",
		"push_code",
		"approver_user_id",
		"decided_at",
		"passkey_session_json",
		"expires_at",
		"state_mask",
		"state_ver",
	).Result()
	if err != nil {
		return nil, err
	}
	if len(values) == 0 || values[0] == nil {
		return nil, nil
	}
	mode := readRedisString(values[8])
	pushStatus := readRedisString(values[9])
	passkeySessionJSON := readRedisString(values[13])
	stateMask := cacheport.NormalizeMFAChallengeStateMask(parseUint32(readRedisString(values[15])), mode, pushStatus, passkeySessionJSON)
	return &cacheport.MFAChallengeEntry{
		ChallengeID:        readRedisString(values[0]),
		UserID:             readRedisString(values[1]),
		Subject:            readRedisString(values[2]),
		Username:           readRedisString(values[3]),
		IPAddress:          readRedisString(values[4]),
		UserAgent:          readRedisString(values[5]),
		ReturnTo:           readRedisString(values[6]),
		RedirectURI:        readRedisString(values[7]),
		MFAMode:            cacheport.MFAModeFromStateMask(stateMask, mode),
		PushStatus:         cacheport.MFAPushStatusFromStateMask(stateMask, pushStatus),
		PushCode:           readRedisString(values[10]),
		ApproverUserID:     readRedisString(values[11]),
		DecidedAt:          parseTime(readRedisString(values[12])),
		PasskeySessionJSON: passkeySessionJSON,
		ExpiresAt:          parseTime(readRedisString(values[14])),
		StateMask:          stateMask,
		StateVersion:       parseUint32(readRedisString(values[16])),
	}, nil
}

func (r *MFARepository) DeleteMFAChallenge(ctx context.Context, challengeID string) error {
	return r.rdb.Del(ctx, r.key.MFAChallenge(challengeID)).Err()
}

func toInt64(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case string:
		return parseInt64(typed)
	default:
		return 0
	}
}
