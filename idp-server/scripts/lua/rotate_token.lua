-- Rotate refresh token atomically:
-- 1) validate old token state
-- 2) mark old token revoked + rotated_to
-- 3) persist revoke marker for old token
-- 4) create new token hash
-- 5) update optional user/client index sets
--
-- KEYS:
--   KEYS[1] = old refresh token hash key
--   KEYS[2] = new refresh token hash key
--   KEYS[3] = old token revoke marker key
--   KEYS[4] = optional user refresh-token set key
--   KEYS[5] = optional client refresh-token set key
--
-- ARGV:
--   ARGV[1]  = old token id/reference (stored in rotated_from)
--   ARGV[2]  = new token id/reference (stored in rotated_to and set members)
--   ARGV[3]  = client_id
--   ARGV[4]  = user_id
--   ARGV[5]  = subject
--   ARGV[6]  = scopes_json
--   ARGV[7]  = issued_at
--   ARGV[8]  = expires_at
--   ARGV[9]  = new token TTL (seconds)
--   ARGV[10] = old revoke marker TTL (seconds)
--
-- Return:
--   -1 -> old token does not exist
--   -2 -> old token already revoked or already rotated
--    1 -> rotate success
if redis.call("EXISTS", KEYS[1]) == 0 then
    return -1
end

-- Reject replay rotation: old token can only be rotated once.
local old_revoked = redis.call("HGET", KEYS[1], "revoked")
local rotated_to = redis.call("HGET", KEYS[1], "rotated_to")
if old_revoked == "1" or (rotated_to and rotated_to ~= "") then
    return -2
end

local new_ttl = tonumber(ARGV[9]) or 0
local old_revoke_ttl = tonumber(ARGV[10]) or 0

-- Mark old token as revoked and link it to the new token.
redis.call("HSET", KEYS[1],
    "revoked", "1",
    "rotated_to", ARGV[2]
)

-- Write explicit deny marker for old token.
if old_revoke_ttl > 0 then
    redis.call("SET", KEYS[3], "1", "EX", old_revoke_ttl)
else
    redis.call("SET", KEYS[3], "1")
end

-- Materialize new token hash payload.
redis.call("HSET", KEYS[2],
    "client_id", ARGV[3],
    "user_id", ARGV[4],
    "subject", ARGV[5],
    "scopes_json", ARGV[6],
    "issued_at", ARGV[7],
    "expires_at", ARGV[8],
    "revoked", "0",
    "rotated_from", ARGV[1],
    "rotated_to", ""
)

-- Optional expiration for new token hash.
if new_ttl > 0 then
    redis.call("EXPIRE", KEYS[2], new_ttl)
end

if KEYS[4] ~= "" then
    -- Keep user-level refresh index in sync.
    redis.call("SADD", KEYS[4], "refresh:" .. ARGV[2])
    if new_ttl > 0 then
        -- Extend set TTL when shorter than token TTL; never shrink valid windows.
        local user_set_ttl = redis.call("TTL", KEYS[4])
        if user_set_ttl < 0 or user_set_ttl < new_ttl then
            redis.call("EXPIRE", KEYS[4], new_ttl)
        end
    end
end

if KEYS[5] ~= "" then
    -- Keep client-level refresh index in sync.
    redis.call("SADD", KEYS[5], "refresh:" .. ARGV[2])
    if new_ttl > 0 then
        -- Same TTL extension strategy as user set.
        local client_set_ttl = redis.call("TTL", KEYS[5])
        if client_set_ttl < 0 or client_set_ttl < new_ttl then
            redis.call("EXPIRE", KEYS[5], new_ttl)
        end
    end
end

return 1
