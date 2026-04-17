-- Save session hash and maintain a set index for lookup/list operations.
--
-- KEYS:
--   KEYS[1] = session hash key
--   KEYS[2] = session index set key
--
-- ARGV:
--   ARGV[1]  = set member representing this session
--   ARGV[2]  = user_id
--   ARGV[3]  = subject
--   ARGV[4]  = acr
--   ARGV[5]  = amr_json
--   ARGV[6]  = ip
--   ARGV[7]  = user_agent
--   ARGV[8]  = authenticated_at
--   ARGV[9]  = expires_at
--   ARGV[10] = status
--   ARGV[11] = session TTL (seconds), optional
--   ARGV[12] = state mask (u32), optional
--   ARGV[13] = state version (u32), optional
--
-- Return:
--   1 -> success
local ttl = tonumber(ARGV[11]) or 0
local state_mask = tonumber(ARGV[12]) or 1
local state_ver = tonumber(ARGV[13]) or 1

-- Session payload is stored as a single hash for compact lookup.
redis.call("HSET", KEYS[1],
    "user_id", ARGV[2],
    "subject", ARGV[3],
    "acr", ARGV[4],
    "amr_json", ARGV[5],
    "ip", ARGV[6],
    "user_agent", ARGV[7],
    "authenticated_at", ARGV[8],
    "expires_at", ARGV[9],
    "status", ARGV[10],
    "state_mask", state_mask,
    "state_ver", state_ver
)

-- Optional expiration for session hash.
if ttl > 0 then
    redis.call("EXPIRE", KEYS[1], ttl)
end

-- Maintain reverse index for session enumeration.
redis.call("SADD", KEYS[2], ARGV[1])

if ttl > 0 then
    -- Keep index set alive at least as long as member sessions.
    local set_ttl = redis.call("TTL", KEYS[2])
    if set_ttl < 0 or set_ttl < ttl then
        redis.call("EXPIRE", KEYS[2], ttl)
    end
end

return 1
