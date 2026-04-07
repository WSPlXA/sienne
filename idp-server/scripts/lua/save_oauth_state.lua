-- Save OAuth state payload exactly once.
--
-- KEYS:
--   KEYS[1] = oauth state hash key
--
-- ARGV:
--   ARGV[1] = client_id
--   ARGV[2] = redirect_uri
--   ARGV[3] = session_id
--   ARGV[4] = created_at
--   ARGV[5] = ttl (seconds), optional
--
-- Return:
--   0 -> state key already exists (reject overwrite)
--   1 -> state persisted
if redis.call("EXISTS", KEYS[1]) == 1 then
    return 0
end

local ttl = tonumber(ARGV[5]) or 0

-- Single hash write keeps related attributes in one key space.
redis.call("HSET", KEYS[1],
    "client_id", ARGV[1],
    "redirect_uri", ARGV[2],
    "session_id", ARGV[3],
    "created_at", ARGV[4]
)

-- Optional lifecycle control for state expiration.
if ttl > 0 then
    redis.call("EXPIRE", KEYS[1], ttl)
end

return 1
