-- Reserve a nonce exactly once using SET NX semantics.
--
-- KEYS:
--   KEYS[1] = nonce key
--
-- ARGV:
--   ARGV[1] = value to store (usually metadata or marker)
--   ARGV[2] = nonce TTL (seconds). <= 0 means no expiration.
--
-- Return:
--   1 -> nonce reserved successfully
--   0 -> nonce already exists
local ttl = tonumber(ARGV[2]) or 0

if ttl > 0 then
    -- Reserve with expiration window.
    local ok = redis.call("SET", KEYS[1], ARGV[1], "EX", ttl, "NX")
    if ok then
        return 1
    end
    return 0
end

-- Reserve without expiration for callers that manage lifecycle externally.
local ok = redis.call("SET", KEYS[1], ARGV[1], "NX")
if ok then
    return 1
end

return 0
