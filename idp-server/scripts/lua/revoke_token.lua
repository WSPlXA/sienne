-- Revoke a token atomically and maintain related revoke/introspection markers.
--
-- KEYS:
--   KEYS[1] = token hash key (optional; empty string means skip token hash update)
--   KEYS[2] = revoke marker key (always written)
--   KEYS[3] = introspection cache key to delete (optional)
--
-- ARGV:
--   ARGV[1] = revoke marker TTL (seconds). <= 0 means no expiration.
--
-- Return:
--   { token_found, introspection_deleted }
--   token_found: 1 if token hash existed and was marked revoked, else 0
--   introspection_deleted: DEL result for KEYS[3] (0 or 1)
local revoke_ttl = tonumber(ARGV[1]) or 0
local token_found = 0
local introspection_deleted = 0

-- Best-effort hash mutation: only if key is provided and exists.
if KEYS[1] ~= "" and redis.call("EXISTS", KEYS[1]) == 1 then
    redis.call("HSET", KEYS[1], "revoked", "1")
    token_found = 1
end

-- Revoke marker is authoritative for fast deny checks.
if revoke_ttl > 0 then
    redis.call("SET", KEYS[2], "1", "EX", revoke_ttl)
else
    redis.call("SET", KEYS[2], "1")
end

-- Remove stale introspection result so revocation is immediately visible.
if KEYS[3] ~= "" then
    introspection_deleted = redis.call("DEL", KEYS[3])
end

return { token_found, introspection_deleted }
