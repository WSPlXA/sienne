-- Increment a counter and optionally set a lock key after threshold is reached.
--
-- KEYS:
--   KEYS[1] = counter key (string integer)
--   KEYS[2] = optional lock key (empty string disables lock behavior)
--
-- ARGV:
--   ARGV[1] = counter TTL (seconds), applied only on first increment
--   ARGV[2] = threshold to trigger lock
--   ARGV[3] = lock TTL (seconds)
--
-- Return:
--   { count, ttl, locked }
--   count  = counter value after INCR
--   ttl    = current TTL of counter key (Redis TTL semantics)
--   locked = 1 if lock key was set in this call, otherwise 0
local counter_ttl = tonumber(ARGV[1]) or 0
local threshold = tonumber(ARGV[2]) or 0
local lock_ttl = tonumber(ARGV[3]) or 0

-- INCR both initializes and increments atomically.
local count = redis.call("INCR", KEYS[1])

-- Apply counter expiration only at creation time to keep a stable counting window.
if count == 1 and counter_ttl > 0 then
    redis.call("EXPIRE", KEYS[1], counter_ttl)
end

local locked = 0
-- Lock only when all guard conditions are valid and threshold is reached.
if KEYS[2] ~= "" and threshold > 0 and lock_ttl > 0 and count >= threshold then
    redis.call("SET", KEYS[2], "1", "EX", lock_ttl)
    locked = 1
end

-- Return post-operation TTL so caller can inspect remaining counter window.
local ttl = redis.call("TTL", KEYS[1])
return { count, ttl, locked }
