-- Atomically consume an authorization code and return its payload.
--
-- KEYS:
--   KEYS[1] = authorization code hash key
--   KEYS[2] = replay/consumed marker key
--
-- ARGV:
--   ARGV[1] = consumed marker TTL (seconds). <= 0 means no expiration.
--
-- Return:
--   { -1 }                 -> authorization code does not exist
--   { -2 }                 -> code is already consumed or replay marker exists
--   { 1, field1, value1... } -> consume success with full hash fields from KEYS[1]
--
-- Notes:
--   1. Script is atomic in Redis, so existence check + consume mutation is race-safe.
--   2. KEYS[2] acts as a fast replay guard for already consumed codes.
local consumed_ttl = tonumber(ARGV[1]) or 0

-- Missing code hash: fail fast.
if redis.call("EXISTS", KEYS[1]) == 0 then
    return { -1 }
end

-- Replay marker already exists: treat as already consumed.
if redis.call("EXISTS", KEYS[2]) == 1 then
    return { -2 }
end

local consumed = redis.call("HGET", KEYS[1], "consumed")
if consumed == "1" then
    -- Hash says consumed already; ensure marker is present as well.
    if consumed_ttl > 0 then
        redis.call("SET", KEYS[2], "1", "EX", consumed_ttl)
    else
        redis.call("SET", KEYS[2], "1")
    end
    return { -2 }
end

-- First successful consume: mutate source hash and write replay marker.
redis.call("HSET", KEYS[1], "consumed", "1")

if consumed_ttl > 0 then
    redis.call("SET", KEYS[2], "1", "EX", consumed_ttl)
else
    redis.call("SET", KEYS[2], "1")
end

-- Return all code payload fields so caller can continue token issuance flow.
local data = redis.call("HGETALL", KEYS[1])
local response = { 1 }

for i = 1, #data do
    response[#response + 1] = data[i]
end

return response
