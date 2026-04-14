-- Rotate refresh token atomically with a short grace-period replay cache.
--
-- KEYS:
--   KEYS[1] = old refresh token hash key
--   KEYS[2] = new refresh token hash key
--   KEYS[3] = old token grace response key
--   KEYS[4] = refresh token family revoked key prefix
--   KEYS[5] = optional user refresh-token set key
--   KEYS[6] = optional client refresh-token set key
--
-- ARGV:
--   ARGV[1]  = old token sha
--   ARGV[2]  = new token sha
--   ARGV[3]  = client_id
--   ARGV[4]  = user_id
--   ARGV[5]  = subject
--   ARGV[6]  = scopes_json
--   ARGV[7]  = issued_at
--   ARGV[8]  = expires_at
--   ARGV[9]  = new token TTL (seconds)
--   ARGV[10] = grace TTL (seconds)
--   ARGV[11] = now unix ts
--   ARGV[12] = replay fingerprint
--   ARGV[13] = response json
--
-- Return:
--   1 -> rotate success
--  -1 -> old token missing
--  -2 -> old token already rotated/revoked
--  -3 -> token family already revoked
if redis.call("EXISTS", KEYS[1]) == 0 then
    return -1
end

local status = redis.call("HGET", KEYS[1], "status")
if not status or status == "" then
    local revoked = redis.call("HGET", KEYS[1], "revoked")
    local rotated_to = redis.call("HGET", KEYS[1], "rotated_to")
    if revoked == "1" then
        status = "revoked"
    elseif rotated_to and rotated_to ~= "" then
        status = "rotated"
    else
        status = "active"
    end
end

if status ~= "active" then
    return -2
end

local new_ttl = tonumber(ARGV[9]) or 0
local grace_ttl = tonumber(ARGV[10]) or 0
local now_ts = tonumber(ARGV[11]) or 0
local grace_until = now_ts + grace_ttl
local family_id = redis.call("HGET", KEYS[1], "family_id")
if not family_id or family_id == "" then
    family_id = ARGV[1]
end
local family_key = KEYS[4] .. family_id

if redis.call("EXISTS", family_key) == 1 then
    return -3
end

redis.call("HSET", KEYS[1],
    "status", "rotated",
    "rotated_to", ARGV[2],
    "rotated_at", tostring(now_ts),
    "grace_until", tostring(grace_until),
    "bind_fp", ARGV[12],
    "family_id", family_id
)

redis.call("HSET", KEYS[2],
    "client_id", ARGV[3],
    "user_id", ARGV[4],
    "subject", ARGV[5],
    "scopes_json", ARGV[6],
    "issued_at", ARGV[7],
    "expires_at", ARGV[8],
    "status", "active",
    "revoked", "0",
    "family_id", family_id,
    "rotated_from", ARGV[1],
    "rotated_to", "",
    "rotated_at", "",
    "grace_until", "",
    "bind_fp", ""
)

if new_ttl > 0 then
    redis.call("EXPIRE", KEYS[2], new_ttl)
end

if grace_ttl > 0 then
    redis.call("SET", KEYS[3], ARGV[13], "EX", grace_ttl)
else
    redis.call("SET", KEYS[3], ARGV[13])
end

if KEYS[5] ~= "" then
    redis.call("SADD", KEYS[5], "refresh:" .. ARGV[2])
    if new_ttl > 0 then
        local user_set_ttl = redis.call("TTL", KEYS[5])
        if user_set_ttl < 0 or user_set_ttl < new_ttl then
            redis.call("EXPIRE", KEYS[5], new_ttl)
        end
    end
end

if KEYS[6] ~= "" then
    redis.call("SADD", KEYS[6], "refresh:" .. ARGV[2])
    if new_ttl > 0 then
        local client_set_ttl = redis.call("TTL", KEYS[6])
        if client_set_ttl < 0 or client_set_ttl < new_ttl then
            redis.call("EXPIRE", KEYS[6], new_ttl)
        end
    end
end

return 1
