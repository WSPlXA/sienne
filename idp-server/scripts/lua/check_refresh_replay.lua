-- Inspect an old refresh token for grace-period replay handling.
--
-- KEYS:
--   KEYS[1] = old refresh token hash key
--   KEYS[2] = old token grace response key
--   KEYS[3] = refresh token family revoked key prefix
--
-- ARGV:
--   ARGV[1] = now unix ts
--   ARGV[2] = replay fingerprint
--
-- Return:
--   {0, ""}   -> no replay decision, continue normal flow
--   {1, json} -> grace replay, return cached response
--   {-1, ""}  -> reject as replay/family revoked
if redis.call("EXISTS", KEYS[1]) == 0 then
    return { 0, "" }
end

local status = redis.call("HGET", KEYS[1], "status")
local family_id = redis.call("HGET", KEYS[1], "family_id")
if not family_id or family_id == "" then
    family_id = ARGV[3]
end
local family_key = KEYS[3] .. family_id
if redis.call("EXISTS", family_key) == 1 then
    return { -1, "" }
end

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

if status == "active" then
    return { 0, "" }
end

if status == "rotated" then
    local grace_until = tonumber(redis.call("HGET", KEYS[1], "grace_until") or "0")
    local bind_fp = redis.call("HGET", KEYS[1], "bind_fp") or ""
    local now_ts = tonumber(ARGV[1]) or 0
    if now_ts <= grace_until then
        if bind_fp == "" or bind_fp == ARGV[2] then
            local cached = redis.call("GET", KEYS[2]) or ""
            if cached ~= "" then
                return { 1, cached }
            end
            return { -1, "" }
        end
    end

    local family_ttl = redis.call("TTL", KEYS[1])
    if family_ttl <= 0 then
        family_ttl = 60
    end
    redis.call("SET", family_key, "1", "EX", family_ttl)
    redis.call("HSET", KEYS[1], "status", "compromised")
    return { -1, "" }
end

return { -1, "" }
