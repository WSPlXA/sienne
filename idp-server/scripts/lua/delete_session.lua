-- Atomically delete one session hash and maintain its secondary set index.
--
-- KEYS:
--   KEYS[1] = session hash key
--   KEYS[2] = session index set key (for user/subject/client aggregation)
--
-- ARGV:
--   ARGV[1] = set member to remove from KEYS[2] (typically session reference)
--
-- Return:
--   { deleted_session, removed_index }
--   deleted_session: DEL result for KEYS[1] (0 or 1)
--   removed_index:  SREM result for KEYS[2] member (0 or 1)
local deleted_session = redis.call("DEL", KEYS[1])
local removed_index = redis.call("SREM", KEYS[2], ARGV[1])

-- Avoid keeping empty index sets to reduce key cardinality and memory overhead.
if redis.call("SCARD", KEYS[2]) == 0 then
    redis.call("DEL", KEYS[2])
end

return { deleted_session, removed_index }
