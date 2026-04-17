# Redis Lua Scripts

These scripts cover the Redis-side atomic operations behind the current IdP cache design.

## Conventions

- All TTL arguments are in seconds.
- All keys are passed through `KEYS`.
- All scalar inputs are passed through `ARGV`.
- Return values use small integer status codes where practical:
  - `1` means success.
  - `0` means a no-op or duplicate reservation.
  - negative values mean business errors such as missing data or replay.

## Scripts

### `save_session.lua`

Atomically writes the browser session hash and the reverse user-to-session index.

- `KEYS[1]`: session hash key
- `KEYS[2]`: user session set key
- `ARGV[1]`: session id
- `ARGV[2]`: user id
- `ARGV[3]`: subject
- `ARGV[4]`: acr
- `ARGV[5]`: amr json
- `ARGV[6]`: ip address
- `ARGV[7]`: user agent
- `ARGV[8]`: authenticated at
- `ARGV[9]`: expires at
- `ARGV[10]`: status
- `ARGV[11]`: ttl seconds
- `ARGV[12]`: state mask (u32)
- `ARGV[13]`: state version (u32)

### `delete_session.lua`

Atomically deletes the session hash and removes the session id from the user reverse index.

- `KEYS[1]`: session hash key
- `KEYS[2]`: user session set key
- `ARGV[1]`: session id

Returns `{deleted_session_count, removed_index_count}`.

### `consume_authorization_code.lua`

Atomically enforces one-time authorization code consumption.

- `KEYS[1]`: authorization code hash key
- `KEYS[2]`: consumed marker key
- `ARGV[1]`: consumed marker ttl seconds

Returns:

- `{-1}` when the code does not exist
- `{-2}` when the code was already consumed
- `{1, field1, value1, field2, value2, ...}` on success

### `save_oauth_state.lua`

Creates a state record only if it does not already exist.

- `KEYS[1]`: oauth state key
- `ARGV[1]`: client id
- `ARGV[2]`: redirect uri
- `ARGV[3]`: session id
- `ARGV[4]`: created at
- `ARGV[5]`: ttl seconds

### `reserve_nonce.lua`

Reserves a nonce exactly once using `SET NX EX`.

- `KEYS[1]`: nonce key
- `ARGV[1]`: value
- `ARGV[2]`: ttl seconds

Returns `1` when reserved and `0` when it already exists.

### `save_mfa_challenge.lua`

Creates or updates an MFA challenge hash with bitmask state and optimistic CAS.

- `KEYS[1]`: mfa challenge hash key
- `ARGV[1]`~`ARGV[15]`: challenge payload fields
- `ARGV[16]`: ttl seconds
- `ARGV[17]`: next state mask (u32)
- `ARGV[18]`: expected version (u32), `-1` means no CAS

Returns:

- `{1, next_ver}` on success
- `{-2, cur_ver}` on version conflict
- `{-3, cur_ver}` on invalid transition

### `increment_with_ttl.lua`

Generic counter helper for login failures and route rate limits.

- `KEYS[1]`: counter key
- `KEYS[2]`: optional lock key, pass empty string if unused
- `ARGV[1]`: counter ttl seconds
- `ARGV[2]`: lock threshold
- `ARGV[3]`: lock ttl seconds

Returns `{count, ttl, locked}`.

### `revoke_token.lua`

Writes a revoke marker, flags the token hash as revoked when present, and clears introspection cache.

- `KEYS[1]`: token hash key, pass empty string if absent
- `KEYS[2]`: revoke marker key
- `KEYS[3]`: introspection cache key, pass empty string if unused
- `ARGV[1]`: revoke ttl seconds

Returns `{token_found, introspection_deleted}`.

### `rotate_token.lua`

Atomically rotates a refresh token by revoking the old token, creating the new token, and updating user/client indexes.

- `KEYS[1]`: old refresh token hash key
- `KEYS[2]`: new refresh token hash key
- `KEYS[3]`: old refresh revoke marker key
- `KEYS[4]`: user token set key
- `KEYS[5]`: client token set key
- `ARGV[1]`: old token sha256
- `ARGV[2]`: new token sha256
- `ARGV[3]`: client id
- `ARGV[4]`: user id
- `ARGV[5]`: subject
- `ARGV[6]`: scopes json
- `ARGV[7]`: issued at
- `ARGV[8]`: expires at
- `ARGV[9]`: new token ttl seconds
- `ARGV[10]`: old revoke ttl seconds

Returns:

- `-1` when the old token does not exist
- `-2` when the old token is already revoked or rotated
- `1` on success
