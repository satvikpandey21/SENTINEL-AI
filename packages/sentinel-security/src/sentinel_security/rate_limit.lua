-- Every decision is atomic. Redis TIME avoids trusting API-instance clocks.
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local blocked = redis.call('HMGET', KEYS[2], 'count', 'threshold', 'source')
if blocked[1] then
    return {4, tonumber(blocked[1]), tonumber(blocked[2]), redis.call('PTTL', KEYS[2]), now, blocked[3]}
end
local limit = tonumber(ARGV[1])
if limit == 0 then return {1, 0, 0, 0, now, 'rate'} end
local window = tonumber(ARGV[2])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])
if count >= limit then
    local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    local retry = math.max(1, tonumber(oldest[2]) + window - now)
    if ARGV[4] == 'block' then
        redis.call('HSET', KEYS[2], 'count', count + 1, 'threshold', limit, 'source', 'rate')
        redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[5]))
        return {4, count + 1, limit, tonumber(ARGV[5]), now, 'rate'}
    end
    if ARGV[4] == 'record' then
        redis.call('ZREMRANGEBYRANK', KEYS[1], 0, 0)
        redis.call('ZADD', KEYS[1], now, ARGV[3])
        redis.call('PEXPIRE', KEYS[1], window)
        return {2, count + 1, limit, retry, now, 'rate'}
    end
    return {3, count + 1, limit, retry, now, 'rate'}
end
redis.call('ZADD', KEYS[1], 'NX', now, ARGV[3])
redis.call('PEXPIRE', KEYS[1], window)
return {1, redis.call('ZCARD', KEYS[1]), limit, 0, now, 'rate'}
