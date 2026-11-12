-- Only trusted application-verified password outcomes reach this script.
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if ARGV[1] == 'succeeded' then
    if ARGV[6] == '1' then redis.call('DEL', KEYS[1]) end
    return {1, 0, tonumber(ARGV[2]), 0, now, 'auth'}
end
local blocked = redis.call('HMGET', KEYS[2], 'count', 'threshold', 'source')
if blocked[1] then
    return {1, tonumber(blocked[1]), tonumber(blocked[2]), redis.call('PTTL', KEYS[2]), now, 'auth'}
end
local limit = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
redis.call('ZADD', KEYS[1], 'NX', now, ARGV[4])
local count = redis.call('ZCARD', KEYS[1])
redis.call('PEXPIRE', KEYS[1], window)
if count >= limit then
    if ARGV[7] == 'record' then
        redis.call('ZREMRANGEBYRANK', KEYS[1], 0, -limit - 1)
        return {2, math.min(count, limit + 1), limit, 0, now, 'auth'}
    end
    redis.call('HSET', KEYS[2], 'count', count, 'threshold', limit, 'source', 'auth')
    redis.call('PEXPIRE', KEYS[2], tonumber(ARGV[5]))
    redis.call('DEL', KEYS[1])
    return {4, count, limit, tonumber(ARGV[5]), now, 'auth'}
end
return {1, count, limit, 0, now, 'auth'}
