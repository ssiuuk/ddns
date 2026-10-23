package shared

import (
	"fmt"
	"strconv"

	"github.com/gomodule/redigo/redis"
)

// The TTL of the A and AAAA records of hosts. It is short by default, as
// hosts are expected to change their address at any time, and resolvers
// keep serving the old address for up to this long after a change.
const (
	DefaultRecordTTL = 5
	MinRecordTTL     = 1
	MaxRecordTTL     = 86400
)

// recordTTLKey is under admin:, so it is part of dumps and syncs, also to
// secondaries that do not know the setting yet.
const recordTTLKey = "admin:record-ttl"

// RecordTTLStore keeps the TTL of host records the admin set.
type RecordTTLStore interface {
	RecordTTL() (int, error)
	SetRecordTTL(int) error
}

// RecordTTL returns the TTL of host records, DefaultRecordTTL if none is set.
func (r *RedisBackend) RecordTTL() (int, error) {
	conn := r.pool.Get()
	defer conn.Close()

	value, err := redis.String(conn.Do("GET", recordTTLKey))
	if err == redis.ErrNil {
		return DefaultRecordTTL, nil
	} else if err != nil {
		return 0, err
	}
	ttl, err := strconv.Atoi(value)
	if err != nil || ttl < MinRecordTTL || ttl > MaxRecordTTL {
		return 0, fmt.Errorf("invalid record TTL %q in Redis", value)
	}
	return ttl, nil
}

func (r *RedisBackend) SetRecordTTL(ttl int) error {
	if ttl < MinRecordTTL || ttl > MaxRecordTTL {
		return fmt.Errorf("the TTL has to be between %d and %d seconds", MinRecordTTL, MaxRecordTTL)
	}

	conn := r.pool.Get()
	defer conn.Close()

	conn.Send("MULTI")
	conn.Send("SET", recordTTLKey, ttl)
	sendRecord(conn, recordTTLKey)
	return execOK(conn)
}
