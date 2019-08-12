package storageredis

import (
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/bsm/redislock"
	"github.com/caddyserver/caddy/caddytls"
	"github.com/go-redis/redis"
	"github.com/mholt/certmagic"
)

const (
	// InactiveLockDuration is when the lock is considered as stale and need to be refreshed
	InactiveLockDuration = 4 * time.Hour

	// LockDuration is lock time duration
	LockDuration = 8 * time.Hour

	// ScanCount is how many scan command might return
	ScanCount int64 = 100
)

// RedisStorage contain Redis client, and plugin option
type RedisStorage struct {
	Client       *redis.Client
	ClientLocker *redislock.Client
	Options      *Options
	locks        map[string]*redislock.Lock
}

// StorageData describe the data that is stored in KV storage
type StorageData struct {
	Value    []byte    `json:"value"`
	Modified time.Time `json:"modified"`
}

func init() {
	caddytls.RegisterClusterPlugin("redis", constructRedisClusterPlugin)
}

// helper function to prefix key
func (rd *RedisStorage) prefixKey(key string) string {
	return path.Join(rd.Options.KeyPrefix, key)
}

// GetRedisStorage build RedisStorage
func GetRedisStorage() (*RedisStorage, error) {
	opt := GetOptions()

	redisClient := redis.NewClient(&redis.Options{
		Addr:         opt.Host + ":" + opt.Port,
		Password:     opt.Password,
		DB:           opt.DB,
		DialTimeout:  time.Second * time.Duration(opt.Timeout),
		ReadTimeout:  time.Second * time.Duration(opt.Timeout),
		WriteTimeout: time.Second * time.Duration(opt.Timeout),
	})

	_, err := redisClient.Ping().Result()
	if err != nil {
		return nil, err
	}

	rd := &RedisStorage{
		Client:       redisClient,
		Options:      opt,
		ClientLocker: redislock.New(redisClient),
		locks:        make(map[string]*redislock.Lock),
	}

	return rd, nil
}

// Store values at key
func (rd RedisStorage) Store(key string, value []byte) error {
	data := &StorageData{
		Value:    value,
		Modified: time.Now(),
	}

	encryptedValue, err := rd.EncryptStorageData(data)
	if err != nil {
		return fmt.Errorf("unable to encode data for %v: %v", key, err)
	}

	if err := rd.Client.Set(rd.prefixKey(key), encryptedValue, 0).Err(); err != nil {
		return fmt.Errorf("unable to store data for %v: %v", key, err)
	}

	return nil
}

// Load retrieves the value at key.
func (rd RedisStorage) Load(key string) ([]byte, error) {
	data, err := rd.getDataDecrypted(key)

	if err != nil {
		return nil, err
	}

	return data.Value, nil
}

// Delete deletes key.
func (rd RedisStorage) Delete(key string) error {
	_, err := rd.getData(key)

	if err != nil {
		return err
	}

	if err := rd.Client.Del(rd.prefixKey(key)).Err(); err != nil {
		return fmt.Errorf("unable to delete data for key %s: %v", key, err)
	}

	return nil
}

// Exists returns true if the key exists
func (rd RedisStorage) Exists(key string) bool {
	_, err := rd.getData(key)
	if err == nil {
		return true
	}
	return false
}

// List returns all keys that match prefix.
func (rd RedisStorage) List(prefix string, recursive bool) ([]string, error) {
	var keysFound []string
	var tempKeys []string
	var firstPointer uint64 = 0
	var pointer uint64 = 0

	// first SCAN command
	keys, pointer, err := rd.Client.Scan(pointer, rd.prefixKey(prefix)+"*", ScanCount).Result()
	if err != nil {
		return keysFound, err
	}
	// store it temporarily
	tempKeys = append(tempKeys, keys...)
	// because SCAN command doesn't always return all possible, keep searching until pointer is equal to the firstPointer
	for pointer != firstPointer {
		keys, nextPointer, _ := rd.Client.Scan(pointer, rd.prefixKey(prefix)+"*", ScanCount).Result()
		tempKeys = append(tempKeys, keys...)
		pointer = nextPointer
	}

	// remove default prefix from keys
	for _, key := range tempKeys {
		if strings.HasPrefix(key, rd.prefixKey(prefix)) {
			key = strings.TrimPrefix(key, rd.Options.KeyPrefix+"/")
			keysFound = append(keysFound, key)
		}
	}

	// if recursive wanted, just return all keys
	if recursive {
		return keysFound, nil
	}

	// for non-recursive split path and look for unique keys just under given prefix
	keysMap := make(map[string]bool)
	for _, key := range keysFound {
		dir := strings.Split(strings.TrimPrefix(key, prefix+"/"), "/")
		keysMap[dir[0]] = true
	}

	keysFound = make([]string, 0)
	for key := range keysMap {
		keysFound = append(keysFound, path.Join(prefix, key))
	}

	return keysFound, nil
}

// Stat returns information about key.
func (rd RedisStorage) Stat(key string) (certmagic.KeyInfo, error) {
	data, err := rd.getDataDecrypted(key)

	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   data.Modified,
		Size:       int64(len(data.Value)),
		IsTerminal: false,
	}, nil
}

// getData return data from redis by key as it is
func (rd RedisStorage) getData(key string) ([]byte, error) {
	data, err := rd.Client.Get(rd.prefixKey(key)).Bytes()

	if err != nil {
		return nil, fmt.Errorf("unable to obtain data for %s: %v", key, err)
	} else if data == nil {
		return nil, certmagic.ErrNotExist(fmt.Errorf("key %s does not exist", key))
	}

	return data, nil
}

// getDataDecrypted return StorageData by key
func (rd RedisStorage) getDataDecrypted(key string) (*StorageData, error) {
	data, err := rd.getData(key)

	if err != nil {
		return nil, err
	}

	decryptedData, err := rd.DecryptStorageData(data)

	if err != nil {
		return nil, fmt.Errorf("unable to decrypt data for %s: %v", key, err)
	}

	return decryptedData, nil
}

// Lock is to lock value
func (rd RedisStorage) Lock(key string) error {
	lockName := rd.prefixKey(key) + ".lock"

	// check if we have the lock
	if lock, exists := rd.locks[key]; exists {
		if ttl, err := lock.TTL(); err != nil {
			return err
		} else if ttl < InactiveLockDuration && ttl > 0 {
			// if the lock almost ending
			err := lock.Refresh(LockDuration, nil)
			if err != nil {
				return err
			}
		} else if ttl == 0 {
			// lock is dead, clean it up from locks data
			_ = lock.Release()
			delete(rd.locks, key)
		} else {
			return nil
		}
	}

	// obtain new lock
	lockActive, err := rd.ClientLocker.Obtain(lockName, LockDuration, nil)
	if err != nil {
		return fmt.Errorf("can't obtain lock, it still being held by other, %v", err)
	}

	// save it
	rd.locks[key] = lockActive

	return nil
}

// Unlock is to unlock value
func (rd RedisStorage) Unlock(key string) error {
	if lock, exists := rd.locks[key]; exists {
		err := lock.Release()
		delete(rd.locks, key)
		if err != nil {
			return fmt.Errorf("we don't have this lock anymore, %v", err)
		}
	}
	return nil
}

func constructRedisClusterPlugin() (certmagic.Storage, error) {
	return GetRedisStorage()
}
