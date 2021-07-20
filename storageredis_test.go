package storageredis

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"sync"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/assert"
)

const TestPrefix = "redistlstest"

// these tests needs a running Redis server
func setupRedisEnv(t *testing.T) *RedisStorage {
	os.Setenv(EnvNameKeyPrefix, TestPrefix)
	os.Setenv(EnvNameRedisDB, "9")

	rd := new(RedisStorage)
	rd.GetConfigValue()
	err := rd.BuildRedisClient()

	// skip test if no redis storage
	if err != nil {
		t.Skip()
		return nil
	}

	assert.NoError(t, err)
	assert.Equal(t, TestPrefix, rd.KeyPrefix)
	assert.Equal(t, 9, rd.DB)

	_, err = rd.Client.FlushAll(rd.ctx).Result()
	assert.NoError(t, err)
	return rd
}

func TestRedisStorage_Store(t *testing.T) {
	rd := setupRedisEnv(t)

	err := rd.Store(path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"), []byte("crt data"))
	assert.NoError(t, err)
}

func TestRedisStorage_Exists(t *testing.T) {
	rd := setupRedisEnv(t)

	key := path.Join("acme", "example.com", "sites", "example.com", "example.com.crt")

	err := rd.Store(key, []byte("crt data"))
	assert.NoError(t, err)

	exists := rd.Exists(key)
	assert.True(t, exists)
}

func TestRedisStorage_Load(t *testing.T) {
	rd := setupRedisEnv(t)

	key := path.Join("acme", "example.com", "sites", "example.com", "example.com.crt")
	content := []byte("crt data")

	err := rd.Store(key, content)
	assert.NoError(t, err)

	contentLoded, err := rd.Load(key)
	assert.NoError(t, err)

	assert.Equal(t, content, contentLoded)
}

func TestRedisStorage_Delete(t *testing.T) {
	rd := setupRedisEnv(t)

	key := path.Join("acme", "example.com", "sites", "example.com", "example.com.crt")
	content := []byte("crt data")

	err := rd.Store(key, content)
	assert.NoError(t, err)

	err = rd.Delete(key)
	assert.NoError(t, err)

	exists := rd.Exists(key)
	assert.False(t, exists)

	contentLoaded, err := rd.Load(key)
	assert.Nil(t, contentLoaded)

	_, ok := err.(certmagic.ErrNotExist)
	assert.True(t, ok)
}

func TestRedisStorage_Stat(t *testing.T) {
	rd := setupRedisEnv(t)

	key := path.Join("acme", "example.com", "sites", "example.com", "example.com.crt")
	content := []byte("crt data")

	err := rd.Store(key, content)
	assert.NoError(t, err)

	info, err := rd.Stat(key)
	assert.NoError(t, err)

	assert.Equal(t, key, info.Key)
}

func TestRedisStorage_List(t *testing.T) {
	rd := setupRedisEnv(t)

	err := rd.Store(path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"), []byte("crt"))
	assert.NoError(t, err)
	err = rd.Store(path.Join("acme", "example.com", "sites", "example.com", "example.com.key"), []byte("key"))
	assert.NoError(t, err)
	err = rd.Store(path.Join("acme", "example.com", "sites", "example.com", "example.com.json"), []byte("meta"))
	assert.NoError(t, err)

	keys, err := rd.List(path.Join("acme", "example.com", "sites", "example.com"), true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"))

	keys, err = rd.List("*", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"))

	keys, err = rd.List("", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"))

	keys, err = rd.List("   ", true)
	assert.NoError(t, err)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"))
}

func TestRedisStorage_ListNonRecursive(t *testing.T) {
	rd := setupRedisEnv(t)

	err := rd.Store(path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"), []byte("crt"))
	assert.NoError(t, err)
	err = rd.Store(path.Join("acme", "example.com", "sites", "example.com", "example.com.key"), []byte("key"))
	assert.NoError(t, err)
	err = rd.Store(path.Join("acme", "example.com", "sites", "example.com", "example.com.json"), []byte("meta"))
	assert.NoError(t, err)

	keys, err := rd.List(path.Join("acme", "example.com", "sites"), false)
	assert.NoError(t, err)

	assert.Len(t, keys, 1)
	assert.Contains(t, keys, path.Join("acme", "example.com", "sites", "example.com"))

	keys, err = rd.List("*", false)
	assert.NoError(t, err)

	assert.Len(t, keys, 3)
	assert.Contains(t, keys, path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"))

	keys, err = rd.List("", false)
	assert.NoError(t, err)

	assert.Len(t, keys, 3)
	assert.Contains(t, keys, path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"))

	keys, err = rd.List("   ", false)
	assert.NoError(t, err)

	assert.Len(t, keys, 3)
	assert.Contains(t, keys, path.Join("acme", "example.com", "sites", "example.com", "example.com.crt"))
}

func TestRedisStorage_LockUnlock(t *testing.T) {
	rd := setupRedisEnv(t)
	lockKey := path.Join("acme", "example.com", "sites", "example.com", "lock")

	err := rd.Lock(context.TODO(), lockKey)
	assert.NoError(t, err)

	err = rd.Unlock(lockKey)
	assert.NoError(t, err)
}

func lockAndUnlock(wg *sync.WaitGroup, t *testing.T, rd *RedisStorage, lockKey string) {
	defer wg.Done()

	err := rd.Lock(context.TODO(), lockKey)
	assert.NoError(t, err)
	err = rd.Unlock(lockKey)
	assert.NoError(t, err)
}

func TestRedisStorage_MultipleLocks(t *testing.T) {
	lockKey := path.Join("acme", "example.com", "sites", "example.com", "lock")

	var wg sync.WaitGroup
	rds := make([]*RedisStorage, 100)

	for i := 0; i < 100; i++ {
		rd := setupRedisEnv(t)
		wg.Add(1)
		rds[i] = rd
	}
	for i := 0; i < len(rds); i++ {
		go lockAndUnlock(&wg, t, rds[i], lockKey)
	}

	wg.Wait()
}

func TestRedisStorage_String(t *testing.T) {
	rd := new(RedisStorage)
	t.Run("validate password", func(t *testing.T) {
		t.Run("is redacted when set", func(t *testing.T) {
			testrd := new(RedisStorage)
			password := "iAmASuperSecurePassword"
			rd.Password = password
			err := json.Unmarshal([]byte(rd.String()), &testrd)
			assert.NoError(t, err)
			assert.Equal(t, "REDACTED", testrd.Password)
			assert.Equal(t, password, rd.Password)
		})
		rd.Password = ""
		t.Run("is empty if not set", func(t *testing.T) {
			err := json.Unmarshal([]byte(rd.String()), &rd)
			assert.NoError(t, err)
			assert.Empty(t, rd.Password)
		})
	})
}
