package storageredis

import (
	"github.com/caddyserver/certmagic"
	"github.com/stretchr/testify/assert"
	"os"
	"path"
	"testing"
)

const TestPrefix = "redistlstest"

// these tests needs a running Redis server
func setupRedisEnv(t *testing.T) *RedisStorage {
	os.Setenv(EnvNameKeyPrefix, TestPrefix)
	os.Setenv(EnvNameRedisDB, "9")

	rd := new(RedisStorage)
	rd.getConfigValue()
	err := rd.buildRedisClient()

	// skip test if no redis storage
	if err != nil {
		t.Skip()
		return nil
	}

	assert.NoError(t, err)
	assert.Equal(t, TestPrefix, rd.KeyPrefix)
	assert.Equal(t, 9, rd.DB)

	_, err = rd.Client.FlushAll().Result()
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

	err := rd.Lock(lockKey)
	assert.NoError(t, err)

	err = rd.Unlock(lockKey)
	assert.NoError(t, err)
}

func TestRedisStorage_TwoLocks(t *testing.T) {
	rd := setupRedisEnv(t)
	rd2 := setupRedisEnv(t)
	lockKey := path.Join("acme", "example.com", "sites", "example.com", "lock")

	err := rd.Lock(lockKey)
	assert.NoError(t, err)

	// other instance shouldn't be able lock it
	err = rd2.Lock(lockKey)
	assert.Error(t, err)

	// let's unlock it first so other can lock it
	err = rd.Unlock(lockKey)
	assert.NoError(t, err)

	// we should be able to lock it
	err = rd2.Lock(lockKey)
	assert.NoError(t, err)

	// and unlock
	err = rd2.Unlock(lockKey)
	assert.NoError(t, err)
}
