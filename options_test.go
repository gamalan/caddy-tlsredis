package storageredis

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRedisStorage_GetOption(t *testing.T) {
	opt := GetOptions()
	assert.Equal(t, opt.KeyPrefix, DefaultKeyPrefix)
	assert.Equal(t, opt.ValuePrefix, DefaultValuePrefix)
	assert.Equal(t, opt.AESKey, DefaultAESKey)
	assert.Equal(t, opt.Host, DefaultRedisHost)
	assert.Equal(t, opt.Port, DefaultRedisPort)
	assert.Equal(t, opt.DB, DefaultRedisDB)
}
