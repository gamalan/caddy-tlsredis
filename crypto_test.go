package storageredis

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRedisStorage_EncryptDecryptStorageData(t *testing.T) {
	testDate := time.Now()
	rd := new(RedisStorage)
	rd.GetConfigValue()

	sd := &StorageData{
		Value:    []byte("crt data"),
		Modified: testDate,
	}

	encryptedData, err := rd.EncryptStorageData(sd)
	assert.NoError(t, err)

	decryptedData, err := rd.DecryptStorageData(encryptedData)
	assert.NoError(t, err)

	assert.Equal(t, sd.Value, decryptedData.Value)
	assert.Equal(t, sd.Modified.Format(time.RFC822), decryptedData.Modified.Format(time.RFC822))
}
