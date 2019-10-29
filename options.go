package storageredis

import (
	"os"
	"strconv"
)

const (
	// Default Values

	// DefaultAESKey needs to be 32 bytes long
	DefaultAESKey = "redistls-01234567890-caddytls-32"

	// DefaultKeyPrefix defines the default prefix in KV store
	DefaultKeyPrefix = "caddytls"

	// DefaultValuePrefix sets a prefix to KV values to check validation
	DefaultValuePrefix = "caddy-storage-redis"

	// DefaultRedisHost define the Redis instance host
	DefaultRedisHost = "127.0.0.1"

	// DefaultRedisPort define the Redis instance port
	DefaultRedisPort = "6379"

	// DefaultRedisDB define the Redis DB number
	DefaultRedisDB = 0

	// DefaultRedisPassword define the Redis instance password, if any
	DefaultRedisPassword = ""

	// DefaultRedisTimeout define the Redis wait time in (s)
	DefaultRedisTimeout = 5

	// DefaultRedisTLS define the Redis TLS connection
	DefaultRedisTLS = false

	// Environment Name

	// EnvNameRedisHost defines the env variable name to override Redis host
	EnvNameRedisHost = "CADDY_CLUSTERING_REDIS_HOST"

	// EnvNameRedisPort defines the env variable name to override Redis port
	EnvNameRedisPort = "CADDY_CLUSTERING_REDIS_PORT"

	// EnvNameRedisDB defines the env variable name to override Redis db number
	EnvNameRedisDB = "CADDY_CLUSTERING_REDIS_DB"

	// EnvNameRedisPassword defines the env variable name to override Redis password
	EnvNameRedisPassword = "CADDY_CLUSTERING_REDIS_PASSWORD"

	// EnvNameRedisTimeout defines the env variable name to override Redis wait timeout for dial, read, write
	EnvNameRedisTimeout = "CADDY_CLUSTERING_REDIS_TIMEOUT"

	// EnvNameAESKey defines the env variable name to override AES key
	EnvNameAESKey = "CADDY_CLUSTERING_REDIS_AESKEY"

	// EnvNameKeyPrefix defines the env variable name to override KV key prefix
	EnvNameKeyPrefix = "CADDY_CLUSTERING_REDIS_KEYPREFIX"

	// EnvNameValuePrefix defines the env variable name to override KV value prefix
	EnvNameValuePrefix = "CADDY_CLUSTERING_REDIS_VALUEPREFIX"

	// EnvNameTLSEnabled defines the env variable name to whether enable Redis TLS Connection or not
	EnvNameTLSEnabled = "CADDY_CLUSTERING_REDIS_TLS"
)

// Options is option to set plugin configuration
type Options struct {
	Host        string
	Port        string
	DB          int
	Password    string
	Timeout     int
	KeyPrefix   string
	ValuePrefix string
	AESKey      string
	TLSEnabled  bool
}

// GetOptions generate options from env or default
func GetOptions() *Options {
	options := Options{}

	if host := os.Getenv(EnvNameRedisHost); host != "" {
		options.Host = host
	} else {
		options.Host = DefaultRedisHost
	}

	if port := os.Getenv(EnvNameRedisPort); port != "" {
		options.Port = port
	} else {
		options.Port = DefaultRedisPort
	}

	if db := os.Getenv(EnvNameRedisDB); db != "" {
		dbParse, err := strconv.Atoi(db)
		if err == nil {
			options.DB = dbParse
		} else {
			options.DB = DefaultRedisDB
		}
	} else {
		options.DB = DefaultRedisDB
	}

	if timeout := os.Getenv(EnvNameRedisTimeout); timeout != "" {
		timeoutParse, err := strconv.Atoi(timeout)
		if err == nil {
			options.Timeout = timeoutParse
		} else {
			options.Timeout = DefaultRedisTimeout
		}
	} else {
		options.Timeout = DefaultRedisTimeout
	}

	if password := os.Getenv(EnvNameRedisPassword); password != "" {
		options.Password = password
	} else {
		options.Password = DefaultRedisPassword
	}

	if tlsEnabled := os.Getenv(EnvNameTLSEnabled); tlsEnabled != "" {
		tlsEnabledParse, err := strconv.ParseBool(tlsEnabled)
		if err == nil {
			options.TLSEnabled = tlsEnabledParse
		} else {
			options.TLSEnabled = DefaultRedisTLS
		}
	} else {
		options.TLSEnabled = DefaultRedisTLS
	}

	if keyPrefix := os.Getenv(EnvNameKeyPrefix); keyPrefix != "" {
		options.KeyPrefix = keyPrefix
	} else {
		options.KeyPrefix = DefaultKeyPrefix
	}

	if valuePrefix := os.Getenv(EnvNameValuePrefix); valuePrefix != "" {
		options.ValuePrefix = valuePrefix
	} else {
		options.ValuePrefix = DefaultValuePrefix
	}

	if aesKey := os.Getenv(EnvNameAESKey); aesKey != "" {
		options.AESKey = aesKey
	} else {
		options.AESKey = DefaultAESKey
	}

	return &options
}

// GetAESKey get aes key as byte
func (op *Options) GetAESKeyByte() []byte {
	return []byte(op.AESKey)
}
