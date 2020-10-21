# Caddy Cluster / Certmagic TLS cluster support for Redis

This plugin is based on [similar plugin using Consul](https://github.com/pteich/caddy-tlsconsul/).
Most of the aspect is also similar, I pretty much copy the crypto implementation.
The reason I use [Redis](https://redis.io/) is because it easier to setup.

For now, this will support redis as single instance, or with replica, but NOT the cluster.
This plugin utilize [go-redis/redis](https://github.com/go-redis/redis) for its client access and [redislock](https://github.com/bsm/redislock)
for it's locking mechanism. See [distlock](https://redis.io/topics/distlock) for the lock algorithm.

This plugin currently work with versions of Caddy v2, for the previous version of Caddy use [caddy-v1](https://github.com/gamalan/caddy-tlsredis/tree/caddy-v1) branch.

## Configuration
You enable Redis storage with Caddy by setting the storage module used, for example
```
{
	//all value is optional, here is the default
	storage redis {
	  host          "127.0.0.1"
	  port          6379
	  address       "127.0.0.1:6379" // no default, but is build from host+":"+port, if set, then host and port is ignored
	  password      ""
	  db            1
	  key_prefix    "caddytls"
	  value_prefix  "caddy-storage-redis"
	  timeout       5
	  tls_enabled   "false"
	  tls_insecure  "true"
	  aes_key       "redistls-01234567890-caddytls-32" // optional, but must have 32 length
	}
	// because the option are set using env, there are no need for additional option value
}

:443 {

}
```

JSON example
```
{
	"admin": {
		"listen": "0.0.0.0:2019"
	},
	"storage": {
		"address": "redis:6379",
		"aes_key": "redistls-01234567890-caddytls-32",
		"db": 1,
		"host": "redis",
		"key_prefix": "caddytls",
		"module": "redis",
		"password": "",
		"port": "6379",
		"timeout": 5,
		"tls_enabled": false,
		"tls_insecure": true,
		"value_prefix": "caddy-storage-redis"
	}
}
```
There are additional environment variable for this plugin:
- `CADDY_CLUSTERING_REDIS_HOST` defines Redis Host, default is `127.0.0.1`
- `CADDY_CLUSTERING_REDIS_PORT` defines Redis Port, default is 6379
- `CADDY_CLUSTERING_REDIS_PASSWORD` defines Redis Password, default is empty
- `CADDY_CLUSTERING_REDIS_DB` defines Redis DB, default is 0
- `CADDY_CLUSTERING_REDIS_TIMEOUT` defines Redis Dial,Read,Write timeout, default is set to 5 for 5 seconds
- `CADDY_CLUSTERING_REDIS_AESKEY` defines your personal AES key to use when encrypting data. It needs to be 32 characters long.
- `CADDY_CLUSTERING_REDIS_KEYPREFIX` defines the prefix for the keys. Default is `caddytls`
- `CADDY_CLUSTERING_REDIS_VALUEPREFIX` defines the prefix for the values. Default is `caddy-storage-redis`
- `CADDY_CLUSTERING_REDIS_TLS` defines whether use Redis TLS Connection or not
- `CADDY_CLUSTERING_REDIS_TLS_INSECURE` defines whether verify Redis TLS Connection or not

## TODO

- Add Redis Cluster or Sentinel support (probably need to update the distlock implementation first)





