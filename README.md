# Caddy Cluster / Certmagic TLS cluster support for Redis

This plugin is based on [similar plugin using Consul](https://github.com/pteich/caddy-tlsconsul/).
Most of the aspect is also similar, I pretty much copy the crypto implementation.
The reason I use [Redis](https://redis.io/) is because it easier to setup.

For now, this will support redis as single instance, or with replica, but NOT the cluster.
This plugin utilize [go-redis/redis](https://github.com/go-redis/redis) for its client access and [redislock](https://github.com/bsm/redislock)
for it's locking mechanism. See [distlock](https://redis.io/topics/distlock) for the lock algorithm.

This plugin currently work with versions of Caddy that use https://github.com/mholt/certmagic
and its new storage interface (> 0.11.1)

## Configuration
You enable Consul storage with Caddy by setting the `CADDY_CLUSTERING` environment variable to `redis`.

There are additional environment variable for this plugin:
- `CADDY_CLUSTERING_REDIS_HOST` defines Redis Host, default is `127.0.0.1`
- `CADDY_CLUSTERING_REDIS_PORT` defines Redis Port, default is 6379
- `CADDY_CLUSTERING_REDIS_PASSWORD` defines Redis Password, default is empty
- `CADDY_CLUSTERING_REDIS_DB` defines Redis DB, default is 0
- `CADDY_CLUSTERING_REDIS_TIMEOUT` defines Redis Dial,Read,Write timeout, default is set to 5 for 5 seconds
- `CADDY_CLUSTERING_REDIS_AESKEY` defines your personal AES key to use when encrypting data. It needs to be 32 characters long.
- `CADDY_CLUSTERING_REDIS_KEYPREFIX` defines the prefix for the keys. Default is `caddytls`
- `CADDY_CLUSTERING_REDIS_VALUEPREFIX` defines the prefix for the values. Default is `caddy-storage-redis`

## TODO

- Add Redis Cluster or Sentinel support (probably need to update the distlock implementation first)





