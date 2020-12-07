package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	storageredis "github.com/gamalan/caddy-tlsredis"

	"go.uber.org/zap"
)

func migrateFile(rd *storageredis.RedisStorage, caddyFolder string, path string) {
	rd.Logger.Infof("Migrating %s...", path)
	binary, err := ioutil.ReadFile(caddyFolder + path)
	if err != nil {
		panic(err)
	}
	rd.Store(path, binary)
}

func main() {
	logger, _ := zap.NewProduction()
	rd := storageredis.RedisStorage{
		Logger: logger.Sugar(),
	}
	rd.GetConfigValue()
	rd.BuildRedisClient()

	caddyFolder := os.Getenv("CADDY_FOLDER")
	if caddyFolder == "" {
		panic("CADDY_FOLDER not defined")
	}

	err := filepath.Walk(caddyFolder, func(path string, f os.FileInfo, err error) error {
		if err != nil {
			panic(err)
		}
		if !f.IsDir() {
			migrateFile(&rd, caddyFolder, strings.TrimPrefix(path, caddyFolder))
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
}
