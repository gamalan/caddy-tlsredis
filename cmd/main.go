package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	storageredis "github.com/gamalan/caddy-tlsredis"

	"go.uber.org/zap"
)

func main() {
	rd := initRedis()

	importCmd := flag.NewFlagSet("import", flag.ExitOnError)
	exportCmd := flag.NewFlagSet("export", flag.ExitOnError)
	source := importCmd.String("source", "", "path to the Caddy Data folder (Required)")
	dest := exportCmd.String("dest", ".", "path to write the exported files")

	var cmd string = ""
	if len(os.Args) >= 2 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "import":
		importCmd.Parse(os.Args[2:])
		if *source == "" {
			rd.Logger.Fatal("source path not specified")
		}
		importFiles(rd, *source)
	case "export":
		exportCmd.Parse(os.Args[2:])
		exportFiles(rd, *dest)
	default:
		fmt.Println("expected 'import' or 'export' subcommands")
		os.Exit(1)
	}
}

func initRedis() *storageredis.RedisStorage {
	config := zap.NewDevelopmentConfig()
	config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	logger, _ := config.Build()

	rd := storageredis.RedisStorage{
		Logger: logger.Sugar(),
	}
	rd.GetConfigValue()
	err := rd.BuildRedisClient()
	if err != nil {
		rd.Logger.Fatal(err)
	}
	return &rd
}

func importFiles(rd *storageredis.RedisStorage, caddyFolder string) error {
	err := filepath.Walk(caddyFolder, func(fullpath string, f os.FileInfo, err error) error {
		if err != nil {
			rd.Logger.Fatal(err)
		}
		if !f.IsDir() {
			path := strings.TrimPrefix(fullpath, caddyFolder)
			rd.Logger.Infof("Importing %s...", path)
			binary, err := ioutil.ReadFile(fullpath)
			if err != nil {
				rd.Logger.Fatal(err)
			}
			rd.Store(path, binary)
		}
		return nil
	})
	return err
}

func exportFiles(rd *storageredis.RedisStorage, dest string) {
	keys, err := rd.List("*", true)
	if err != nil {
		rd.Logger.Fatal(err)
	}
	for _, key := range keys {
		rd.Logger.Infof("Exporting %s...", key)
		val, err := rd.Load(key)
		if err != nil {
			rd.Logger.Fatal(err)
		}
		path := filepath.Join(dest, key)
		err = os.MkdirAll(filepath.Dir(path), 0700)
		if err != nil {
			rd.Logger.Fatal(err)
		}
		ioutil.WriteFile(path, val, 0600)
	}
}
