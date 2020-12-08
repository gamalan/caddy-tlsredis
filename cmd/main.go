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
	importCmd.Usage = func() {
		fmt.Println("Usage: import CADDY_PATH")
	}
	exportCmd := flag.NewFlagSet("export", flag.ExitOnError)
	exportCmd.Usage = func() {
		fmt.Println("Usage: export DEST_PATH")
	}

	var cmd string = ""
	if len(os.Args) >= 2 {
		cmd = os.Args[1]
	}

	switch cmd {
	case "import":
		importCmd.Parse(os.Args[2:])
		if importCmd.NArg() == 0 {
			importCmd.Usage()
			os.Exit(1)
		}
		importFiles(rd, importCmd.Arg(0))
	case "export":
		exportCmd.Parse(os.Args[2:])
		if exportCmd.NArg() == 0 {
			exportCmd.Usage()
			os.Exit(1)
		}
		exportFiles(rd, exportCmd.Arg(0))
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
