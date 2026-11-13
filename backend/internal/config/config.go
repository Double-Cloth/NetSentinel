// Package config 从环境读取基础运行配置。
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type Config struct {
	Address      string
	DataDir      string
	DatabasePath string
}

func Load() (Config, error) {
	address := os.Getenv("NETSENTINEL_ADDR")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return Config{}, fmt.Errorf("NETSENTINEL_ADDR 无效: %w", err)
	}
	dataDir := os.Getenv("NETSENTINEL_DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	absolute, err := filepath.Abs(dataDir)
	if err != nil {
		return Config{}, err
	}
	return Config{Address: address, DataDir: absolute, DatabasePath: filepath.Join(absolute, "netsentinel.db")}, nil
}
