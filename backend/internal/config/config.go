// Package config 从环境读取基础运行配置。
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
)

type Config struct {
	Address       string
	DataDir       string
	DatabasePath  string
	PublicOrigin  string
	SourceCatalog string
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
	origin := os.Getenv("NETSENTINEL_PUBLIC_ORIGIN")
	if origin != "" {
		value, err := url.Parse(origin)
		if err != nil || value.Hostname() == "" || (value.Scheme != "http" && value.Scheme != "https") ||
			value.User != nil || origin != value.Scheme+"://"+value.Host {
			return Config{}, fmt.Errorf("NETSENTINEL_PUBLIC_ORIGIN 须为含协议和主机的 Origin")
		}
	}
	return Config{Address: address, DataDir: absolute, DatabasePath: filepath.Join(absolute, "netsentinel.db"), PublicOrigin: origin, SourceCatalog: os.Getenv("NETSENTINEL_SOURCE_CATALOG")}, nil
}
