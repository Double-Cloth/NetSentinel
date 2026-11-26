package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Double-Cloth/NetSentinel/backend/internal/api"
	"github.com/Double-Cloth/NetSentinel/backend/internal/auth"
	"github.com/Double-Cloth/NetSentinel/backend/internal/config"
	"github.com/Double-Cloth/NetSentinel/backend/internal/repository"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("服务退出", "error", err.Error())
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	migrate := flag.Bool("migrate", false, "应用数据库迁移后退出")
	healthcheck := flag.Bool("healthcheck", false, "检查本地服务就绪状态后退出")
	initAdmin := flag.String("init-admin", "", "首次初始化指定管理员账号，从标准输入读取一行密码")
	flag.Parse()
	if (*migrate && *healthcheck) || (*initAdmin != "" && (*migrate || *healthcheck)) {
		return fmt.Errorf("migrate、healthcheck 与 init-admin 须单独使用")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if *healthcheck {
		return checkHealth(cfg.Address)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	startup, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	store, err := repository.Open(startup, cfg.DatabasePath)
	if err != nil {
		return err
	}
	defer store.Close()
	if *migrate {
		if err := store.Migrate(startup); err != nil {
			return err
		}
		logger.Info("数据库迁移完成")
		return nil
	}
	if err := store.Ready(startup); err != nil {
		return fmt.Errorf("请先执行 server -migrate: %w", err)
	}
	if *initAdmin != "" {
		input := bufio.NewScanner(os.Stdin)
		input.Buffer(make([]byte, 256), 256)
		if !input.Scan() {
			return fmt.Errorf("请从标准输入提供一行有效密码")
		}
		if err := auth.BootstrapAdmin(startup, store.DB, *initAdmin, input.Text()); err != nil {
			return err
		}
		logger.Info("首个管理员已初始化")
		return nil
	}
	if err := repository.WritableDirectory(cfg.DataDir); err != nil {
		return err
	}
	identity, err := auth.NewService(store.DB)
	if err != nil {
		return err
	}
	handler := api.New(api.Dependencies{
		DatabaseReady: store.Ready, DirectoryReady: func() error { return repository.WritableDirectory(cfg.DataDir) },
		Logger: logger, Auth: identity, PublicOrigin: cfg.PublicOrigin,
	})
	server := &http.Server{Addr: cfg.Address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return err
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()
	logger.Info("服务已启动", "address", cfg.Address)
	select {
	case err := <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			server.Close()
			return err
		}
		return nil
	}
}

func checkHealth(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + net.JoinHostPort(host, port) + "/api/v1/health/ready")
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("服务未就绪")
	}
	return nil
}
