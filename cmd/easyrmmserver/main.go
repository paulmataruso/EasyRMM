package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/paulmataruso/easyrm/internal/config"
	"github.com/paulmataruso/easyrm/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("connecting to database",
		"host", cfg.Database.Host,
		"port", cfg.Database.Port,
		"name", cfg.Database.Name,
	)
	pool, err := server.NewDatabasePool(context.Background(), cfg.Database)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	logger.Info("running database migrations")
	if err := server.RunMigrations(context.Background(), pool, "migrations"); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	srv := server.New(cfg, pool, logger)
	if err := srv.Start(); err != nil {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}
}
