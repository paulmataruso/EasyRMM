package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/paulmataruso/easyrm/internal/auth"
	"github.com/paulmataruso/easyrm/internal/config"
	"github.com/paulmataruso/easyrm/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := server.NewDatabasePool(ctx, cfg.Database)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := server.RunMigrations(ctx, pool, "migrations"); err != nil {
		logger.Error("failed to run migrations", "error", err)
		os.Exit(1)
	}

	store := auth.NewStore(pool, cfg.Auth)

	existing, _ := store.GetUserByUsername(ctx, "admin")
	if existing != nil {
		fmt.Println("Admin user already exists, skipping seed.")
		return
	}

	user, err := store.CreateUser(ctx, "admin@easyrm.local", "admin", "admin", "Administrator", "super_admin")
	if err != nil {
		logger.Error("failed to create admin user", "error", err)
		os.Exit(1)
	}

	fmt.Printf("Created initial admin user:\n")
	fmt.Printf("  Username: admin\n")
	fmt.Printf("  Password: admin\n")
	fmt.Printf("  Role:     super_admin\n")
	fmt.Printf("  ID:       %s\n", user.ID)
	fmt.Println("\n** IMPORTANT: Change the admin password immediately after first login **")
}
