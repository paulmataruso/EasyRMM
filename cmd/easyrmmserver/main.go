package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/paulmataruso/easyrm/internal/auth"
	"github.com/paulmataruso/easyrm/internal/config"
	"github.com/paulmataruso/easyrm/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: easyrmmserver <command>")
		fmt.Fprintln(os.Stderr, "Commands: serve, migrate, create-admin")
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		logger.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := server.NewDatabasePool(ctx, cfg.Database)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	switch os.Args[1] {
	case "serve":
		logger.Info("running database migrations")
		if err := server.RunMigrations(ctx, pool, "migrations"); err != nil {
			logger.Error("failed to run migrations", "error", err)
			os.Exit(1)
		}
		srv := server.New(cfg, pool, logger)
		if err := srv.Start(); err != nil {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}

	case "migrate":
		logger.Info("running database migrations")
		if err := server.RunMigrations(ctx, pool, "migrations"); err != nil {
			logger.Error("failed to run migrations", "error", err)
			os.Exit(1)
		}
		logger.Info("migrations complete")

	case "create-admin":
		fs := flag.NewFlagSet("create-admin", flag.ExitOnError)
		email := fs.String("email", "admin@easyrm.local", "admin email")
		password := fs.String("password", "admin", "admin password")
		ifNone := fs.Bool("if-none-exists", false, "skip if any user exists")
		fs.Parse(os.Args[2:])

		store := auth.NewStore(pool, cfg.Auth)

		if *ifNone {
			existing, _ := store.GetUserByUsername(ctx, "admin")
			if existing != nil {
				fmt.Println("Admin user already exists, skipping.")
				return
			}
		}

		user, err := store.CreateUser(ctx, *email, "admin", *password, "Administrator", "super_admin")
		if err != nil {
			logger.Error("failed to create admin user", "error", err)
			os.Exit(1)
		}
		fmt.Printf("Created admin user: %s (ID: %s)\n", user.Username, user.ID)
		fmt.Println("** Change the password immediately after first login **")

	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		os.Exit(1)
	}
}
