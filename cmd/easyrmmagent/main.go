package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/paulmataruso/easyrm/internal/rmagent"
)

var version = "dev"

func main() {
	fs := flag.NewFlagSet("easyrmmagent", flag.ExitOnError)
	serverURL := fs.String("server", "", "EasyRMM server URL (e.g. https://rmm.example.com)")
	agentID := fs.String("agent-id", "", "Agent ID (assigned during enrollment)")
	agentToken := fs.String("token", "", "Agent token for authentication")
	configPath := fs.String("config", "", "Path to agent config file")
	enrollToken := fs.String("enroll", "", "Enrollment token (for first-time setup)")
	showVersion := fs.Bool("version", false, "Print version and exit")
	fs.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("easyrmmagent %s\n", version)
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := &rmagent.Config{
		ServerURL:   *serverURL,
		AgentID:     *agentID,
		AgentToken:  *agentToken,
		ConfigPath:  *configPath,
		EnrollToken: *enrollToken,
		Version:     version,
	}

	if *configPath != "" {
		loaded, err := rmagent.LoadConfig(*configPath)
		if err != nil && *enrollToken == "" {
			logger.Error("failed to load config", "error", err)
			os.Exit(1)
		}
		if loaded != nil {
			if cfg.ServerURL == "" {
				cfg.ServerURL = loaded.ServerURL
			}
			if cfg.AgentID == "" {
				cfg.AgentID = loaded.AgentID
			}
			if cfg.AgentToken == "" {
				cfg.AgentToken = loaded.AgentToken
			}
		}
	}

	if cfg.ServerURL == "" {
		fmt.Fprintln(os.Stderr, "Error: --server is required")
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	agent, err := rmagent.New(cfg, logger)
	if err != nil {
		logger.Error("failed to create agent", "error", err)
		os.Exit(1)
	}

	go func() {
		<-stop
		logger.Info("shutdown signal received")
		cancel()
	}()

	if err := agent.Run(ctx); err != nil && ctx.Err() == nil {
		logger.Error("agent error", "error", err)
		os.Exit(1)
	}
}
