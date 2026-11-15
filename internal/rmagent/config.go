package rmagent

import (
	"encoding/json"
	"os"
)

type Config struct {
	ServerURL   string `json:"server_url"`
	AgentID     string `json:"agent_id"`
	AgentToken  string `json:"agent_token"`
	ConfigPath  string `json:"-"`
	EnrollToken string `json:"-"`
	Version     string `json:"-"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}
