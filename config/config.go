package config

import (
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"
)

type RuntimeConfig struct {
	StorageType   string            `yaml:"storage_type"`
	StorageConfig map[string]string `yaml:"storage_config"`
}

func NewConfig() *RuntimeConfig {
	return &RuntimeConfig{}
}

func (c *RuntimeConfig) Load(homeDir string) error {
	var home string
	if homeDir == "" {
		userHome, err := homedir.Dir()
		if err != nil {
			return err
		}
		home = filepath.Join(userHome, "config/config.yml")
	} else {
		home = homeDir
	}

	bz, err := os.ReadFile(home)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(bz, c)
	if err != nil {
		return err
	}
	return nil
}
