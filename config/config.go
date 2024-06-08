package config

import (
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v2"
)

type Env struct {
	Communication string            `yaml:"communication"`
	StorageType   string            `yaml:"storage_type"`
	StorageConfig map[string]string `yaml:"storage_config"`
	EscrowServer  string            `yaml:"escrow_server"`
}

func NewConfig() *Env {
	return &Env{}
}

func (e *Env) Load(homeDir string) error {
	var home string
	if homeDir == "" {
		userHome, err := homedir.Dir()
		if err != nil {
			return err
		}
		home = filepath.Join(userHome, "config.yml")
	} else {
		home = homeDir
	}

	bz, err := os.ReadFile(home)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(bz, e)
	if err != nil {
		return err
	}
	return nil
}
