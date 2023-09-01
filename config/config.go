// SPDX-License-Identifier: MIT

package config

import (
	"fmt"
	yaml "gopkg.in/yaml.v2"
	"io"
	"os"
)

// Config represents configuration for the exporter.
type Config struct {
	Targets []TargetConfig `yaml:"targets"`

	Ping struct {
		Interval duration `yaml:"interval"`
		Timeout  duration `yaml:"timeout"`
		History  int      `yaml:"history-size"`
		Size     uint16   `yaml:"payload-size"`
	} `yaml:"ping"`

	DNS struct {
		Refresh    duration `yaml:"refresh"`
		Nameserver string   `yaml:"nameserver"`
	} `yaml:"dns"`

	Options struct {
		DisableIPv6 bool `yaml:"disableIPv6"` // prohibits DNS resolved IPv6 addresses
		DisableIPv4 bool `yaml:"disableIPv4"` // prohibits DNS resolved IPv4 addresses
	} `yaml:"options"`
}

// FromYAML reads YAML from reader and unmarshals it to Config.
func fromYAML(r io.Reader) (*Config, error) {
	c := &Config{}
	err := yaml.NewDecoder(r).Decode(c)
	if err != nil {
		return nil, fmt.Errorf("failed to decode YAML: %w", err)
	}

	return c, nil
}

func (cfg *Config) TargetConfigByAddr(addr string) TargetConfig {
	for _, t := range cfg.Targets {
		if t.Addr == addr {
			return t
		}
	}

	return TargetConfig{Addr: addr}
}

func LoadConfig(configFile string) (*Config, error) {
	if configFile == "" {
		return nil, fmt.Errorf("config file not specified")
	}

	f, err := os.Open(configFile)
	if err != nil {
		return nil, fmt.Errorf("cannot load config file: %w", err)
	}
	defer f.Close()

	cfg, err := fromYAML(f)
	return cfg, err
}
