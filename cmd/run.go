package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/meow-io/heya"
)

type Config struct {
	APNSCertPath          string `json:"apns_cert_path"`
	APNSTopic             string `json:"apns_topic"`
	TLSCertPath           string `json:"tls_cert_path"`
	TLSKeyPath            string `json:"tls_key_path"`
	APNSProductionMode    bool   `json:"apns_mode"`
	DatabaseURL           string `json:"database_url"`
	RedisURL              string `json:"redis_url"`
	Port                  int    `json:"port"`
	Debug                 bool   `json:"debug"`
	LogPath               string `json:"log_path"`
	OverrideIncomingToken string `json:"override_incoming_token"`
}

func main() {
	configPath := flag.String("config", "/etc/heya/config.json", "Config path for heya")
	flag.Parse()
	file, err := os.Open(*configPath)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("error while closing file %#v", err)
		}
	}()
	decoder := json.NewDecoder(file)
	config := Config{}
	if err := decoder.Decode(&config); err != nil {
		panic(err)
	}

	overrideToken, err := hex.DecodeString(config.OverrideIncomingToken)
	if err != nil {
		panic(err)
	}

	conf := &heya.Config{
		APNSCertPath:          config.APNSCertPath,
		APNSTopic:             config.APNSTopic,
		APNSProductionMode:    config.APNSProductionMode,
		TLSCertPath:           config.TLSCertPath,
		TLSKeyPath:            config.TLSKeyPath,
		DatabaseURL:           config.DatabaseURL,
		RedisURL:              config.RedisURL,
		Port:                  config.Port,
		Debug:                 config.Debug,
		LogPath:               config.LogPath,
		OverrideIncomingToken: overrideToken,
	}
	server, err := heya.NewServer(conf)
	if err != nil {
		panic(err)
	}
	if err := server.Start(); err != nil {
		panic(err)
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Printf("got %s", sig)
		server.Stop()
		close(sigs)
	}()

	server.Wait()
}
