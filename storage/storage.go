package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"strings"
	"time"

	"github.com/armon/go-metrics"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault"
	"github.com/valli0x/signature-escrow/storage/file"
)

func CreateBackend(ID, sType, pass string, config map[string]string, logger hclog.Logger) (logical.Storage, error) {
	// create physical backend
	phisStorage, err := CreatePhysical(sType, config, logger)
	if err != nil {
		return nil, err
	}
	// create physical view
	physicalView, err := CreatePhysicalView(phisStorage, clearPath(ID))
	if err != nil {
		return nil, err
	}
	// create cache
	cache, err := CreateCache(physicalView, logger, 0)
	if err != nil {
		return nil, err
	}
	// create aes-gcm storage
	key := sha256.Sum256([]byte(pass))
	aesbackend, err := CreateAESGCM(cache, key[:])
	if err != nil {
		return nil, err
	}

	return aesbackend, nil
}

func clearPath(path string) string {
	return strings.Trim(path, "/") + "/"
}

/*
	physical backend
*/

func CreatePhysical(sType string, config map[string]string, logger hclog.Logger) (physical.Backend, error) {
	return file.NewFileBackend(config, logger)
}

func CreateCache(backend physical.Backend, logger hclog.Logger, size int) (physical.Backend, error) {
	return physical.NewCache(
			backend,
			size,
			logger.Named("cache"),
			metrics.NewInmemSink(10*time.Second, time.Minute)),
		nil
}

func CreatePhysicalView(backend physical.Backend, prefix string) (physical.Backend, error) {
	return physical.NewView(backend, prefix), nil
}

/*
	logical backend
*/

func NewStorageView(storage logical.Storage, prefix string) logical.Storage {
	return logical.NewStorageView(storage, prefix)
}

func CreateAESGCM(backend physical.Backend, key []byte) (logical.Storage, error) {
	aesBackend, err := vault.NewAESGCMBarrier(backend, true)
	if err != nil {
		return nil, err
	}

	// check init aes-barrir
	alreadyInit, err := aesBackend.Initialized(context.Background())
	if err != nil {
		return nil, err
	}

	if !alreadyInit {
		// init aes-gcm barrier
		if err := aesBackend.Initialize(context.Background(), key, nil, rand.Reader); err != nil {
			return nil, err
		}
	}

	// unseal barrier
	if err := aesBackend.Unseal(context.Background(), key); err != nil {
		return nil, err
	}

	return aesBackend, nil
}
