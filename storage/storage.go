package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"strings"

	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/valli0x/signature-escrow/storage/file"
)

type Storage interface {
	Put(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

type FileStorage struct {
	backend physical.Backend
}

func NewFileStorage(config map[string]string, logger hclog.Logger) (*FileStorage, error) {
	fb, err := file.NewFileBackend(config, logger)
	if err != nil {
		return nil, err
	}
	return &FileStorage{backend: fb}, nil
}

func (f *FileStorage) Put(ctx context.Context, key string, value []byte) error {
	entry := &physical.Entry{Key: key, Value: value}
	return f.backend.Put(ctx, entry)
}

func (f *FileStorage) Get(ctx context.Context, key string) ([]byte, error) {
	entry, err := f.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	return entry.Value, nil
}

func (f *FileStorage) Delete(ctx context.Context, key string) error {
	return f.backend.Delete(ctx, key)
}

type EncryptedStorage struct {
	backend Storage
	gcm     cipher.AEAD
	nonceSz int
}

func NewEncryptedStorage(backend Storage, pass string) (*EncryptedStorage, error) {
	key := sha256.Sum256([]byte(pass))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &EncryptedStorage{
		backend: backend,
		gcm:     gcm,
		nonceSz: gcm.NonceSize(),
	}, nil
}

func (e *EncryptedStorage) Put(ctx context.Context, key string, value []byte) error {
	nonce := make([]byte, e.nonceSz)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ciphertext := e.gcm.Seal(nonce, nonce, value, nil)
	return e.backend.Put(ctx, key, ciphertext)
}

func (e *EncryptedStorage) Get(ctx context.Context, key string) ([]byte, error) {
	ciphertext, err := e.backend.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < e.nonceSz {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:e.nonceSz]
	data := ciphertext[e.nonceSz:]
	return e.gcm.Open(nil, nonce, data, nil)
}

func (e *EncryptedStorage) Delete(ctx context.Context, key string) error {
	return e.backend.Delete(ctx, key)
}

// clearPath оставлен для совместимости, если нужно использовать префиксы
func clearPath(path string) string {
	return strings.Trim(path, "/") + "/"
}
