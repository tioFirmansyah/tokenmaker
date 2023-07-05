package token

import (
	"github.com/aead/chacha20poly1305"
	"github.com/o1egl/paseto"
)

// len key Must be 32 bytes
func NewPasetoMaker(key string) Token {
	if len(key) != chacha20poly1305.KeySize {
		return nil
	}

	return &MakerTokenPaseto{
		maker: paseto.NewV2(),
		key:   []byte(key), // Must be 32 bytes
	}
}

type MakerTokenPaseto struct {
	maker *paseto.V2
	key   []byte
}

// CreateToken implements Token
// Payload must be implement Valid() error
func (m *MakerTokenPaseto) CreateToken(payload TokenPayload) (string, error) {
	return m.maker.Encrypt(m.key, payload, nil)
}

// VerifyToken implements Token
// Payload must be implement Valid() error
func (m *MakerTokenPaseto) VerifyToken(token string, payload TokenPayload) error {
	err := m.maker.Decrypt(token, m.key, &payload, nil)
	if err != nil {
		return err
	}

	err = payload.Valid()
	if err != nil {
		return err
	}

	return nil
}
