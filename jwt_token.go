package token

import (
	"errors"

	"github.com/golang-jwt/jwt"
)

// len key Must be 32 bytes
func NewJwtToken(key string) Token {
	return &MakerJwtToken{
		secretKey: key,
	}
}

type MakerJwtToken struct {
	secretKey string
}

// CreateToken implements Token
// Payload must be implement Valid() error
func (j *MakerJwtToken) CreateToken(payload TokenPayload) (string, error) {
	JwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	return JwtToken.SignedString([]byte(j.secretKey))
}

// VerifyToken implements Token
// Payload must be implement Valid() error
func (j *MakerJwtToken) VerifyToken(token string, payload TokenPayload) error {
	keyFunc := func(jwtToken *jwt.Token) (interface{}, error) {
		_, ok := jwtToken.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, errors.New("invalid token")
		}
		return []byte(j.secretKey), nil
	}

	_, err := jwt.ParseWithClaims(token, payload, keyFunc)
	if err != nil {
		verr, ok := err.(*jwt.ValidationError)
		if ok && errors.Is(verr.Inner, errors.New("expired")) {
			return errors.New("expired")
		}
		return err
	}
	return nil
}
