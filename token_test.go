package token_test

import (
	"errors"
	"testing"
	"time"
	"token"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

var key = "YELLOW SUBMARINE, BLACK WIZARDRY" // Must be 32 bytes

type Payload struct {
	ID        uuid.UUID
	Username  string
	IssuedAt  time.Time
	ExpiredAt time.Time
}

func (p *Payload) Valid() error {
	if time.Now().After(p.ExpiredAt) {
		return errors.New("expired")
	}
	return nil
}

func TestJwtToken(t *testing.T) {
	make := token.NewJwtToken(key)
	id, _ := uuid.NewRandom()
	paylod := Payload{
		ID:        id,
		Username:  "test",
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().Add(time.Second * 2),
	}
	newToken, err := make.CreateToken(&paylod)
	require.NoError(t, err)

	dataPayload := Payload{}
	err = make.VerifyToken(newToken, &dataPayload)
	require.NoError(t, err)

	require.Equal(t, &paylod.ID, &dataPayload.ID)
	require.Equal(t, &paylod.Username, &dataPayload.Username)
}

func TestPasetoToken(t *testing.T) {
	make := token.NewPasetoMaker(key)
	id, _ := uuid.NewRandom()
	paylod := Payload{
		ID:        id,
		Username:  "test",
		IssuedAt:  time.Now(),
		ExpiredAt: time.Now().AddDate(0, 0, 1),
	}
	newToken, err := make.CreateToken(&paylod)
	require.NoError(t, err)

	dataPayload := Payload{}
	err = make.VerifyToken(newToken, &dataPayload)
	require.NoError(t, err)

	require.Equal(t, &paylod.ID, &dataPayload.ID)
	require.Equal(t, &paylod.Username, &dataPayload.Username)
}
