package token

type TokenPayload interface {
	Valid() error
}

type Token interface {
	CreateToken(payload TokenPayload) (string, error)
	VerifyToken(token string, payload TokenPayload) error
}
