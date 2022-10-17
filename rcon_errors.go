package rcon

import "errors"

var (
	ErrChallengeRequired        = errors.New("challenge required for this server")
	ErrInvalidPassword          = errors.New("RCON password provided is invalid")
	ErrInvalidChallengeResponse = errors.New("server sent an invalid response for challenge request")
)
