package rcon

import "errors"

var (
	ChallengeRequiredError = errors.New("Challenge required for this server.")
	InvalidPasswordError = errors.New("RCON password provided is invalid.")
	InvalidChallengeResponseError = errors.New("Server sent an invalid response for challenge request.")
)