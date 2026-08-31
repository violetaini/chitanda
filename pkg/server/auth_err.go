package server

import "errors"

var (
	errInvalidSignature = errors.New("invalid signature")
	errReplayDetected   = errors.New("replay detected")
)
