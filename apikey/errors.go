package apikey

import "errors"

// ErrTokenNotFound indicates that a token ID is not present in storage.
var ErrTokenNotFound = errors.New("apikey: token not found")
