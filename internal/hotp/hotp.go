package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"math/big"
)

func calculateHMACSHA1(secret string, count int64) (string, error) {
	secretBytes, err := hex.DecodeString(secret)
	if err != nil {
		return "", err
	}
	h := hmac.New(sha1.New, secretBytes)
	h.Write(big.NewInt(count).Bytes())

	return hex.EncodeToString(h.Sum(nil)), nil
}
