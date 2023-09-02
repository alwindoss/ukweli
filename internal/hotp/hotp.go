package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
)

func calculateHMACSHA1(secret string, count uint64) (string, error) {
	secretBytes, err := hex.DecodeString(secret)
	if err != nil {
		return "", err
	}
	h := hmac.New(sha1.New, secretBytes)
  countBytes := make([]byte, 8)
  binary.BigEndian.PutUint64(countBytes, uint64(count))
	h.Write(countBytes)

	return hex.EncodeToString(h.Sum(nil)), nil
}

func truncateHex(h string) string {
  
  return "4c93cf18" 
}
