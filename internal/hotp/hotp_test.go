package hotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestHMACSHA1Calculation(t *testing.T) {
	secret := "3132333435363738393031323334353637383930"
	testCases := []struct {
		desc         string
		count        uint64
		expectedHMAC string
	}{
		{"when count is 0", 0, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"},
		{"when count is 1", 1, "75a48a19d4cbe100644e8ac1397eea747a2d33ab"},
		{"when count is 2", 2, "0bacb7fa082fef30782211938bc1c5e70416ff44"},
		{"when count is 3", 3, "66c28227d03a2d5529262ff016a1e6ef76557ece"},
		{"when count is 4", 4, "a904c900a64b35909874b33e61c5938a8e15ed1c"},
		{"when count is 5", 5, "a37e783d7b7233c083d4f62926c7a25f238d0316"},
		{"when count is 6", 6, "bc9cd28561042c83f219324d3c607256c03272ae"},
		{"when count is 7", 7, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"},
		{"when count is 8", 8, "1b3c89f65e6c9e883012052823443f048b4332db"},
		{"when count is 9", 9, "1637409809a679dc698207310c8c7fc07290d9e5"},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			hmacStr, err := calculateHMACSHA1(secret, tC.count)
			assert.NoError(t, err, "expected err to be nil but was found to be non nil")
			assert.Equal(t, tC.expectedHMAC, hmacStr, "expected them to be the same")
		})
	}
}
