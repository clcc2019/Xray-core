// Package crypto provides common crypto libraries for Xray.
package crypto // import "github.com/xtls/xray-core/common/crypto"

import (
	"math/rand/v2"
)

// RandBetween returns a random int64 in range [from, to].
// Uses math/rand/v2 for better performance.
// Note: This is NOT cryptographically secure, suitable for non-security-critical use cases
// like spider timing, padding lengths, etc.
func RandBetween(from int64, to int64) int64 {
	if from == to {
		return from
	}
	if from > to {
		from, to = to, from
	}
	return from + rand.Int64N(to-from+1)
}
