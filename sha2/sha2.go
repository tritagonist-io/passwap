// Package sha2 provides hashing and verification of
// SHA-256 and SHA-512 encoded passwords with salt based on crypt(3).
// [The algorithm](https://passlib.readthedocs.io/en/stable/lib/passlib.hash.sha256_crypt.html#format-algorithm)
// builds hashes through multiple digest iterations
// with shuffles of password and salt.
package sha2

import (
	"bytes"
	"hash"
)

const (
	Sha256Identifier = "$5$"
	Sha512Identifier = "$6$"
	SaltLenMin       = 1
	SaltLenMax       = 16
	RoundsMin        = 1000
	RoundsMax        = 999999999
	RoundsDefault    = 5000
)

// Follows the algorithm stepts outlined in https://www.akkadia.org/drepper/SHA-crypt.txt
func sha2Crypt(hash hash.Hash, password, salt []byte, rounds int) []byte {
	// steps 4 - 6 (we start with digest B because it is more convenient)
	hash.Write(password)
	hash.Write(salt)
	hash.Write(password)
	digestB := hash.Sum(nil)

	// steps 1 - 3
	hash.Reset()
	hash.Write(password)
	hash.Write(salt)

	// step 9 - 10
	passwordLength := len(password)
	hash.Write(repeatBytesToSize(digestB, passwordLength))

	// step 11
	for i := passwordLength; i != 0; i >>= 1 {
		if i&1 == 1 {
			hash.Write(digestB)
		} else {
			hash.Write(password)
		}
	}

	// step 12
	digestA := hash.Sum(nil)
}

func repeatBytesToSize(input []byte, size int) []byte {
	repeats := 1 + (size-1)/len(input)
	return bytes.Repeat(input, repeats)[:size]
}
