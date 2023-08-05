package ca

import "crypto/ecdsa"

func arePublicKeysEqual(key1, key2 *ecdsa.PublicKey) bool {
	if key1 == key2 {
		return true
	}
	if key1 == nil || key2 == nil {
		return false
	}
	return key1.Curve == key2.Curve &&
		key1.X.Cmp(key2.X) == 0 &&
		key1.Y.Cmp(key2.Y) == 0
}
