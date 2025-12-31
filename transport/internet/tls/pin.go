package tls

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

// HashSize is the size of SHA-256 hash output
const HashSize = sha256.Size

// CalculatePEMCertChainSHA256Hash calculates the SHA256 hash of a PEM certificate chain
// and returns it as a base64 encoded string.
func CalculatePEMCertChainSHA256Hash(certContent []byte) string {
	var certChain [][]byte
	for {
		block, remain := pem.Decode(certContent)
		if block == nil {
			break
		}
		certChain = append(certChain, block.Bytes)
		certContent = remain
	}
	certChainHash := GenerateCertChainHash(certChain)
	return base64.StdEncoding.EncodeToString(certChainHash)
}

// GenerateCertChainHash generates a chained SHA256 hash of the certificate chain.
// The algorithm chains hashes: H(H(cert1) || H(cert2) || ...)
// This is more efficient than the previous implementation as it:
// 1. Uses a single hasher instance for the final chain hash
// 2. Avoids intermediate slice allocations
func GenerateCertChainHash(rawCerts [][]byte) []byte {
	if len(rawCerts) == 0 {
		return nil
	}

	// For single cert, just return its hash
	if len(rawCerts) == 1 {
		hash := sha256.Sum256(rawCerts[0])
		return hash[:]
	}

	// For multiple certs, chain the hashes efficiently
	// Use a single hasher for the final chain computation
	chainHasher := sha256.New()

	for _, certValue := range rawCerts {
		certHash := sha256.Sum256(certValue)
		chainHasher.Write(certHash[:])
	}

	return chainHasher.Sum(nil)
}

// GenerateCertPublicKeyHash generates a SHA256 hash of the certificate's
// Subject Public Key Info (SPKI). This is the standard format for
// public key pinning as defined in RFC 7469.
func GenerateCertPublicKeyHash(cert *x509.Certificate) []byte {
	if cert == nil {
		return nil
	}
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hash[:]
}

// VerifyPinnedCertChain verifies if the certificate chain matches any of the pinned hashes.
// Uses constant-time comparison to prevent timing attacks.
func VerifyPinnedCertChain(rawCerts [][]byte, pinnedHashes [][]byte) bool {
	if len(pinnedHashes) == 0 {
		return true // No pinning configured
	}
	if len(rawCerts) == 0 {
		return false
	}

	certChainHash := GenerateCertChainHash(rawCerts)

	for _, pinnedHash := range pinnedHashes {
		if len(pinnedHash) == HashSize && hmac.Equal(certChainHash, pinnedHash) {
			return true
		}
	}
	return false
}

// VerifyPinnedPublicKey verifies if any certificate in the verified chains
// has a public key matching any of the pinned public key hashes.
// Uses constant-time comparison to prevent timing attacks.
func VerifyPinnedPublicKey(verifiedChains [][]*x509.Certificate, pinnedHashes [][]byte) bool {
	if len(pinnedHashes) == 0 {
		return true // No pinning configured
	}
	if len(verifiedChains) == 0 {
		return false
	}

	for _, chain := range verifiedChains {
		for _, cert := range chain {
			if cert == nil {
				continue
			}
			publicKeyHash := GenerateCertPublicKeyHash(cert)
			for _, pinnedHash := range pinnedHashes {
				if len(pinnedHash) == HashSize && hmac.Equal(publicKeyHash, pinnedHash) {
					return true
				}
			}
		}
	}
	return false
}

// ValidatePinnedHashFormat checks if a pinned hash has the correct format (SHA-256 = 32 bytes)
func ValidatePinnedHashFormat(hash []byte) bool {
	return len(hash) == HashSize
}

// ValidateAllPinnedHashes validates all pinned hashes have correct format
func ValidateAllPinnedHashes(hashes [][]byte) bool {
	for _, h := range hashes {
		if !ValidatePinnedHashFormat(h) {
			return false
		}
	}
	return true
}
