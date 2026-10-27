package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// DPoPPrivateJWK is the P-256 private JWK persisted with the refresh_token.
type DPoPPrivateJWK map[string]string

type dpopKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicJWK  map[string]string
}

// NewDPoPPrivateJWK generates a persistable ES256 P-256 private JWK.
func NewDPoPPrivateJWK() (DPoPPrivateJWK, error) {
	kp, err := newDpopKeyPair()
	if err != nil {
		return nil, err
	}
	return DPoPPrivateJWK{
		"kty": "EC",
		"crv": "P-256",
		"x":   kp.PublicJWK["x"],
		"y":   kp.PublicJWK["y"],
		"d":   base64.RawURLEncoding.EncodeToString(padded(kp.PrivateKey.D, 32)),
	}, nil
}

func newDpopKeyPair() (*dpopKeyPair, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(padded(key.PublicKey.X, 32)),
		"y":   base64.RawURLEncoding.EncodeToString(padded(key.PublicKey.Y, 32)),
	}
	return &dpopKeyPair{PrivateKey: key, PublicJWK: jwk}, nil
}

func dpopKeyPairFromPrivateJWK(jwk DPoPPrivateJWK) (*dpopKeyPair, error) {
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		return nil, fmt.Errorf("invalid DPoP JWK curve")
	}
	decode := func(field string) ([]byte, error) {
		raw, err := base64.RawURLEncoding.DecodeString(jwk[field])
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("invalid DPoP JWK %s", field)
		}
		return raw, nil
	}
	xRaw, err := decode("x")
	if err != nil {
		return nil, err
	}
	yRaw, err := decode("y")
	if err != nil {
		return nil, err
	}
	dRaw, err := decode("d")
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	x, y, d := new(big.Int).SetBytes(xRaw), new(big.Int).SetBytes(yRaw), new(big.Int).SetBytes(dRaw)
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 || !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid DPoP JWK key material")
	}
	wantX, wantY := curve.ScalarBaseMult(dRaw)
	if wantX.Cmp(x) != 0 || wantY.Cmp(y) != 0 {
		return nil, fmt.Errorf("DPoP JWK public/private key mismatch")
	}
	return &dpopKeyPair{
		PrivateKey: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d},
		PublicJWK:  map[string]string{"kty": "EC", "crv": "P-256", "x": jwk["x"], "y": jwk["y"]},
	}, nil
}

func dpopKeyPairFor(jwk DPoPPrivateJWK) (*dpopKeyPair, error) {
	if len(jwk) > 0 && jwk["d"] != "" {
		kp, err := dpopKeyPairFromPrivateJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("restore dpop keypair: %w", err)
		}
		return kp, nil
	}
	kp, err := newDpopKeyPair()
	if err != nil {
		return nil, fmt.Errorf("dpop keypair: %w", err)
	}
	return kp, nil
}

// SignDPoPProof builds an ES256 DPoP JWT (htm=POST, htu=token endpoint).
func SignDPoPProof(jwk DPoPPrivateJWK, htu string) (string, error) {
	kp, err := dpopKeyPairFor(jwk)
	if err != nil {
		return "", err
	}
	return signDpopProof(kp, htu)
}

func signDpopProof(kp *dpopKeyPair, htu string) (string, error) {
	header := map[string]any{
		"alg": "ES256",
		"typ": "dpop+jwt",
		"jwk": kp.PublicJWK,
	}
	headerJSON, _ := json.Marshal(header)
	payload := map[string]any{
		"htm": "POST",
		"htu": htu,
		"iat": time.Now().Unix(),
		"jti": RandomHexOrTime(32),
	}
	payloadJSON, _ := json.Marshal(payload)
	input := b64(headerJSON) + "." + b64(payloadJSON)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, kp.PrivateKey, digest[:])
	if err != nil {
		return "", err
	}
	n := elliptic.P256().Params().N
	halfN := new(big.Int).Rsh(n, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(n, s)
	}
	sig := append(padded(r, 32), padded(s, 32)...)
	return input + "." + b64(sig), nil
}

func padded(b *big.Int, size int) []byte {
	out := make([]byte, size)
	raw := b.Bytes()
	copy(out[size-len(raw):], raw)
	return out
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
