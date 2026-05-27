package algo

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strings"
	"time"
)

const (
	PrandStateSize = 16
	Magic          = "\x10\xAB\xFF\xDE"
	MagicSize      = 4
	DeSize         = 512
)

// PrandState represents the xobfs deterministic PRNG state.
type PrandState struct {
	s [2]uint64
}

// AutoSeed seeds the PRNG state based on cryptographic randomness.
func (st *PrandState) AutoSeed() {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err == nil {
		st.s[0] = binary.LittleEndian.Uint64(entropy[:8])
		st.s[1] = binary.LittleEndian.Uint64(entropy[8:])
	} else {
		// Fallback similar to C version if crypto/rand fails
		st.s[0] = uint64(time.Now().UnixNano()) ^ 0xDEADBEEF
		st.s[1] = uint64(time.Now().UnixNano()) ^ 0xCAFEBABE
	}
	if st.s[0] == 0 && st.s[1] == 0 {
		st.s[0], st.s[1] = 1, 2
	}
}

// Next generates the next uint64 using the xoroshiro128 algorithm (matches C).
func (st *PrandState) Next() uint64 {
	s0 := st.s[0]
	s1 := st.s[1]
	result := s0 + s1
	s1 ^= s0
	st.s[0] = bits.RotateLeft64(s0, 24) ^ s1 ^ (s1 << 16)
	st.s[1] = bits.RotateLeft64(s1, 37)
	return result
}

// Serialize converts the PRNG state to a 16-byte slice (BigEndian as in C).
func (st *PrandState) Serialize() []byte {
	out := make([]byte, PrandStateSize)
	binary.BigEndian.PutUint64(out[0:8], st.s[0])
	binary.BigEndian.PutUint64(out[8:16], st.s[1])
	return out
}

// Deserialize restores the PRNG state from a 16-byte slice.
func (st *PrandState) Deserialize(in []byte) error {
	if len(in) < PrandStateSize {
		return errors.New("input too small for PrandState")
	}
	st.s[0] = binary.BigEndian.Uint64(in[0:8])
	st.s[1] = binary.BigEndian.Uint64(in[8:16])
	return nil
}

// PrandInt generates a random integer between minV and maxV inclusive using PrandState.
func (st *PrandState) PrandInt(minV, maxV int64) int64 {
	if st.s[0] == 0 && st.s[1] == 0 {
		st.AutoSeed()
	}
	if minV > maxV {
		return -1
	}
	rangeV := uint64(maxV - minV + 1)
	if rangeV == 0 {
		return minV
	}
	limit := math.MaxUint64 - (math.MaxUint64 % rangeV)
	for {
		r := st.Next()
		if r < limit {
			return minV + int64(r%rangeV)
		}
	}
}

// UrandInt generates a cryptographically secure random integer between minV and maxV inclusive.
func UrandInt(minV, maxV int64) (int64, error) {
	if minV > maxV {
		return -1, errors.New("minV > maxV")
	}
	rangeV := uint64(maxV - minV + 1)
	if rangeV == 0 {
		return minV, nil
	}
	limit := math.MaxUint64 - (math.MaxUint64 % rangeV)
	var buf [8]byte
	for {
		if _, err := rand.Read(buf[:]); err != nil {
			return -1, err
		}
		r := binary.LittleEndian.Uint64(buf[:])
		if r < limit {
			return minV + int64(r%rangeV), nil
		}
	}
}

// InitPrandStateFromPSK initializes deterministic PRNG from PSK (equivalent to _init_prand_state).
func InitPrandStateFromPSK(psk []byte) *PrandState {
	hash := sha512.Sum512(psk)
	st := &PrandState{}
	_ = st.Deserialize(hash[:PrandStateSize])
	return st
}

// RandomFillUrand fills `out` with uniform random values in range 1..255.
func RandomFillUrand(out []byte) error {
	for i := range out {
		v, err := UrandInt(1, 255)
		if err != nil {
			return err
		}
		out[i] = byte(v)
	}
	return nil
}

// RandomFillPrand fills `out` with PRNG random values in range 1..255.
func RandomFillPrand(out []byte, st *PrandState) {
	for i := range out {
		out[i] = byte(st.PrandInt(1, 255))
	}
}

// GenJitterUrand generates between minSize and maxSize random jitter bytes.
func GenJitterUrand(minSize, maxSize int64) ([]byte, error) {
	if minSize > maxSize {
		return nil, errors.New("min > max")
	}
	sz, err := UrandInt(minSize, maxSize)
	if err != nil {
		return nil, err
	}
	out := make([]byte, sz)
	if err := RandomFillUrand(out); err != nil {
		return nil, err
	}
	return out, nil
}

// XorData applies an XOR key repeatedly across data.
func XorData(data, key []byte) []byte {
	out := make([]byte, len(data))
	if len(key) == 0 {
		copy(out, data)
		return out
	}
	kLen := len(key)
	for i := range data {
		out[i] = data[i] ^ key[i%kLen]
	}
	return out
}

func xorDataInPlace(data, key []byte) {
	if len(key) == 0 {
		return
	}
	kLen := len(key)
	for i := range data {
		data[i] ^= key[i%kLen]
	}
}

// XorDataMixed applies XOR with random PRNG offset.
func XorDataMixed(data, key []byte, st *PrandState) []byte {
	out := make([]byte, len(data))
	if len(key) == 0 {
		copy(out, data)
		return out
	}
	kLen := int64(len(key))
	for i := range data {
		offset := st.PrandInt(0, kLen-1)
		idx := (int64(i) + offset) % kLen
		out[i] = data[i] ^ key[idx]
	}
	return out
}

// MergeData merges a slice of strings into a single string (equivalent to xobfs_merge_data).
func MergeData(parts []string) string {
	var res strings.Builder
	for _, p := range parts {
		res.WriteString(p)
	}
	return res.String()
}

// GetTimeMillis returns the current epoch time in milliseconds.
func GetTimeMillis() int64 {
	return time.Now().UnixMilli()
}

// Obfuscate applies XOBFS obfuscation to data using PSK.
func Obfuscate(data, psk []byte) ([]byte, error) {
	if len(data) == 0 || len(psk) == 0 {
		return nil, errors.New("[xobfs][obfs] data or PSK cannot be empty")
	}
	if len(psk) < 6 {
		return nil, errors.New("[xobfs][obfs] PSK_LEN is too small, make 6 at least")
	}
	if len(psk) > 64 {
		return nil, errors.New("[xobfs][obfs] PSK_LEN exceeds max supported size of 64")
	}

	packetNonce := make([]byte, 8)
	if err := RandomFillUrand(packetNonce); err != nil {
		return nil, fmt.Errorf("[xobfs][obfs] packet nonce generation failed: %w", err)
	}

	keyMaterial := make([]byte, 0, len(psk)+8)
	keyMaterial = append(keyMaterial, psk...)
	keyMaterial = append(keyMaterial, packetNonce...)
	hash := sha512.Sum512(keyMaterial)
	sessionKey := hash[:len(psk)]

	pstate := InitPrandStateFromPSK(psk)

	de := make([]byte, DeSize)
	RandomFillPrand(de, pstate)

	xoredPsk := XorData(psk, de)

	jitter, err := GenJitterUrand(10, 50)
	if err != nil {
		return nil, fmt.Errorf("[xobfs][obfs] jitter failed: %w", err)
	}
	jitterSz := len(jitter)

	lenMask := xoredPsk[0]
	lenByte := byte(jitterSz) ^ lenMask

	rawPayloadLen := MagicSize + len(data)
	totalLen := 1 + 8 + jitterSz + rawPayloadLen

	frame := make([]byte, 0, totalLen)
	frame = append(frame, lenByte)
	frame = append(frame, packetNonce...)
	frame = append(frame, jitter...)
	frame = append(frame, []byte(Magic)...)
	frame = append(frame, data...)

	xorDataInPlace(frame[1+8:], sessionKey)

	return frame, nil
}

// Deobfuscate decodes XOBFS obfuscated data.
func Deobfuscate(obfsData, psk []byte) ([]byte, error) {
	if len(obfsData) < 1 {
		return nil, errors.New("[xobfs][deobfs] obfsData is empty")
	}
	if len(psk) < 6 {
		return nil, errors.New("[xobfs][deobfs] PSK_LEN is too small")
	}
	if len(psk) > 64 {
		return nil, errors.New("[xobfs][deobfs] PSK_LEN exceeds max supported size of 64")
	}

	pstate := InitPrandStateFromPSK(psk)

	de := make([]byte, DeSize)
	RandomFillPrand(de, pstate)

	xoredPsk := XorData(psk, de)
	lenMask := xoredPsk[0]
	jitterSz := int(obfsData[0] ^ lenMask)

	if jitterSz < 10 || jitterSz > 50 {
		return nil, fmt.Errorf("[xobfs][deobfs] invalid jitter size: %d (wrong PSK?)", jitterSz)
	}

	if len(obfsData) < 1+8+jitterSz+MagicSize {
		return nil, errors.New("[xobfs][deobfs] frame too short for declared jitter")
	}

	packetNonce := obfsData[1:9]

	keyMaterial := make([]byte, 0, len(psk)+8)
	keyMaterial = append(keyMaterial, psk...)
	keyMaterial = append(keyMaterial, packetNonce...)
	hash := sha512.Sum512(keyMaterial)
	sessionKey := hash[:len(psk)]

	bodySize := len(obfsData) - 1 - 8
	dexored := make([]byte, bodySize)
	copy(dexored, obfsData[9:])

	xorDataInPlace(dexored, sessionKey)

	if string(dexored[jitterSz:jitterSz+MagicSize]) != Magic {
		return nil, errors.New("[xobfs][deobfs] integrity check failed, magic bytes do not match")
	}

	payloadSize := bodySize - jitterSz - MagicSize
	payload := make([]byte, payloadSize)
	copy(payload, dexored[jitterSz+MagicSize:])

	return payload, nil
}
