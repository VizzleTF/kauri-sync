package kauri

import (
	"crypto/sha256"
	_ "embed"
	"errors"
	"strings"
)

//go:embed bip39_english.txt
var englishList string

var (
	wordList  = strings.Fields(englishList)
	wordIndex = func() map[string]int {
		m := make(map[string]int, len(wordList))
		for i, w := range wordList {
			m[w] = i
		}
		return m
	}()
)

// EntropyToMnemonic encodes 16 to 32 bytes (a multiple of 4) as BIP-39 words.
func EntropyToMnemonic(entropy []byte) (string, error) {
	n := len(entropy)
	if n < 16 || n > 32 || n%4 != 0 {
		return "", errors.New("kauri: entropy must be 16 to 32 bytes, a multiple of 4")
	}
	sum := sha256.Sum256(entropy)
	bits := append(append([]byte{}, entropy...), sum[0])
	csBits := n * 8 / 32
	total := n*8 + csBits
	words := make([]string, 0, total/11)
	for i := 0; i < total; i += 11 {
		idx := 0
		for j := 0; j < 11; j++ {
			b := i + j
			if bits[b/8]&(0x80>>(b%8)) != 0 {
				idx |= 1 << (10 - j)
			}
		}
		words = append(words, wordList[idx])
	}
	return strings.Join(words, " "), nil
}

// MnemonicToEntropy decodes BIP-39 words and checks their checksum.
func MnemonicToEntropy(mnemonic string) ([]byte, error) {
	words := strings.Fields(strings.ToLower(mnemonic))
	if len(words)%3 != 0 || len(words) < 12 || len(words) > 24 {
		return nil, errors.New("kauri: wrong number of words")
	}
	total := len(words) * 11
	csBits := total / 33
	entBytes := (total - csBits) / 8
	bits := make([]byte, (total+7)/8)
	for i, w := range words {
		idx, ok := wordIndex[w]
		if !ok {
			return nil, errors.New("kauri: unknown word " + w)
		}
		for j := 0; j < 11; j++ {
			if idx&(1<<(10-j)) != 0 {
				b := i*11 + j
				bits[b/8] |= 0x80 >> (b % 8)
			}
		}
	}
	entropy := bits[:entBytes]
	sum := sha256.Sum256(entropy)
	want := sum[0] >> (8 - csBits)
	got := bits[entBytes] >> (8 - csBits)
	if want != got {
		return nil, errors.New("kauri: the sync code has a typo (checksum mismatch)")
	}
	return append([]byte{}, entropy...), nil
}
