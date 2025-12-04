package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: mp-dh <verb> [arguments]")
		os.Exit(1)
	}

	verb := os.Args[1]
	switch verb {
	case "generate":
		generate(os.Args[2:])
	case "send":
		send(os.Args[2:])
	case "recover":
		recoverSecret(os.Args[2:])
	default:
		fmt.Printf("Unknown verb: %s\n", verb)
		os.Exit(1)
	}
}

func generate(args []string) {
	if len(args) != 3 {
		fmt.Println("Usage: mp-dh generate <pubkey_file> <chuck_share_file> <alice_share_file>")
		os.Exit(1)
	}

	pubKeyFile := args[0]
	chuckShareFile := args[1]
	aliceShareFile := args[2]

	curve := elliptic.P256()

	// Generate Alice's share (a1)
	a1, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}

	// Generate Chuck's share (a2)
	a2, err := rand.Int(rand.Reader, curve.Params().N)
	if err != nil {
		panic(err)
	}

	// Compute Public Key P = (a1 + a2) * G
	sum := new(big.Int).Add(a1, a2)
	sum.Mod(sum, curve.Params().N)

	x, y := curve.ScalarBaseMult(sum.Bytes())
	pubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Save Public Key
	if err := savePublicKey(pubKeyFile, pubKey); err != nil {
		fmt.Printf("Error saving public key: %v\n", err)
		os.Exit(1)
	}

	// Save Chuck's share (a2)
	if err := saveScalar(chuckShareFile, a2); err != nil {
		fmt.Printf("Error saving Chuck's share: %v\n", err)
		os.Exit(1)
	}

	// Save Alice's share (a1)
	if err := saveScalar(aliceShareFile, a1); err != nil {
		fmt.Printf("Error saving Alice's share: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Key generation complete.")
}

func send(args []string) {
	if len(args) != 2 {
		fmt.Println("Usage: mp-dh send <pubkey_input_file> <ephemeral_pubkey_output_file>")
		os.Exit(1)
	}

	pubKeyInputFile := args[0]
	ephemeralPubKeyOutputFile := args[1]

	// Read Destination Public Key
	destPubKey, err := loadPublicKey(pubKeyInputFile)
	if err != nil {
		fmt.Printf("Error loading public key: %v\n", err)
		os.Exit(1)
	}

	curve := elliptic.P256()

	// Generate Ephemeral Key Pair (b, bG)
	b, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic(err)
	}
	ephemeralPubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	// Compute Shared Secret S = b * DestPubKey
	sx, sy := curve.ScalarMult(destPubKey.X, destPubKey.Y, b)
	if sx == nil || sy == nil {
		fmt.Println("Error computing shared secret")
		os.Exit(1)
	}

	// Save Ephemeral Public Key
	if err := savePublicKey(ephemeralPubKeyOutputFile, ephemeralPubKey); err != nil {
		fmt.Printf("Error saving ephemeral public key: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Sender Shared Secret (x-coord): %x\n", sx.Bytes())
}

func recoverSecret(args []string) {
	if len(args) != 4 {
		fmt.Println("Usage: mp-dh recover <ephemeral_pubkey_input_file> <chuck_share_file> <alice_share_file> <output_secret_file>")
		os.Exit(1)
	}

	ephemeralPubKeyInputFile := args[0]
	chuckShareFile := args[1]
	aliceShareFile := args[2]
	outputSecretFile := args[3]

	// Load inputs
	ephemeralPubKey, err := loadPublicKey(ephemeralPubKeyInputFile)
	if err != nil {
		fmt.Printf("Error loading ephemeral public key: %v\n", err)
		os.Exit(1)
	}

	a2, err := loadScalar(chuckShareFile)
	if err != nil {
		fmt.Printf("Error loading Chuck's share: %v\n", err)
		os.Exit(1)
	}

	a1, err := loadScalar(aliceShareFile)
	if err != nil {
		fmt.Printf("Error loading Alice's share: %v\n", err)
		os.Exit(1)
	}

	curve := elliptic.P256()

	// Compute Partial 1: P_recipient = a1 * (bG)
	rx1, ry1 := curve.ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, a1.Bytes())

	// Compute Partial 2: P_cloud = a2 * (bG)
	rx2, ry2 := curve.ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, a2.Bytes())

	// Recover Secret: S = P_recipient + P_cloud
	sx, sy := curve.Add(rx1, ry1, rx2, ry2)

	// Verify: S_check = (a1 + a2) * (bG)
	sum := new(big.Int).Add(a1, a2)
	sum.Mod(sum, curve.Params().N)
	checkX, checkY := curve.ScalarMult(ephemeralPubKey.X, ephemeralPubKey.Y, sum.Bytes())

	if sx.Cmp(checkX) != 0 || sy.Cmp(checkY) != 0 {
		fmt.Println("Error: Recovered secret does not match direct computation!")
		os.Exit(1)
	} else {
		fmt.Println("Verification successful: Recovered secret matches direct computation.")
	}

	// Save Recovered Secret (x-coord)
	if err := os.WriteFile(outputSecretFile, []byte(hex.EncodeToString(sx.Bytes())), 0644); err != nil {
		fmt.Printf("Error saving recovered secret: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Recovered Shared Secret (x-coord): %x\n", sx.Bytes())
}

// Helper functions

func savePublicKey(filename string, key *ecdsa.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	return pem.Encode(file, block)
}

func loadPublicKey(filename string) (*ecdsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub.(*ecdsa.PublicKey), nil
}

func saveScalar(filename string, scalar *big.Int) error {
	return os.WriteFile(filename, []byte(hex.EncodeToString(scalar.Bytes())), 0644)
}

func loadScalar(filename string) (*big.Int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	bytes, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(bytes), nil
}
