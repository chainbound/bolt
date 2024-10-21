package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	blst "github.com/supranational/blst/bindings/go"
)

type blsPublicKey = blst.P1Affine

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: pubkey_to_g1 <pubkey>")
		os.Exit(1)
	}

	pubkey := strings.TrimPrefix(os.Args[1], "0x")

	pubkeyBytes, err := hex.DecodeString(pubkey)
	if err != nil {
		fmt.Println("Failed to decode pubkey:", err)
		os.Exit(1)
	}

	if len(pubkeyBytes) != 48 {
		fmt.Println("Invalid pubkey length")
		os.Exit(1)
	}

	G1 := new(blsPublicKey).Uncompress(pubkeyBytes)

	serialized := G1.Serialize()

	x := serialized[0:48]
	y := serialized[48:]

	fmt.Printf("0x%x,0x%x\n", x, y)
}
