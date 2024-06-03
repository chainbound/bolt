package server

import (
	"encoding/hex"
	"fmt"
	"strings"

	ssz "github.com/ferranbt/fastssz"
)

// MaxBytesPerTransaction is the maximum length in bytes of a raw RLP-encoded transaction
var MaxBytesPerTransaction uint64 = 1_073_741_824 // 2**30

// Transaction is a wrapper type of byte slice to implement the ssz.HashRoot interface
type Transaction []byte

// HashTreeRoot calculates the hash tree root of the transaction, which
// is a list of basic types (byte).
//
// Reference: https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md#merkleization
func (tx *Transaction) HashTreeRoot() ([32]byte, error) {
	hasher := ssz.NewHasher()
	tx.HashTreeRootWith(hasher)
	root, err := hasher.HashRoot()

	return root, err
}

func (tx *Transaction) HashTreeRootWith(hh ssz.HashWalker) error {
	var err error
	byteLen := uint64(len(*tx))

	if byteLen > MaxBytesPerTransaction {
		err = ssz.ErrIncorrectListSize
		return err
	}

	// Load the bytes of the transaction into the hasher
	hh.AppendBytes32(*tx)
	// Perform `mix_in_length(merkleize(pack(value), limit=chunk_count(type)), len(value))`
	// Reference: https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md#merkleization
	//
	// The `indx` parameters is set to `0` as we need to consider the whole hh.buf buffer for this.
	// In an implementation of more complex types, this parameter would be used to indicate the starting
	// index of the buffer to be merkleized. It is used a single buffer to do everything for
	// optimization purposes.
	hh.MerkleizeWithMixin(0, byteLen, (1073741824+31)/32)

	return nil
}

func (tx *Transaction) GetTree() (*ssz.Node, error) {
	w := &ssz.Wrapper{}
	tx.HashTreeRootWith(w)
	return w.Node(), nil
}

// UnmarshalJSON custom unmarshal function for the Transaction type
func (tx *Transaction) UnmarshalJSON(data []byte) error {
	// Remove the quotes from the JSON string
	jsonString := string(data)
	if len(jsonString) < 2 || jsonString[0] != '"' || jsonString[len(jsonString)-1] != '"' {
		return fmt.Errorf("invalid JSON string")
	}
	jsonString = jsonString[1 : len(jsonString)-1]

	// Remove the "0x" prefix if present
	jsonString = strings.TrimPrefix(jsonString, "0x")

	// Decode the hex string into the Transaction byte slice
	decodedBytes, err := hex.DecodeString(jsonString)
	if err != nil {
		return err
	}

	// Set the decoded bytes to the Transaction
	*tx = Transaction(decodedBytes)

	return nil
}
