package api

import (
	ssz "github.com/ferranbt/fastssz"
	"github.com/flashbots/mev-boost-relay/common"
)

// MaxBytesPerTransaction is the maximum length in bytes of a raw RLP-encoded transaction
var MaxBytesPerTransaction uint64 = 1_073_741_824 // 2**30

// Transaction is a wrapper type of `common.HexBytes` to implement the ssz.HashRoot interface
type Transaction common.HexBytes

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

func (tx Transaction) MarshalJSON() ([]byte, error) {
	return common.HexBytes(tx).MarshalJSON()
}

func (tx *Transaction) UnmarshalJSON(buf []byte) error {
	return (*common.HexBytes)(tx).UnmarshalJSON(buf)
}

func (tx Transaction) String() string {
	return JSONStringify(tx)
}
