package server

import (
	"encoding/hex"
	"testing"

	gethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/require"
)

func Test_ParseContraintsDecoded(t *testing.T) {
	rawTxs := []string{
		// These two will have index set, and nonce 367, 368
		"f86882016f84042343e082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead07808360306ba0a5b07edf4e7074a679b08cfc474364f3378e87006d82843c8bf306fc1c6e9e57a07927c7f92ac2f9a5166433e2b9bbc5f48ebf9d366d437c568c465cdf9ac148d8",
		"f86882017084042343e082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead3b808360306ba082d4f1a817f12d59d21bbf1b156715bc1ab307f160b4a3e1527ec915a7757273a073a51224caa582e0cb34388ff188a68d022a6a283fcb9b4e6dfecece8ccf21e6",
		// These three will not
		// The first two will have same nonce 369, but one is to aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa just to have different hash: 0x678a4d09b8dd43ebd675b9e3f1983185f5a31f7b44e3f5815436a8fae647d1f9
		"f86882017184042343e082520894aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa27808360306ca00499b985ef217b1f9c03ef039190ae877b4578114e0b03a1ebbae977d5ca7d5fa0086a6d280a7dd5fdb64c4ddc727329f0ba1fa8c49deab9cafe71207f21dbf81b",
		// This has hash 0x1c8e21622617cc02111389c67f542b5059cf5b024b265c5fdbcac529ae7ab7e0, so it will appear first
		"f86882017184042343e082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead27808360306ca00499b985ef217b1f9c03ef039190ae877b4578114e0b03a1ebbae977d5ca7d5fa0086a6d280a7dd5fdb64c4ddc727329f0ba1fa8c49deab9cafe71207f21dbf81b",
		// This will have nonce 370
		"f86882017284042343e082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead11808360306ba0891ff5261562c21a3f89f12d95391aef865c21f5cf72f97c4602aa9f072c0489a04c4482a46802d160c9a812cffc90be0cd6ffc1206c9dd2f5b53111d9098ff207",
		// "f86882017384042343e082520894deaddeaddeaddeaddeaddeaddeaddeaddeaddead4b808360306ca087d083fadadeba27f213ebb2b428003aa730035686202547e2260cadfb824ee5a00c93b0f0403fbb78b5810e90b9f5bb63368dd6bcd5c31c56ed1b132167e7d69f",
	}

	hashToConstraint := make(HashToConstraintDecoded)

	for i, rawTx := range rawTxs {
		rawTxBytes, err := hex.DecodeString(rawTx)
		require.NoError(t, err)
		tx := new(gethTypes.Transaction)
		err = tx.UnmarshalBinary(rawTxBytes)

		require.NoError(t, err)
		var index *uint64
		if i < 2 {
			index = new(uint64)
			*index = uint64(i)
		}
		hashToConstraint[tx.Hash()] = &ConstraintDecoded{
			Tx:    tx,
			Index: index,
		}
	}

	constraintsParsed := ParseConstraintsDecoded(hashToConstraint)
	require.Equal(t, uint64(367), constraintsParsed[0].Tx.Nonce())
	require.Equal(t, uint64(368), constraintsParsed[1].Tx.Nonce())
	require.Equal(t, "0x1c8e21622617cc02111389c67f542b5059cf5b024b265c5fdbcac529ae7ab7e0", constraintsParsed[2].Tx.Hash().String())
	require.Equal(t, uint64(369), constraintsParsed[3].Tx.Nonce())
	require.Equal(t, uint64(370), constraintsParsed[4].Tx.Nonce())
}
