package builder

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	fastSsz "github.com/ferranbt/fastssz"
	"github.com/stretchr/testify/require"
)

func TestGenerateMerkleMultiProofs(t *testing.T) {
	// https://etherscan.io/tx/0x138a5f8ba7950521d9dec66ee760b101e0c875039e695c9fcfb34f5ef02a881b
	// 0x02f873011a8405f5e10085037fcc60e182520894f7eaaf75cb6ec4d0e2b53964ce6733f54f7d3ffc880b6139a7cbd2000080c080a095a7a3cbb7383fc3e7d217054f861b890a935adc1adf4f05e3a2f23688cf2416a00875cdc45f4395257e44d709d04990349b105c22c11034a60d7af749ffea2765
	// https://etherscan.io/tx/0xfb0ee9de8941c8ad50e6a3d2999cd6ef7a541ec9cb1ba5711b76fcfd1662dfa9
	// 0xf8708305dc6885029332e35883019a2894500b0107e172e420561565c8177c28ac0f62017f8810ffb80e6cc327008025a0e9c0b380c68f040ae7affefd11979f5ed18ae82c00e46aa3238857c372a358eca06b26e179dd2f7a7f1601755249f4cff56690c4033553658f0d73e26c36fe7815
	// https://etherscan.io/tx/0x45e7ee9ba1a1d0145de29a764a33bb7fc5620486b686d68ec8cb3182d137bc90
	// 0xf86c0785028fa6ae0082520894098d880c4753d0332ca737aa592332ed2522cd22880d2f09f6558750008026a0963e58027576b3a8930d7d9b4a49253b6e1a2060e259b2102e34a451d375ce87a063f802538d3efed17962c96fcea431388483bbe3860ea9bb3ef01d4781450fbf
	// https://etherscan.io/tx/0x9d48b4a021898a605b7ae49bf93ad88fa6bd7050e9448f12dde064c10f22fe9c
	// 0x02f87601836384348477359400850517683ba883019a28943678fce4028b6745eb04fa010d9c8e4b36d6288c872b0f1366ad800080c080a0b6b7aba1954160d081b2c8612e039518b9c46cd7df838b405a03f927ad196158a071d2fb6813e5b5184def6bd90fb5f29e0c52671dea433a7decb289560a58416e

	raw := `["0x02f873011a8405f5e10085037fcc60e182520894f7eaaf75cb6ec4d0e2b53964ce6733f54f7d3ffc880b6139a7cbd2000080c080a095a7a3cbb7383fc3e7d217054f861b890a935adc1adf4f05e3a2f23688cf2416a00875cdc45f4395257e44d709d04990349b105c22c11034a60d7af749ffea2765","0xf8708305dc6885029332e35883019a2894500b0107e172e420561565c8177c28ac0f62017f8810ffb80e6cc327008025a0e9c0b380c68f040ae7affefd11979f5ed18ae82c00e46aa3238857c372a358eca06b26e179dd2f7a7f1601755249f4cff56690c4033553658f0d73e26c36fe7815", "0xf86c0785028fa6ae0082520894098d880c4753d0332ca737aa592332ed2522cd22880d2f09f6558750008026a0963e58027576b3a8930d7d9b4a49253b6e1a2060e259b2102e34a451d375ce87a063f802538d3efed17962c96fcea431388483bbe3860ea9bb3ef01d4781450fbf", "0x02f87601836384348477359400850517683ba883019a28943678fce4028b6745eb04fa010d9c8e4b36d6288c872b0f1366ad800080c080a0b6b7aba1954160d081b2c8612e039518b9c46cd7df838b405a03f927ad196158a071d2fb6813e5b5184def6bd90fb5f29e0c52671dea433a7decb289560a58416e"]`

	byteTxs := make([]*common.HexBytes, 0, 2)
	err := json.Unmarshal([]byte(raw), &byteTxs)
	require.NoError(t, err)

	payloadTransactions := common.Map(byteTxs, func(rawTx *common.HexBytes) *types.Transaction {
		transaction := new(types.Transaction)
		err = transaction.UnmarshalBinary([]byte(*rawTx))
		return transaction
	})

	transactionsRaw := new([]string)
	err = json.Unmarshal([]byte(raw), transactionsRaw)
	require.NoError(t, err)

	constraints := make(types.HashToConstraintDecoded, 2)
	constraints[payloadTransactions[0].Hash()] = &types.ConstraintDecoded{Tx: payloadTransactions[0]}
	constraints[payloadTransactions[1].Hash()] = &types.ConstraintDecoded{Tx: payloadTransactions[1]}

	inclusionProof, root, err := CalculateMerkleMultiProofs(payloadTransactions, constraints)
	require.NoError(t, err)
	rootHash := root.Hash()

	hashesBytes := make([][]byte, len(inclusionProof.MerkleHashes))
	for i, hash := range inclusionProof.MerkleHashes {
		hashesBytes[i] = (*hash)[:]
	}
	leavesBytes := make([][]byte, len(constraints))
	for i := 0; i < len(constraints); i++ {
		tx := Transaction([]byte(*byteTxs[i]))
		root, err := tx.HashTreeRoot()
		require.NoError(t, err)
		leavesBytes[i] = root[:]
	}
	indicesInt := make([]int, len(inclusionProof.GeneralizedIndexes))
	for i, index := range inclusionProof.GeneralizedIndexes {
		indicesInt[i] = int(index)
	}

	fastSsz.VerifyMultiproof(rootHash, hashesBytes, leavesBytes, indicesInt)
}
