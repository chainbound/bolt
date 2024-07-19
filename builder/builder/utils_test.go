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
	// https://etherscan.io/tx/0x15bd881daa1408b33f67fa4bdeb8acfb0a2289d9b4c6f81eef9bb2bb2e52e780 - Blob Tx
	// 0x03f9029c01830299f184b2d05e008507aef40a00832dc6c09468d30f47f19c07bccef4ac7fae2dc12fca3e0dc980b90204ef16e845000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000633b68f5d8d3a86593ebb815b4663bcbe0302e31382e302d64657600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109de8da2a97e37f2e6dc9f7d50a408f9344d7aa1a925ae53daf7fbef43491a571960d76c0cb926190a9da10df7209fb1ba93cd98b1565a3a2368749d505f90c81c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0843b9aca00e1a00141e3a338e30c49ed0501e315bcc45e4edefebed43ab1368a1505461d9cf64901a01e8511e06b17683d89eb57b9869b96b8b611f969f7f56cbc0adc2df7c88a2a07a00910deacf91bba0d74e368d285d311dc5884e7cfe219d85aea5741b2b6e3a2fe

	raw := `["0x03f9029c01830299f184b2d05e008507aef40a00832dc6c09468d30f47f19c07bccef4ac7fae2dc12fca3e0dc980b90204ef16e845000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000633b68f5d8d3a86593ebb815b4663bcbe0302e31382e302d64657600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004109de8da2a97e37f2e6dc9f7d50a408f9344d7aa1a925ae53daf7fbef43491a571960d76c0cb926190a9da10df7209fb1ba93cd98b1565a3a2368749d505f90c81c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0843b9aca00e1a00141e3a338e30c49ed0501e315bcc45e4edefebed43ab1368a1505461d9cf64901a01e8511e06b17683d89eb57b9869b96b8b611f969f7f56cbc0adc2df7c88a2a07a00910deacf91bba0d74e368d285d311dc5884e7cfe219d85aea5741b2b6e3a2fe", "0x02f873011a8405f5e10085037fcc60e182520894f7eaaf75cb6ec4d0e2b53964ce6733f54f7d3ffc880b6139a7cbd2000080c080a095a7a3cbb7383fc3e7d217054f861b890a935adc1adf4f05e3a2f23688cf2416a00875cdc45f4395257e44d709d04990349b105c22c11034a60d7af749ffea2765","0xf8708305dc6885029332e35883019a2894500b0107e172e420561565c8177c28ac0f62017f8810ffb80e6cc327008025a0e9c0b380c68f040ae7affefd11979f5ed18ae82c00e46aa3238857c372a358eca06b26e179dd2f7a7f1601755249f4cff56690c4033553658f0d73e26c36fe7815", "0xf86c0785028fa6ae0082520894098d880c4753d0332ca737aa592332ed2522cd22880d2f09f6558750008026a0963e58027576b3a8930d7d9b4a49253b6e1a2060e259b2102e34a451d375ce87a063f802538d3efed17962c96fcea431388483bbe3860ea9bb3ef01d4781450fbf", "0x02f87601836384348477359400850517683ba883019a28943678fce4028b6745eb04fa010d9c8e4b36d6288c872b0f1366ad800080c080a0b6b7aba1954160d081b2c8612e039518b9c46cd7df838b405a03f927ad196158a071d2fb6813e5b5184def6bd90fb5f29e0c52671dea433a7decb289560a58416e"]`

	byteTxs := make([]*common.HexBytes, 0, 5)
	err := json.Unmarshal([]byte(raw), &byteTxs)
	require.NoError(t, err)
	require.Equal(t, len(byteTxs), 5)

	payloadTransactions := common.Map(byteTxs, func(rawTx *common.HexBytes) *types.Transaction {
		transaction := new(types.Transaction)
		err = transaction.UnmarshalBinary([]byte(*rawTx))
		return transaction
	})

	require.Equal(t, payloadTransactions[0].Type(), uint8(3))
	require.Equal(t, payloadTransactions[1].Type(), uint8(2))

	// try out all combinations of "constraints":
	// e.g. only [0], then [0, 1], then [1] etc...
	// and log which ones are failing and which ones are not
	for i := 1; i < len(payloadTransactions)+1; i++ {
		t.Logf("--- Trying with %d constraints\n", i)
		for _, chosenConstraintTransactions := range combinations(payloadTransactions, i) {
			// find the index of the chosen constraints inside payload transactions for debugging
			payloadIndexes := make([]int, len(chosenConstraintTransactions))
			for i, chosenConstraint := range chosenConstraintTransactions {
				for j, payloadTransaction := range payloadTransactions {
					if chosenConstraint.Hash() == payloadTransaction.Hash() {
						payloadIndexes[i] = j
						break
					}
				}
			}

			constraints := make(types.HashToConstraintDecoded)
			for _, tx := range chosenConstraintTransactions {
				constraints[tx.Hash()] = &types.ConstraintDecoded{Tx: tx}
			}

			inclusionProof, root, err := CalculateMerkleMultiProofs(payloadTransactions, constraints)
			require.NoError(t, err)
			rootHash := root.Hash()

			leaves := make([][]byte, len(constraints))

			i := 0
			for _, constraint := range constraints {
				if constraint == nil || constraint.Tx == nil {
					t.Logf("nil constraint or transaction!")
				}

				// Compute the hash tree root for the raw preconfirmed transaction
				// and use it as "Leaf" in the proof to be verified against

				withoutBlob, err := constraint.Tx.WithoutBlobTxSidecar().MarshalBinary()
				if err != nil {
					t.Logf("error marshalling transaction without blob tx sidecar: %v", err)
				}

				tx := Transaction(withoutBlob)
				txHashTreeRoot, err := tx.HashTreeRoot()
				if err != nil {
					t.Logf("error calculating hash tree root: %v", err)
				}

				leaves[i] = txHashTreeRoot[:]
				i++
			}

			hashes := make([][]byte, len(inclusionProof.MerkleHashes))
			for i, hash := range inclusionProof.MerkleHashes {
				hashes[i] = []byte(*hash)
			}
			indexes := make([]int, len(inclusionProof.GeneralizedIndexes))
			for i, index := range inclusionProof.GeneralizedIndexes {
				indexes[i] = int(index)
			}

			ok, err := fastSsz.VerifyMultiproof(rootHash[:], hashes, leaves, indexes)
			if err != nil {
				t.Logf("error verifying merkle proof: %v", err)
			}

			if !ok {
				t.Logf("FAIL with txs: %v", payloadIndexes)
			} else {
				t.Logf("SUCCESS with txs: %v", payloadIndexes)
			}
		}
	}
}

// Function to generate combinations of a specific length
func combinations[T any](arr []T, k int) [][]T {
	var result [][]T
	n := len(arr)
	data := make([]T, k)
	combine(arr, data, 0, n-1, 0, k, &result)
	return result
}

// Helper function to generate combinations
func combine[T any](arr, data []T, start, end, index, k int, result *[][]T) {
	if index == k {
		tmp := make([]T, k)
		copy(tmp, data)
		*result = append(*result, tmp)
		return
	}

	for i := start; i <= end && end-i+1 >= k-index; i++ {
		data[index] = arr[i]
		combine(arr, data, i+1, end, index+1, k, result)
	}
}
