package server

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	builderApi "github.com/attestantio/go-builder-client/api"
	builderApiDeneb "github.com/attestantio/go-builder-client/api/deneb"
	"github.com/attestantio/go-eth2-client/spec"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/deneb"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	utilbellatrix "github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/ethereum/go-ethereum/core/types"
	fastssz "github.com/ferranbt/fastssz"
	"github.com/flashbots/mev-boost/config"
	"github.com/stretchr/testify/require"
)

func TestMakePostRequest(t *testing.T) {
	// Test errors
	var x chan bool
	code, err := SendHTTPRequest(context.Background(), *http.DefaultClient, http.MethodGet, "", "test", nil, x, nil)
	require.Error(t, err)
	require.Equal(t, 0, code)
}

func TestDecodeJSON(t *testing.T) {
	// test disallows unknown fields
	var x struct {
		A int `json:"a"`
		B int `json:"b"`
	}
	payload := bytes.NewReader([]byte(`{"a":1,"b":2,"c":3}`))
	err := DecodeJSON(payload, &x)
	require.Error(t, err)
	require.Equal(t, "json: unknown field \"c\"", err.Error())
}

func TestSendHTTPRequestUserAgent(t *testing.T) {
	done := make(chan bool, 1)

	// Test with custom UA
	customUA := "test-user-agent"
	expectedUA := fmt.Sprintf("mev-boost/%s %s", config.Version, customUA)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, expectedUA, r.Header.Get("User-Agent"))
		done <- true
	}))
	code, err := SendHTTPRequest(context.Background(), *http.DefaultClient, http.MethodGet, ts.URL, UserAgent(customUA), nil, nil, nil)
	ts.Close()
	require.NoError(t, err)
	require.Equal(t, 200, code)
	<-done

	// Test without custom UA
	expectedUA = fmt.Sprintf("mev-boost/%s", config.Version)
	ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, expectedUA, r.Header.Get("User-Agent"))
		done <- true
	}))
	code, err = SendHTTPRequest(context.Background(), *http.DefaultClient, http.MethodGet, ts.URL, "", nil, nil, nil)
	ts.Close()
	require.NoError(t, err)
	require.Equal(t, 200, code)
	<-done
}

func TestSendHTTPRequestGzip(t *testing.T) {
	// Test with gzip response
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write([]byte(`{ "msg": "test-message" }`))
	require.NoError(t, err)
	require.NoError(t, zw.Close())

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "gzip", r.Header.Get("Accept-Encoding"))
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(buf.Bytes())
	}))
	resp := struct{ Msg string }{}
	code, err := SendHTTPRequest(context.Background(), *http.DefaultClient, http.MethodGet, ts.URL, "", nil, nil, &resp)
	ts.Close()
	require.NoError(t, err)
	require.Equal(t, 200, code)
	require.Equal(t, "test-message", resp.Msg)
}

func TestWeiBigIntToEthBigFloat(t *testing.T) {
	// test with valid input
	i := big.NewInt(1)
	f := weiBigIntToEthBigFloat(i)
	require.Equal(t, "0.000000000000000001", f.Text('f', 18))

	// test with nil, which results on invalid big.Int input
	f = weiBigIntToEthBigFloat(nil)
	require.Equal(t, "0.000000000000000000", f.Text('f', 18))
}

func TestGetPayloadResponseIsEmpty(t *testing.T) {
	testCases := []struct {
		name     string
		payload  *builderApi.VersionedSubmitBlindedBlockResponse
		expected bool
	}{
		{
			name: "Non-empty capella payload response",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Version: spec.DataVersionCapella,
				Capella: &capella.ExecutionPayload{
					BlockHash: phase0.Hash32{0x1},
				},
			},
			expected: false,
		},
		{
			name: "Non-empty deneb payload response",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Version: spec.DataVersionDeneb,
				Deneb: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
					ExecutionPayload: &deneb.ExecutionPayload{
						BlockHash: phase0.Hash32{0x1},
					},
					BlobsBundle: &builderApiDeneb.BlobsBundle{
						Blobs:       make([]deneb.Blob, 0),
						Commitments: make([]deneb.KZGCommitment, 0),
						Proofs:      make([]deneb.KZGProof, 0),
					},
				},
			},
			expected: false,
		},
		{
			name: "Empty capella payload response",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Version: spec.DataVersionCapella,
			},
			expected: true,
		},
		{
			name: "Nil block hash for capella payload response",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Version: spec.DataVersionCapella,
				Capella: &capella.ExecutionPayload{
					BlockHash: nilHash,
				},
			},
			expected: true,
		},
		{
			name: "Empty deneb payload response",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Version: spec.DataVersionDeneb,
			},
			expected: true,
		},
		{
			name: "Empty deneb execution payload",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Version: spec.DataVersionDeneb,
				Deneb: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
					BlobsBundle: &builderApiDeneb.BlobsBundle{
						Blobs:       make([]deneb.Blob, 0),
						Commitments: make([]deneb.KZGCommitment, 0),
						Proofs:      make([]deneb.KZGProof, 0),
					},
				},
			},
			expected: true,
		},
		{
			name: "Empty deneb blobs bundle",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Deneb: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
					ExecutionPayload: &deneb.ExecutionPayload{
						BlockHash: phase0.Hash32{0x1},
					},
				},
			},
			expected: true,
		},
		{
			name: "Nil block hash for deneb payload response",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Deneb: &builderApiDeneb.ExecutionPayloadAndBlobsBundle{
					ExecutionPayload: &deneb.ExecutionPayload{
						BlockHash: nilHash,
					},
				},
			},
			expected: true,
		},
		{
			name: "Unsupported payload version",
			payload: &builderApi.VersionedSubmitBlindedBlockResponse{
				Version: spec.DataVersionBellatrix,
			},
			expected: true,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, getPayloadResponseIsEmpty(tt.payload))
		})
	}
}

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

	// Unmarshal the raw transactions
	byteTxs := make([]*HexBytes, 0, 2)
	err := json.Unmarshal([]byte(raw), &byteTxs)
	require.NoError(t, err)

	// Create payload transactions
	payloadTransactions := Map(byteTxs, func(rawTx *HexBytes) *types.Transaction {
		transaction := new(types.Transaction)
		err = transaction.UnmarshalBinary([]byte(*rawTx))
		require.NoError(t, err)
		return transaction
	})

	// Constraints
	constraints := []struct {
		tx   Transaction
		hash phase0.Hash32
	}{
		{tx: Transaction(*byteTxs[0]), hash: phase0.Hash32(payloadTransactions[0].Hash())},
		{tx: Transaction(*byteTxs[1]), hash: phase0.Hash32(payloadTransactions[1].Hash())},
	}

	// Create root node
	transactions := new(utilbellatrix.ExecutionPayloadTransactions)

	for _, con := range constraints {
		transactions.Transactions = append(transactions.Transactions, bellatrix.Transaction(con.tx))
	}

	rootNode, err := transactions.GetTree()
	require.NoError(t, err)

	// Call the function to test
	inclusionProof, err := CalculateMerkleMultiProofs(rootNode, constraints)
	require.NoError(t, err)

	// Verify the inclusion proof
	rootHash := rootNode.Hash()
	hashesBytes := make([][]byte, len(inclusionProof.MerkleHashes))
	for i, hash := range inclusionProof.MerkleHashes {
		hashesBytes[i] = (*hash)[:]
	}
	leavesBytes := make([][]byte, len(constraints))
	for i, con := range constraints {
		root, err := con.tx.HashTreeRoot()
		require.NoError(t, err)
		leavesBytes[i] = root[:]
	}
	indicesInt := make([]int, len(inclusionProof.GeneralizedIndexes))
	for i, index := range inclusionProof.GeneralizedIndexes {
		indicesInt[i] = int(index)
	}

	_, err = fastssz.VerifyMultiproof(rootHash, hashesBytes, leavesBytes, indicesInt)
	require.NoError(t, err)
}
