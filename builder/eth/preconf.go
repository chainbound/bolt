package eth

import (
	"encoding/hex"
	"encoding/json"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-utils/jsonrpc"
)

type rawPreconfirmation struct {
	Slot   uint64 `json:"slot"`
	TxHash string `json:"txHash"`
	RawTx  string `json:"rawTx"`
}

func GetPreconfirmations(boltCCEndpoint string, nextSlot uint64) ([]*types.Transaction, error) {
	var preconfirms = new([]rawPreconfirmation)

	params := map[string]interface{}{
		"slot": nextSlot,
	}

	// Request preconfirmations directly from the next proposer in line.
	// In a real version, this would be done through a mempool / DA service.
	req := jsonrpc.NewJSONRPCRequest("1", "eth_getPreconfirmations", params)
	res, err := jsonrpc.SendJSONRPCRequest(*req, boltCCEndpoint)
	if err != nil {
		log.Error("Error getting preconfs via RPC: ", err)
		return nil, err
	}

	// Unmarshal the JSON data
	err = json.Unmarshal(res.Result, &preconfirms)
	if err != nil {
		log.Error("Error unmarshaling data: ", err)
		return nil, err
	}

	result := make([]*types.Transaction, len(*preconfirms))

	for i, preconfirm := range *preconfirms {
		rlpBytes, err := hex.DecodeString(preconfirm.RawTx[2:])
		if err != nil {
			log.Error("Failed to decode transaction hex RLP: ", err)
			return nil, err
		}

		decoded := new(types.Transaction)
		if err := decoded.UnmarshalBinary(rlpBytes); err != nil {
			log.Error("Failed to decode preconfirmation transaction RLP: ", err)
			return nil, err
		}

		result[i] = decoded
	}

	return result, nil
}
