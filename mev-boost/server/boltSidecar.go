package server

import (
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/log"
	"github.com/flashbots/go-utils/jsonrpc"
)

// boltSidecar is a thin http client that communicates with the
// bolt sidecar server to fetch preconfirmed transactions.
type boltSidecar struct {
	endpoint string
}

// newBoltSidecar creates a new boltSidecar instance.
func newBoltSidecar(endpoint string) *boltSidecar {
	return &boltSidecar{
		endpoint: endpoint,
	}
}

type rawPreconfirmation struct {
	Slot   uint64 `json:"slot"`
	TxHash string `json:"txHash"`
	RawTx  string `json:"rawTx"`
}

func (b *boltSidecar) GetPreconfirmations(slot uint64) ([]*rawPreconfirmation, error) {
	var preconfirms = new([]*rawPreconfirmation)

	params := map[string]interface{}{
		"slot": slot,
	}

	// Request preconfirmations directly from the next proposer in line.
	// In a real version, this would be done through a mempool / DA service.
	req := jsonrpc.NewJSONRPCRequest("1", "eth_getPreconfirmations", params)
	res, err := jsonrpc.SendJSONRPCRequest(*req, b.endpoint)
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

	log.Info(fmt.Sprintf("Preconf Response Body: %s", string(res.Result)))

	return *preconfirms, nil
}
