package builder

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

var errHTTPErrorResponse = errors.New("HTTP error response")

func DecodeConstraints(constraints *common.SignedConstraints) (types.HashToConstraintDecoded, error) {
	decodedConstraints := make(types.HashToConstraintDecoded)
	for _, tx := range constraints.Message.Constraints {
		decoded := new(types.Transaction)
		if err := decoded.UnmarshalBinary(tx.Tx); err != nil {
			return nil, err
		}
		decodedConstraints[decoded.Hash()] = &types.ConstraintDecoded{Index: tx.Index, Tx: decoded}
	}
	return decodedConstraints, nil
}

// SendSSZRequest is a request to send SSZ data to a remote relay.
func SendSSZRequest(ctx context.Context, client http.Client, method, url string, payload []byte, useGzip bool) (code int, err error) {
	var req *http.Request

	reader := bytes.NewReader(payload)

	if useGzip {
		// Create a new gzip writer
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)

		// Write the payload to the gzip writer
		_, err = reader.WriteTo(gzipWriter)
		if err != nil {
			return 0, fmt.Errorf("error writing payload to gzip writer: %w", err)
		}

		// Flush and close the gzip writer to finalize the compressed data
		err = gzipWriter.Close()
		if err != nil {
			return 0, fmt.Errorf("error closing gzip writer: %w", err)
		}

		req, err = http.NewRequest(http.MethodPost, url, &buf)
		if err != nil {
			return 0, fmt.Errorf("error creating request: %w", err)
		}
		req.Header.Add("Content-Encoding", "gzip")
	} else {
		req, err = http.NewRequest(http.MethodPost, url, reader)
		if err != nil {
			return 0, fmt.Errorf("error creating request: %w", err)
		}
	}

	req.Header.Add("Content-Type", "application/octet-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("HTTP error response: %d / %s", resp.StatusCode, string(bodyBytes))
	}
	return resp.StatusCode, nil
}

// SendHTTPRequest - prepare and send HTTP request, marshaling the payload if any, and decoding the response if dst is set
func SendHTTPRequest(ctx context.Context, client http.Client, method, url string, payload, dst any) (code int, err error) {
	var req *http.Request

	if payload == nil {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	} else {
		payloadBytes, err2 := json.Marshal(payload)
		if err2 != nil {
			return 0, fmt.Errorf("could not marshal request: %w", err2)
		}
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(payloadBytes))

		// Set headers
		req.Header.Add("Content-Type", "application/json")
	}
	if err != nil {
		return 0, fmt.Errorf("could not prepare request: %w", err)
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}

	if resp.StatusCode > 299 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read error response body for status code %d: %w", resp.StatusCode, err)
		}
		return resp.StatusCode, fmt.Errorf("%w: %d / %s", errHTTPErrorResponse, resp.StatusCode, string(bodyBytes))
	}

	if dst != nil {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return resp.StatusCode, fmt.Errorf("could not read response body: %w", err)
		}

		if err := json.Unmarshal(bodyBytes, dst); err != nil {
			return resp.StatusCode, fmt.Errorf("could not unmarshal response %s: %w", string(bodyBytes), err)
		}
	}

	return resp.StatusCode, nil
}

// EmitBoltDemoEvent sends a message to the web demo backend to log an event.
// This is only used for demo purposes and should be removed in production.
func EmitBoltDemoEvent(message string) {
	event := strings.NewReader(fmt.Sprintf("{ \"message\": \"BOLT-BUILDER: %s\"}", message))
	eventRes, err := http.Post("http://172.17.0.1:3001/events", "application/json", event)
	if err != nil {
		log.Error("Failed to send web demo event: ", err)
	}
	if eventRes != nil {
		defer eventRes.Body.Close()
	}
}
