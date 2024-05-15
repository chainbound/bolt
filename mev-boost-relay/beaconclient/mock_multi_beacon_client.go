package beaconclient

import (
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/flashbots/mev-boost-relay/common"
	"github.com/sirupsen/logrus"
	uberatomic "go.uber.org/atomic"
)

type MockMultiBeaconClient struct {
	log             *logrus.Entry
	bestBeaconIndex uberatomic.Int64
	beaconInstances []IBeaconInstance
}

func NewMockMultiBeaconClient(log *logrus.Entry, beaconInstances []IBeaconInstance) *MockMultiBeaconClient {
	return &MockMultiBeaconClient{
		log:             log.WithField("component", "mockMultiBeaconClient"),
		bestBeaconIndex: uberatomic.Int64{},
		beaconInstances: beaconInstances,
	}
}

func (*MockMultiBeaconClient) BestSyncStatus() (*SyncStatusPayloadData, error) {
	return &SyncStatusPayloadData{HeadSlot: 1}, nil //nolint:exhaustruct
}

func (*MockMultiBeaconClient) SubscribeToHeadEvents(slotC chan HeadEventData) {}

func (*MockMultiBeaconClient) SubscribeToPayloadAttributesEvents(payloadAttrC chan PayloadAttributesEvent) {
}

func (c *MockMultiBeaconClient) GetStateValidators(stateID string) (*GetStateValidatorsResponse, error) {
	for i, client := range c.beaconInstances {
		log := c.log.WithField("uri", client.GetURI())
		log.Debug("fetching validators")

		validators, err := client.GetStateValidators(stateID)
		if err != nil {
			log.WithError(err).Error("failed to fetch validators")
			continue
		}

		c.bestBeaconIndex.Store(int64(i))

		// Received successful response. Set this index as last successful beacon node
		return validators, nil
	}

	return nil, ErrBeaconNodesUnavailable
}

func (*MockMultiBeaconClient) GetProposerDuties(epoch uint64) (*ProposerDutiesResponse, error) {
	return nil, nil
}

func (*MockMultiBeaconClient) PublishBlock(block *common.VersionedSignedProposal) (code int, err error) {
	return 0, nil
}

func (*MockMultiBeaconClient) GetGenesis() (*GetGenesisResponse, error) {
	resp := &GetGenesisResponse{} //nolint:exhaustruct
	resp.Data.GenesisTime = 0
	return resp, nil
}

func (*MockMultiBeaconClient) GetSpec() (spec *GetSpecResponse, err error) {
	return nil, nil
}

func (*MockMultiBeaconClient) GetForkSchedule() (spec *GetForkScheduleResponse, err error) {
	resp := &GetForkScheduleResponse{
		Data: []struct {
			PreviousVersion string `json:"previous_version"`
			CurrentVersion  string `json:"current_version"`
			Epoch           uint64 `json:"epoch,string"`
		}{
			{
				CurrentVersion: "",
				Epoch:          1,
			},
		},
	}
	return resp, nil
}

func (*MockMultiBeaconClient) GetRandao(slot uint64) (spec *GetRandaoResponse, err error) {
	return nil, nil
}

func (*MockMultiBeaconClient) GetWithdrawals(slot uint64) (spec *GetWithdrawalsResponse, err error) {
	resp := &GetWithdrawalsResponse{}                                            //nolint:exhaustruct
	resp.Data.Withdrawals = append(resp.Data.Withdrawals, &capella.Withdrawal{}) //nolint:exhaustruct
	return resp, nil
}
