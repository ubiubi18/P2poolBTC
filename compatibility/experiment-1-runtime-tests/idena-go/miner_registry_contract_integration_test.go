package wasm

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/idena-network/idena-go/blockchain/attachments"
	"github.com/idena-network/idena-go/blockchain/types"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/common/eventbus"
	"github.com/idena-network/idena-go/core/appstate"
	"github.com/idena-network/idena-go/core/state"
	"github.com/idena-network/idena-go/crypto"
	models "github.com/idena-network/idena-wasm-binding/lib/protobuf"
	"github.com/stretchr/testify/require"
	dbm "github.com/tendermint/tm-db"
)

const registryRuntimeWasmGasLimit = uint64(1_000_000_000)

type registryRuntimeObservation struct {
	contractAddress  common.Address
	parameters       string
	validRecord      string
	registeredCount  string
	registeredSet    string
	invalidRecord    []byte
	invalidPending   []byte
	staleVotePending []byte
	checkpointRecord string
	invalidBalance   *big.Int
	contractBalance  *big.Int
	validEvents      []string
	invalidEvents    []string
	staleVoteEvents  []string
	checkpointEvents []string
}

func TestPohwMinerRegistryProductionRuntimeIdentityGate(t *testing.T) {
	contractPath := os.Getenv("IDENA_POHW_MINER_REGISTRY_WASM")
	if contractPath == "" {
		t.Skip("set IDENA_POHW_MINER_REGISTRY_WASM and IDENA_POHW_MINER_REGISTRY_WASM_SHA256 to run the runtime gate")
	}
	expectedSHA256 := os.Getenv("IDENA_POHW_MINER_REGISTRY_WASM_SHA256")
	require.Len(t, expectedSHA256, 64)
	code, err := os.ReadFile(contractPath)
	require.NoError(t, err)
	digest := sha256.Sum256(code)
	require.Equal(t, expectedSHA256, hex.EncodeToString(digest[:]))

	first := runRegistryRuntimeScenario(t, code)
	second := runRegistryRuntimeScenario(t, code)
	require.Equal(t, first, second, "production runtime registration must be deterministic")
	require.Contains(t, first.parameters, `"schemaVersion":3`)
	require.Contains(t, first.parameters, `"contractVersion":"0.3.0"`)
	require.Contains(t, first.parameters, `"eligibleIdentityStates":["Newbie","Verified","Human"]`)
	require.Equal(t, "1", first.registeredCount)
	require.Equal(t, "genesis-01", first.registeredSet)
	require.Equal(t, `1|genesis-01|aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa|1|100|0|1700000000`, first.validRecord)
	require.Empty(t, first.invalidRecord)
	require.Empty(t, first.invalidPending)
	require.Empty(t, first.staleVotePending)
	require.Contains(t, first.checkpointRecord, `1|1|1111111111111111111111111111111111111111111111111111111111111111|12|345|`)
	require.Equal(t, big.NewInt(1000), first.invalidBalance)
	require.Equal(t, big.NewInt(98_000), first.contractBalance)
	require.Contains(t, first.validEvents, "PohwMinerRegisteredV1")
	require.Contains(t, first.invalidEvents, "PohwMinerRegRefundedV1")
	require.Contains(t, first.staleVoteEvents, "PohwCheckpointVoteRejectedV1")
	require.Contains(t, first.checkpointEvents, "PohwCheckpointFinalizedV1")
}

func runRegistryRuntimeScenario(t *testing.T, code []byte) registryRuntimeObservation {
	t.Helper()
	database := dbm.NewMemDB()
	appState, err := appstate.NewAppState(database, eventbus.New())
	require.NoError(t, err)
	appState.Initialize(0)

	validKey, err := crypto.GenerateKeyFromSeed(rand.New(rand.NewSource(101)))
	require.NoError(t, err)
	invalidKey, err := crypto.GenerateKeyFromSeed(rand.New(rand.NewSource(102)))
	require.NoError(t, err)
	validAddress := crypto.PubkeyToAddress(validKey.PublicKey)
	invalidAddress := crypto.PubkeyToAddress(invalidKey.PublicKey)
	appState.State.SetState(validAddress, state.Human)
	appState.State.SetState(invalidAddress, state.Candidate)

	vm := NewWasmVM(appState, nil, registryRuntimeHeader(100, 1_700_000_000), getLatestConfig(), true, nil)
	validNonce := uint32(1)
	invalidNonce := uint32(1)
	deployAttachment := attachments.CreateDeployContractAttachment(
		common.Hash{},
		code,
		nil,
		[]byte("p2poolbtc-experiment-1"),
		[]byte("bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm"),
		[]byte("1000"),
	)
	deployPayload, err := deployAttachment.ToBytes()
	require.NoError(t, err)
	deployTx, err := types.SignTx(&types.Transaction{
		Epoch:        0,
		AccountNonce: validNonce,
		Type:         types.DeployContractTx,
		Payload:      deployPayload,
		Amount:       big.NewInt(0),
	}, validKey)
	require.NoError(t, err)
	validNonce++
	deployReceipt := vm.Run(deployTx, registryRuntimeWasmGasLimit)
	require.True(t, deployReceipt.Success, "registry deploy failed: %v", deployReceipt.Error)
	contract := deployReceipt.ContractAddress
	appState.State.SetBalance(contract, big.NewInt(100_000))

	validReceipt := callRegistryRuntimeMethod(
		t,
		vm,
		validKey,
		&validNonce,
		contract,
		"registerMiner",
		big.NewInt(1000),
		[]byte("genesis-01"),
		[]byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	)
	require.JSONEq(t, `{"address":"0x`+hex.EncodeToString(validAddress.Bytes())+`","minerId":"genesis-01","ok":true,"pending":true}`, string(registryRuntimeOutput(t, validReceipt)))

	invalidReceipt := callRegistryRuntimeMethod(
		t,
		vm,
		invalidKey,
		&invalidNonce,
		contract,
		"registerMiner",
		big.NewInt(1000),
		[]byte("candidate"),
		[]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
	)
	require.JSONEq(t, `{"address":"0x`+hex.EncodeToString(invalidAddress.Bytes())+`","minerId":"candidate","ok":true,"pending":true}`, string(registryRuntimeOutput(t, invalidReceipt)))

	vm.head = registryRuntimeHeader(101, 1_700_000_020)
	appState.State.SetState(validAddress, state.Candidate)
	staleVoteReceipt := callRegistryRuntimeMethod(
		t,
		vm,
		validKey,
		&validNonce,
		contract,
		"voteCheckpoint",
		big.NewInt(0),
		[]byte("1"),
		[]byte("1111111111111111111111111111111111111111111111111111111111111111"),
		[]byte("12"),
		[]byte("345"),
		[]byte("0000000000000000000000000000000000000000000000000000000000000000"),
	)
	require.Contains(t, string(registryRuntimeOutput(t, staleVoteReceipt)), `"pending":true`)
	require.Empty(t, appState.State.GetContractValue(contract, []byte("checkpoint:final:1")))

	appState.State.SetState(validAddress, state.Human)
	checkpointReceipt := callRegistryRuntimeMethod(
		t,
		vm,
		validKey,
		&validNonce,
		contract,
		"voteCheckpoint",
		big.NewInt(0),
		[]byte("1"),
		[]byte("1111111111111111111111111111111111111111111111111111111111111111"),
		[]byte("12"),
		[]byte("345"),
		[]byte("0000000000000000000000000000000000000000000000000000000000000000"),
	)
	require.Contains(t, string(registryRuntimeOutput(t, checkpointReceipt)), `"pending":true`)

	parametersReceipt := callRegistryRuntimeMethod(
		t,
		vm,
		validKey,
		&validNonce,
		contract,
		"contractParameters",
		big.NewInt(0),
	)
	validRecordKey := []byte("miner:" + hex.EncodeToString(validAddress.Bytes()) + ":1")
	invalidRecordKey := []byte("miner:" + hex.EncodeToString(invalidAddress.Bytes()) + ":1")
	invalidPendingKey := []byte("pending:identity:" + hex.EncodeToString(invalidAddress.Bytes()))
	staleVotePendingKey := []byte("pending:checkpoint:" + hex.EncodeToString(validAddress.Bytes()))

	return registryRuntimeObservation{
		contractAddress:  contract,
		parameters:       string(registryRuntimeOutput(t, parametersReceipt)),
		validRecord:      string(appState.State.GetContractValue(contract, validRecordKey)),
		registeredCount:  string(appState.State.GetContractValue(contract, []byte("registry:registered-count"))),
		registeredSet:    string(appState.State.GetContractValue(contract, []byte("registry:registered-miners"))),
		invalidRecord:    append([]byte(nil), appState.State.GetContractValue(contract, invalidRecordKey)...),
		invalidPending:   append([]byte(nil), appState.State.GetContractValue(contract, invalidPendingKey)...),
		staleVotePending: append([]byte(nil), appState.State.GetContractValue(contract, staleVotePendingKey)...),
		checkpointRecord: string(appState.State.GetContractValue(contract, []byte("checkpoint:final:1"))),
		invalidBalance:   new(big.Int).Set(appState.State.GetBalance(invalidAddress)),
		contractBalance:  new(big.Int).Set(appState.State.GetBalance(contract)),
		validEvents:      registryRuntimeEvents(validReceipt),
		invalidEvents:    registryRuntimeEvents(invalidReceipt),
		staleVoteEvents:  registryRuntimeEvents(staleVoteReceipt),
		checkpointEvents: registryRuntimeEvents(checkpointReceipt),
	}
}

func callRegistryRuntimeMethod(
	t *testing.T,
	vm *WasmVM,
	key *ecdsa.PrivateKey,
	nonce *uint32,
	contract common.Address,
	method string,
	amount *big.Int,
	args ...[]byte,
) *types.TxReceipt {
	t.Helper()
	attachment := attachments.CreateCallContractAttachment(method, args...)
	payload, err := attachment.ToBytes()
	require.NoError(t, err)
	tx, err := types.SignTx(&types.Transaction{
		Epoch:        0,
		AccountNonce: *nonce,
		To:           &contract,
		Type:         types.CallContractTx,
		Payload:      payload,
		Amount:       new(big.Int).Set(amount),
	}, key)
	require.NoError(t, err)
	*nonce++
	receipt := vm.Run(tx, registryRuntimeWasmGasLimit)
	require.True(t, receipt.Success, "%s failed: %v", method, receipt.Error)
	return receipt
}

func registryRuntimeOutput(t *testing.T, receipt *types.TxReceipt) []byte {
	t.Helper()
	result := &models.ActionResult{}
	require.NoError(t, proto.Unmarshal(receipt.ActionResult, result))
	require.True(t, result.Success, "runtime action failed: %s", result.Error)
	return append([]byte(nil), result.OutputData...)
}

func registryRuntimeEvents(receipt *types.TxReceipt) []string {
	result := make([]string, 0, len(receipt.Events))
	for _, event := range receipt.Events {
		result = append(result, event.EventName)
	}
	return result
}

func registryRuntimeHeader(height uint64, timestamp int64) *types.Header {
	seed := types.Seed{}
	seed.SetBytes(common.ToBytes(height))
	return &types.Header{ProposedHeader: &types.ProposedHeader{
		BlockSeed: seed,
		Height:    height,
		Time:      timestamp,
	}}
}
