package wasm

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/idena-network/idena-go/blockchain/attachments"
	"github.com/idena-network/idena-go/blockchain/types"
	"github.com/idena-network/idena-go/common"
	"github.com/idena-network/idena-go/common/eventbus"
	"github.com/idena-network/idena-go/config"
	"github.com/idena-network/idena-go/core/appstate"
	"github.com/idena-network/idena-go/crypto"
	models "github.com/idena-network/idena-wasm-binding/lib/protobuf"
	"github.com/stretchr/testify/require"
	dbm "github.com/tendermint/tm-db"
)

const (
	governanceInitialCID   = "bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm"
	governanceParameterCID = "bafyreiaabeekl424fqyy4psc7vqqvqjmgeid4lcrectvhn2lb3fbjlddmm"
	governanceMetricsEpoch = "7"
	governanceWasmGasLimit = uint64(612000000)
	governanceStakeAtoms   = "1000000000000000000"
)

type governanceRuntimeResult struct {
	contractAddress  string
	deployGas        uint64
	deployHash       string
	deployEvents     []string
	metricsGas       uint64
	metricsHash      string
	metricsEvents    []string
	stakeGas         uint64
	stakeHash        string
	stakeEvents      []string
	activationGas    uint64
	activationHash   string
	activationEvents []string
	pendingStake     string
	activeStake      string
	rejectedPayGas   uint64
	rejectedPayHash  string
	rejectedPayError string
	canonicalGas     uint64
	canonicalHash    string
	canonicalResult  string
	parameterGas     uint64
	parameterHash    string
	parameterResult  string
	parametersGas    uint64
	parametersHash   string
}

type governanceMetricsFixture struct {
	root         string
	state        string
	finalized    string
	reported     string
	trust        string
	sourceEpoch  string
	sourceHeight string
	sourceHash   string
}

type governanceStakeState struct {
	Active  string `json:"active"`
	Pending string `json:"pending"`
}

func TestGovernanceContractProductionRuntimeDeterminism(t *testing.T) {
	contractPath := os.Getenv("IDENA_GOVERNANCE_WASM")
	expectedDigest := os.Getenv("IDENA_GOVERNANCE_WASM_SHA256")
	require.NotEmpty(t, contractPath, "IDENA_GOVERNANCE_WASM is required")
	require.Regexp(t, "^[0-9a-f]{64}$", expectedDigest)

	metadata, err := os.Lstat(contractPath)
	require.NoError(t, err)
	require.True(t, metadata.Mode().IsRegular(), "contract must be a regular file")
	require.Zero(t, metadata.Mode()&os.ModeSymlink, "contract must not be a symlink")
	code, err := os.ReadFile(contractPath)
	require.NoError(t, err)
	digest := sha256.Sum256(code)
	require.Equal(t, expectedDigest, hex.EncodeToString(digest[:]))

	first := runGovernanceRuntimeFixture(t, code)
	second := runGovernanceRuntimeFixture(t, code)
	require.Equal(t, first, second)
	require.Equal(
		t,
		`{"ok":true,"canonicalEcosystemCid":"`+governanceInitialCID+`"}`,
		first.canonicalResult,
	)
	require.Equal(
		t,
		`{"ok":true,"governanceParameterSetCid":"`+governanceParameterCID+`"}`,
		first.parameterResult,
	)
	require.Len(t, first.deployEvents, 1)
	require.Contains(t, first.deployEvents[0], "GovernanceInitializedV1")
}

func runGovernanceRuntimeFixture(t *testing.T, code []byte) governanceRuntimeResult {
	t.Helper()
	database := dbm.NewMemDB()
	state, err := appstate.NewAppState(database, eventbus.New())
	require.NoError(t, err)
	state.Initialize(0)
	state.State.SetGlobalEpoch(7)

	random := rand.New(rand.NewSource(1))
	key, err := crypto.GenerateKeyFromSeed(random)
	require.NoError(t, err)
	metricsFixture := governanceMetricsForAddress(crypto.PubkeyToAddress(key.PublicKey))
	header := createHeader(42, 1234567)
	vm := NewWasmVM(state, nil, header, governanceRuntimeConfig(), true, nil)

	deployAttachment := attachments.CreateDeployContractAttachment(
		common.Hash{},
		code,
		nil,
		[]byte(governanceInitialCID),
		[]byte(governanceParameterCID),
		[]byte(metricsFixture.root),
		[]byte(governanceMetricsEpoch),
	)
	deployPayload, err := deployAttachment.ToBytes()
	require.NoError(t, err)
	deployTransaction := &types.Transaction{
		Epoch:        7,
		AccountNonce: 1,
		Type:         types.DeployContractTx,
		Payload:      deployPayload,
		Amount:       big.NewInt(0),
	}
	deployTransaction, err = types.SignTx(deployTransaction, key)
	require.NoError(t, err)
	deployReceipt := vm.Run(deployTransaction, governanceWasmGasLimit)
	require.True(t, deployReceipt.Success, "deployment failed: %v", deployReceipt.Error)
	require.Equal(t, code, state.State.GetContractCode(deployReceipt.ContractAddress))
	require.Equal(
		t,
		[]byte(governanceInitialCID),
		state.State.GetContractValue(deployReceipt.ContractAddress, []byte("governance:canonical-cid")),
	)

	metrics := callGovernanceRuntimeMethod(
		t, state, header, key, deployReceipt.ContractAddress, 2, 7, big.NewInt(0),
		"registerIdentityMetricsProof",
		[]byte(metricsFixture.state),
		[]byte(metricsFixture.finalized),
		[]byte(metricsFixture.reported),
		[]byte(metricsFixture.trust),
		[]byte(metricsFixture.sourceEpoch),
		[]byte(metricsFixture.sourceHeight),
		[]byte(metricsFixture.sourceHash),
		[]byte("0"),
		[]byte("1"),
		nil,
	)
	require.Contains(t, string(governanceRuntimeOutput(t, metrics)), metricsFixture.root)

	rejectedPayment := callGovernanceRuntimeMethodRaw(
		t, state, header, key, deployReceipt.ContractAddress, 3, 7, big.NewInt(1),
		"canonicalEcosystemCid",
	)
	require.False(t, rejectedPayment.Success, "read-only query accepted attached payment")
	require.Empty(t, rejectedPayment.Events)

	stakeAmount, ok := new(big.Int).SetString(governanceStakeAtoms, 10)
	require.True(t, ok)
	stake := callGovernanceRuntimeMethod(
		t, state, header, key, deployReceipt.ContractAddress, 4, 7, stakeAmount,
		"registerGovernanceStake",
	)
	require.Contains(t, string(governanceRuntimeOutput(t, stake)), `"activationEpoch":"8"`)
	pendingStakeReceipt := callGovernanceRuntimeMethod(
		t, state, header, key, deployReceipt.ContractAddress, 5, 7, big.NewInt(0),
		"governanceStakeState",
	)
	pendingStake := decodeGovernanceStakeState(t, governanceRuntimeOutput(t, pendingStakeReceipt))
	require.Equal(t, "0", pendingStake.Active)
	require.True(t, strings.HasPrefix(pendingStake.Pending, governanceStakeAtoms+"~8~"))

	activationHeader := createHeader(43, 1234568)
	state.State.SetGlobalEpoch(8)
	activation := callGovernanceRuntimeMethod(
		t, state, activationHeader, key, deployReceipt.ContractAddress, 6, 8, big.NewInt(0),
		"activateGovernanceStake",
	)
	require.Contains(t, string(governanceRuntimeOutput(t, activation)), `"activated":true`)
	activeStakeReceipt := callGovernanceRuntimeMethod(
		t, state, activationHeader, key, deployReceipt.ContractAddress, 7, 8, big.NewInt(0),
		"governanceStakeState",
	)
	activeStake := decodeGovernanceStakeState(t, governanceRuntimeOutput(t, activeStakeReceipt))
	require.Equal(t, governanceStakeAtoms, activeStake.Active)
	require.Empty(t, activeStake.Pending)

	canonical := callGovernanceRuntimeMethod(
		t, state, activationHeader, key, deployReceipt.ContractAddress, 8, 8, big.NewInt(0),
		"canonicalEcosystemCid",
	)
	parameter := callGovernanceRuntimeMethod(
		t, state, activationHeader, key, deployReceipt.ContractAddress, 9, 8, big.NewInt(0),
		"governanceParameterSetCid",
	)
	parameters := callGovernanceRuntimeMethod(
		t, state, activationHeader, key, deployReceipt.ContractAddress, 10, 8, big.NewInt(0),
		"governanceParameters",
	)
	canonicalOutput := governanceRuntimeOutput(t, canonical)
	parameterOutput := governanceRuntimeOutput(t, parameter)
	governanceRuntimeOutput(t, parameters)
	parametersDigest := sha256.Sum256(parameters.ActionResult)
	rejectedError := ""
	if rejectedPayment.Error != nil {
		rejectedError = rejectedPayment.Error.Error()
	}

	return governanceRuntimeResult{
		contractAddress:  deployReceipt.ContractAddress.Hex(),
		deployGas:        deployReceipt.GasUsed,
		deployHash:       governanceReceiptHash(deployReceipt),
		deployEvents:     governanceEventSummaries(deployReceipt.Events),
		metricsGas:       metrics.GasUsed,
		metricsHash:      governanceReceiptHash(metrics),
		metricsEvents:    governanceEventSummaries(metrics.Events),
		stakeGas:         stake.GasUsed,
		stakeHash:        governanceReceiptHash(stake),
		stakeEvents:      governanceEventSummaries(stake.Events),
		activationGas:    activation.GasUsed,
		activationHash:   governanceReceiptHash(activation),
		activationEvents: governanceEventSummaries(activation.Events),
		pendingStake:     pendingStake.Pending,
		activeStake:      activeStake.Active,
		rejectedPayGas:   rejectedPayment.GasUsed,
		rejectedPayHash:  governanceReceiptHash(rejectedPayment),
		rejectedPayError: rejectedError,
		canonicalGas:     canonical.GasUsed,
		canonicalHash:    governanceReceiptHash(canonical),
		canonicalResult:  string(canonicalOutput),
		parameterGas:     parameter.GasUsed,
		parameterHash:    governanceReceiptHash(parameter),
		parameterResult:  string(parameterOutput),
		parametersGas:    parameters.GasUsed,
		parametersHash:   hex.EncodeToString(parametersDigest[:]),
	}
}

func governanceReceiptHash(receipt *types.TxReceipt) string {
	digest := sha256.Sum256(receipt.ActionResult)
	return hex.EncodeToString(digest[:])
}

func governanceRuntimeOutput(t *testing.T, receipt *types.TxReceipt) []byte {
	t.Helper()
	result := new(models.ActionResult)
	require.NoError(t, proto.Unmarshal(receipt.ActionResult, result))
	require.True(t, result.Success, "runtime action failed: %s", result.Error)
	require.Empty(t, result.SubActionResults)
	require.Equal(t, receipt.ContractAddress.Bytes(), result.Contract)
	return result.OutputData
}

func callGovernanceRuntimeMethod(
	t *testing.T,
	state *appstate.AppState,
	header *types.Header,
	key *ecdsa.PrivateKey,
	contract common.Address,
	nonce uint32,
	epoch uint16,
	amount *big.Int,
	method string,
	args ...[]byte,
) *types.TxReceipt {
	t.Helper()
	receipt := callGovernanceRuntimeMethodRaw(
		t, state, header, key, contract, nonce, epoch, amount, method, args...,
	)
	require.True(t, receipt.Success, "%s failed: %v", method, receipt.Error)
	return receipt
}

func callGovernanceRuntimeMethodRaw(
	t *testing.T,
	state *appstate.AppState,
	header *types.Header,
	key *ecdsa.PrivateKey,
	contract common.Address,
	nonce uint32,
	epoch uint16,
	amount *big.Int,
	method string,
	args ...[]byte,
) *types.TxReceipt {
	t.Helper()
	attachment := attachments.CreateCallContractAttachment(method, args...)
	payload, err := attachment.ToBytes()
	require.NoError(t, err)
	transaction := &types.Transaction{
		Epoch:        epoch,
		AccountNonce: nonce,
		To:           &contract,
		Type:         types.CallContractTx,
		Payload:      payload,
		Amount:       new(big.Int).Set(amount),
	}
	transaction, err = types.SignTx(transaction, key)
	require.NoError(t, err)
	vm := NewWasmVM(state, nil, header, governanceRuntimeConfig(), true, nil)
	return vm.Run(transaction, governanceWasmGasLimit)
}

func decodeGovernanceStakeState(t *testing.T, output []byte) governanceStakeState {
	t.Helper()
	state := governanceStakeState{}
	require.NoError(t, json.Unmarshal(output, &state))
	return state
}

func governanceMetricsForAddress(address common.Address) governanceMetricsFixture {
	fixture := governanceMetricsFixture{
		state:        "Human",
		finalized:    "0",
		reported:     "0",
		trust:        "9250",
		sourceEpoch:  governanceMetricsEpoch,
		sourceHeight: "41",
		sourceHash:   strings.Repeat("11", 32),
	}
	payload := make([]byte, 0, 128)
	payload = append(payload, []byte("IDENA_GOV_METRICS_V1\x00")...)
	payload = append(payload, address.Bytes()...)
	payload = append(payload, byte(3))
	payload = appendUint64(payload, 0)
	payload = appendUint64(payload, 0)
	payload = appendUint16(payload, 9250)
	payload = appendUint16(payload, 7)
	payload = appendUint64(payload, 41)
	sourceHash, err := hex.DecodeString(fixture.sourceHash)
	if err != nil {
		panic(err)
	}
	payload = append(payload, sourceHash...)
	leaf := sha256.Sum256(payload)
	rootPayload := make([]byte, 0, 64)
	rootPayload = append(rootPayload, []byte("IDENA_GOV_METRICS_ROOT_V1\x00")...)
	rootPayload = appendUint64(rootPayload, 1)
	rootPayload = append(rootPayload, leaf[:]...)
	root := sha256.Sum256(rootPayload)
	fixture.root = hex.EncodeToString(root[:])
	return fixture
}

func appendUint64(target []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(target, encoded[:]...)
}

func appendUint16(target []byte, value uint16) []byte {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	return append(target, encoded[:]...)
}

func governanceRuntimeConfig() *config.Config {
	configuration := getLatestConfig()
	configuration.IsDebug = false
	return configuration
}

func governanceEventSummaries(events []*types.TxEvent) []string {
	result := make([]string, 0, len(events))
	for _, event := range events {
		result = append(result, fmt.Sprintf("%s:%x:%x", event.EventName, event.Contract[:], event.Data))
	}
	return result
}
