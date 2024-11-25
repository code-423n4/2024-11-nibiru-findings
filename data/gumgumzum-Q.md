## Summary
### Low Risk

|      | Title                                                                                            |
| ---- | ------------------------------------------------------------------------------------------------ |
| L-01 | Unclosed Iterator in `IterateEpochInfo`                                                          |
| L-02 | `EmitEthereumTxEvents` assumes that calls with data only target contracts                        |
| L-03 | `EmitEthereumTxEvents` assumes that contract creation calls and calls to contracts have no value |
| L-04 | Foundry `cast` fails to get transaction receipts                                                 |

## Low Risks
### L-01 | Unclosed Iterator in `IterateEpochInfo`

**Issue Description:**

Unless `Keys`, `Values`, `KeyValues` or `Walk` are used, an Iterator must be explicitly closed by the caller.
This is not the case in `IterateEpochInfo` which is used in the `epoch` module `BeginBlocker` and lacks a `defer iterate.Close()` call and might lead to increasing resource consumptions.

[x/epochs/keeper/epoch.go](https://github.com/code-423n4/2024-11-nibiru/blob/main/x/epochs/keeper/epoch.go#L62-L78)

```golang
func (k Keeper) IterateEpochInfo(
	ctx sdk.Context,
	fn func(index int64, epochInfo types.EpochInfo) (stop bool),
) {
	iterate := k.Epochs.Iterate(ctx, &collections.Range[string]{}) <@
	i := int64(0)

	for ; iterate.Valid(); iterate.Next() {
		epoch := iterate.Value()
		stop := fn(i, epoch)

		if stop {
			break
		}
		i++
	}
}
```
### L-02 | `EmitEthereumTxEvents` assumes that calls with data only target contracts 

**Issue Description:**

If the call has data, `EmitEthereumTxEvents` emits a `EventContractExecuted` event with the target as the `ContractAddress`, however it is possible to have simple transfers that have data associated with them (.e.g inscriptions).

[x/evm/keeper/msg_server.go](https://github.com/code-423n4/2024-11-nibiru/blob/main/x/evm/keeper/msg_server.go#L627C18-L687)

```golang
func (k *Keeper) EmitEthereumTxEvents(
	ctx sdk.Context,
	recipient *gethcommon.Address,
	txType uint8,
	msg gethcore.Message,
	evmResp *evm.MsgEthereumTxResponse,
) error {
	// ...
	if !evmResp.Failed() {
		if recipient == nil { // contract creation
			contractAddr := crypto.CreateAddress(msg.From(), msg.Nonce())
			_ = ctx.EventManager().EmitTypedEvent(&evm.EventContractDeployed{
				Sender:       msg.From().Hex(),
				ContractAddr: contractAddr.String(),
			})
		} else if len(msg.Data()) > 0 { // contract executed
			_ = ctx.EventManager().EmitTypedEvent(&evm.EventContractExecuted{ <@
				Sender:       msg.From().Hex(),
				ContractAddr: msg.To().String(), <@
			})
		} else if msg.Value().Cmp(big.NewInt(0)) > 0 { // evm transfer
			_ = ctx.EventManager().EmitTypedEvent(&evm.EventTransfer{
				Sender:    msg.From().Hex(),
				Recipient: msg.To().Hex(),
				Amount:    msg.Value().String(),
			})
		}
	}

	return nil
}
```

### L-03 | `EmitEthereumTxEvents` assumes that contract creation calls and calls to contracts have no value

**Issue Description:**

Contract creation calls and contracts call can have value but the `Amount` is missing in the events emitted  in those cases.

[x/evm/keeper/msg_server.go](https://github.com/code-423n4/2024-11-nibiru/blob/main/x/evm/keeper/msg_server.go#L627C18-L687)

```golang
func (k *Keeper) EmitEthereumTxEvents(
	ctx sdk.Context,
	recipient *gethcommon.Address,
	txType uint8,
	msg gethcore.Message,
	evmResp *evm.MsgEthereumTxResponse,
) error {
	// ...
	if !evmResp.Failed() {
		if recipient == nil { // contract creation
			contractAddr := crypto.CreateAddress(msg.From(), msg.Nonce())
			_ = ctx.EventManager().EmitTypedEvent(&evm.EventContractDeployed{ <@
				Sender:       msg.From().Hex(),
				ContractAddr: contractAddr.String(),
			})
		} else if len(msg.Data()) > 0 { // contract executed
			_ = ctx.EventManager().EmitTypedEvent(&evm.EventContractExecuted{ <@
				Sender:       msg.From().Hex(),
				ContractAddr: msg.To().String(),
			})
		} else if msg.Value().Cmp(big.NewInt(0)) > 0 { // evm transfer
			_ = ctx.EventManager().EmitTypedEvent(&evm.EventTransfer{
				Sender:    msg.From().Hex(),
				Recipient: msg.To().Hex(),
				Amount:    msg.Value().String(),
			})
		}
	}

	return nil
}
```

### L-04 | Foundry `cast` fails to get transaction receipts

**Issue Description:**

Getting a transaction receipt using `cast` fails due to a deserialization error. The following happens for a simple transfer transaction.

```console
❯ cast receipt 0xf967159085d71d8c026578f1e699418a44e88ef705c8c42aa8be4345ae3219a6
Error:
deserialization error: Invalid string length at line 1 column 1043

Context:
- Invalid string length at line 1 column 1043
```