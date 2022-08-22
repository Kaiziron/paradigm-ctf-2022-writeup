# RIDDLE-OF-THE-SPHINX (172.1 points, sanity check)

Solved by: Kaiziron

Team: D53_H473r5

### Description :
```
DESCRIPTION
What walks on four legs in the morning, two legs in the afternoon, three legs in the evening, and no legs at night?


ACCESS
nc 35.193.19.12 31337


RESOURCES
https://github.com/paradigmxyz/paradigm-ctf-infrastructure
/resources/riddle-of-the-sphinx.zip
```

This challenge is just a sanity check, just call the function `solve()` with "man" to solve it. Nothing about this challenge is hard, except interacting with the starknet protocol. At first I tried to use `starknet.js`, however the documentation is confusing, so I use `starknet.py` instead, which has a much better documentation.

### Contract :
```
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

@storage_var
func _solution() -> (res : felt):
end

@external
func solve{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}(solution : felt):
    _solution.write(solution)
    return ()
end

@view
func solution{
    syscall_ptr : felt*,
    pedersen_ptr : HashBuiltin*,
    range_check_ptr,
}() -> (solution : felt):
    let (solution) = _solution.read()
    return (solution)
end
```

On the deploy script `chal.py`, the solution of "man" is shown : 
```
async def checker(client: AccountClient, riddle_contract: Contract, player_address: int) -> bool:
    solution = (await riddle_contract.functions["solution"].call()).solution

    return to_bytes(solution).lstrip(b"\x00") == b"man"
```

Then just write a script to call `solve()` function : 

```python
from starknet_py.net.gateway_client import GatewayClient
from starknet_py.net.models import StarknetChainId
from starknet_py.net import AccountClient, KeyPair
from starknet_py.contract import Contract
from starkware.starknet.core.os.contract_address.contract_address import calculate_contract_address_from_hash
from starkware.crypto.signature.signature import private_to_stark_key

client = GatewayClient("http://7e1b946f-56ad-471d-9dff-01c25caa4dd8@35.193.19.12:5050", chain=StarknetChainId.TESTNET)

pri_key = 0x66296dc15d074261fed61295a03e560d
pub_key = private_to_stark_key(pri_key)

player_address = calculate_contract_address_from_hash(salt=20, class_hash=1803505466663265559571280894381905521939782500874858933595227108099796801620, constructor_calldata=[pub_key], deployer_address=0)

acc_client = AccountClient(
    client=client,
    address=player_address,
    key_pair = KeyPair.from_private_key(key=pri_key)
)

contract_address = ("0x64e148a4ba6e2a42412f3f728191892a87dc544f59df1ab907e07a9f07b9e7c")

abi = [{"inputs":[{"name":"solution","type":"felt"}],"name":"solve","outputs":[],"type":"function"},{"inputs":[],"name":"solution","outputs":[{"name":"solution","type":"felt"}],"stateMutability":"view","type":"function"}]

contract = Contract(
    contract_address,
    abi,
    acc_client,
)

invocation = contract.functions["solve"].invoke_sync("man", max_fee=int(1e16))

print(invocation)
```


### Flag :
```
nc 35.193.19.12 31337
running until complete
1 - launch new instance
2 - kill instance
3 - get flag
action? 3

PCTF{600D_1UCK_H4V3_FUN}
```