# RANDOM (115.6 points, sanity check)

Solved by: Kaiziron

Team: D53_H473r5 

### Description :
```
DESCRIPTION
I'm thinking of a number between 4 and 4


ACCESS
nc 34.66.135.107 31337

RESOURCES
https://github.com/paradigmxyz/paradigm-ctf-infrastructure
/resources/random.zip
```

This challenge is just a sanity check, just call the function `solve()` with 4 to solve it.

### Contract :
```solidity
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.15;

contract Random {

    bool public solved = false;

    function _getRandomNumber() internal pure returns (uint256) {   // chosen by fair dice roll.
        return 4;                                                   // guaranteed to be random.
    }
    
    function solve(uint256 guess) public {
        require(guess == _getRandomNumber());
        solved = true;
    }
}
```

`_getRandomNumber()` return a fixed number of `4`, so just call `solve()` with 4 to set `solved` to `true`.



### Flag :
```
nc 34.66.135.107 31337
1 - launch new instance
2 - kill instance
3 - get flag
action? 3

PCTF{IT5_C7F_71M3}
```