# 0xMonaco (93.4/1500 points 6th place (1478.4 ELO), F1)

Solved by: Kaiziron

Team: D53_H473r5  (6th place out of 127)

### Description :
```
DESCRIPTION
Max Verstappen's favorite smart contract. The points for this challenge will be allocated at the end of the CTF. See "How to Play" for more info

ACCESS
https://0xmonaco.ctf.paradigm.xyz/

RESOURCES
https://github.com/paradigmxyz/paradigm-ctf-infrastructure
/resources/0xmonaco.zip
```

This challenge is too complex, so I won't explain it here, just read this : https://0xmonaco.ctf.paradigm.xyz/howtoplay

I am looking forward to see the official "writeup car" by paradigm. Hope they will have it after they release their writeups.

This challenge is about competing with other participants' car contract, and my car contract got 6th place at the end : 

![](https://i.imgur.com/P2WvY85.png)


### My car contract that got me 6th place (I know my contract is bad) :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.13;

import "./Car.sol";

contract ExampleCar is Car {
    constructor(Monaco _monaco) Car(_monaco) {}

    function takeYourTurn(Monaco.CarData[] calldata allCars, uint256 ourCarIndex) external override {
        Monaco.CarData memory ourCar = allCars[ourCarIndex];
        
        
        if (ourCarIndex != 0 && allCars[ourCarIndex - 1].y > 800) {
            if (ourCar.speed < 20) {
                 if (ourCar.balance > monaco.getAccelerateCost(20 - ourCar.speed)) ourCar.balance -= uint24(monaco.buyAcceleration(20 - ourCar.speed));
            }
        } else if (ourCarIndex != 0) {
            if (ourCar.speed < 12) {
                 if (ourCar.balance > monaco.getAccelerateCost(12 - ourCar.speed)) ourCar.balance -= uint24(monaco.buyAcceleration(12 - ourCar.speed));
            }
        }
        
        if (ourCarIndex != 0 && allCars[ourCarIndex - 1].speed > ourCar.speed ) {
            if (ourCar.speed < 5) {
                if (ourCar.balance > monaco.getAccelerateCost(4)) ourCar.balance -= uint24(monaco.buyAcceleration(4));
            } else if (ourCar.speed > 20) {
            } else if (ourCar.speed < 4) {
                if (ourCar.balance > monaco.getAccelerateCost(12)) ourCar.balance -= uint24(monaco.buyAcceleration(12));
            } else {
                if (ourCar.balance > monaco.getAccelerateCost(3)) ourCar.balance -= uint24(monaco.buyAcceleration(3));
            }
        }

        if (ourCarIndex == 2 && allCars[ourCarIndex - 2].y > (ourCar.y + 200) ) {
            if (ourCar.balance > monaco.getAccelerateCost(12)) ourCar.balance -= uint24(monaco.buyAcceleration(12));
        }

        if (ourCarIndex == 1 && allCars[ourCarIndex - 1].y > (ourCar.y + 100) ) {
            if (ourCar.balance > monaco.getAccelerateCost(12)) ourCar.balance -= uint24(monaco.buyAcceleration(12));
        }

        if (ourCarIndex != 0 && allCars[ourCarIndex - 1].speed > 8 && ourCar.balance > monaco.getShellCost(1) && monaco.getShellCost(1) < 300) {
            monaco.buyShell(1); 
        } else if (ourCarIndex != 0 && ourCar.balance > monaco.getShellCost(1) && monaco.getShellCost(1) < 40) {
            monaco.buyShell(1); 
        } else if (ourCarIndex != 0 && ourCar.balance > monaco.getShellCost(1) && allCars[ourCarIndex - 1].y > 800) {
            monaco.buyShell(1);
        }

    }
}
```
