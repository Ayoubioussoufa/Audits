# 🛡️ Smart Contract Security Report – [Beatland Festival](https://github.com/CodeHawks-Contests/2025-07-beatland-festival)

## 🔧 Tools Used
- 🔍 **Slither** – Static analysis and vulnerability detection  
- 🐦 **Aderyn** – Cross-verification of known smart contract issues  
- 🔨 **Foundry** – Testing, fuzzing, and custom Proof-of-Concepts (PoCs)

# Table of Contents

- [Table of Contents](#table-of-contents)
- [Summary](#summary)
	- [Files Summary](#files-summary)
	- [Files Details](#files-details)
	- [Issue Summary](#issue-summary)
-  [Medium Issues](#medium-issues)
-  [Low Issues](#low-issues)

# Summary

## Files Summary

| Key | Value |
| --- | --- |
| .sol Files | 3 |
| Total nSLOC | 291 |


## Files Details

| Filepath | nSLOC |
| --- | --- |
| src/BeatToken.sol | 20 |
| src/FestivalPass.sol | 217 |
| src/Interfaces/IFestivalPass.sol | 54 |
| **Total** | **291** |

## Issue Summary

| Category | No. of Issues |
| --- | --- |
| Medium | 1 |
| Low | 3 |

## Medium Issues

### [M-1] Inconsistent Access Control Comments and Event Naming in `FestivalPass::withdraw` function.

**Description:** The `FestivalPass::withdraw` function uses the `onlyOwner` modifier (correctly enforcing that only the contract owner can withdraw ETH). However, the inline comment (`// Organizer withdraws ETH`) and the emitted event (`IFestivalPass::FundsWithdrawn(address organizer, uint256 amount)`) imply that the **organizer**, not the owner, is the authorized actor.
This mismatch between the code and the documentation/comments may lead to confusion or misimplementation in the frontend or by other developers.

**Impact:**
- Developers may incorrectly assume the `organizer` can withdraw ETH.
- Event consumers (e.g. analytics, frontend) might mislabel the withdrawer as the `organizer`.
- While **no unauthorized access occurs**, the inconsistent naming and documentation pose **a medium risk to system clarity and maintainability**.

**Proof of Concept:** Add this to your FestivalPass.t.sol:

```solidity
function test_organizerWithdrawEth() public {
        // To not query balance of address(0) or a weird corrupted pointer
        vm.deal(owner, 0 ether);
        uint256 startTime = block.timestamp + 30 minutes;
        uint256 duration = 2 hours;
        uint256 reward = 100e18;
        
        vm.prank(organizer);
        uint256 perfId = festivalPass.createPerformance(startTime, duration, reward);
        assertEq(perfId, 0);
        vm.prank(user1);
        // BACKSTAGE_PASS = 0.25 ether
        festivalPass.buyPass{value: BACKSTAGE_PRICE}(3);

        vm.prank(organizer);
        vm.expectRevert();
        // reverts because the owner isn't the organizer
        festivalPass.withdraw(organizer);
        assertEq(address(organizer).balance, 0 ether);

        vm.prank(owner);
        festivalPass.withdraw(owner);
        assertEq(address(owner).balance, 0.25 ether);   
    }

    // This allows the test contract to receive ETH via .transfer() or .call{value:...}.
    receive() external payable {}
```

The following test demonstrates that the `FestivalPass::withdraw` function allows the owner to withdraw ETH, even though the in-code comment implies the organizer should be authorized.

**Recommended Mitigation:**  Choose one of the following, depending on the intended business logic:

If only the owner should withdraw, rename the event to FundsWithdrawn(address owner, uint256 amount) and correct the inline comment.

If the organizer is the true withdrawer, change the modifier to onlyOrganizer.

Most importantly, ensure the code, comments, and interface all reflect the same authorized role to avoid confusion.

# Low Issues

### [L-1] Inefficient Iteration Over Unused Collection IDs in `FestivalPass::getUserMemorabiliaDetailed`.

**Description:** The `FestivalPass::getUserMemorabiliaDetailed` function loops from `cId = 1` to `cId < nextCollectionId` even though the contract initializes `FestivalPass::nextCollectionId = 100`. This results in 99 unnecessary iterations over uninitialized `FestivalPass::collectections[cId]` entries. Since each iteration involves a nested loop and multiple balanceOf and `FestivalPass::encodeTokenId` calls, this adds significant overhead to what is expected to be a lightweight view function.

**Impact:** While this does not affect the correctness of the function or user balances, it:

* Wastes gas in view simulations.

* Slows down frontend responsiveness.

* May lead to out-of-gas errors in off-chain tools or future on-chain calls if scaled further.

**Proof of Concept:** Add this into the FestivalPass.t.sol :

```solidity
function test_GasUsedIngetUserMemorabiliaDetailed() public {
    // Record gas before the function call
    uint firstGas = gasleft();

    // Call the function and store the returned arrays
    (uint256[] memory tokenIds, uint256[] memory collectionIds, uint256[] memory itemIds) = festivalPass.getUserMemorabiliaDetailed(user2);

    // Record gas after the function call
    uint secondGas = gasleft();

    // Log gas before, after, and total gas used
    console.log("Gas first:", firstGas);
    console.log("Gas after:", secondGas);
    console.log("Gas consummed:", firstGas - secondGas);
}
```

This test measures how much gas is used when calling `FestivalPass::getUserMemorabiliaDetailed(user2)` by checking the gas before and after the call, then logging the difference. It's useful to see how expensive the function is.
Gas usage for a sample view call reached \~286,000 even without a valid collection.

**Recommended Mitigation:** Update the loop to start from the actual collection start ID:

```diff
-   for (uint256 cId = 1; cId < nextCollectionId; cId++) {
+   for (uint256 cId = 100; cId < nextCollectionId; cId++) {
```

Alternatively, refactor the initial value of `FestivalPass::nextCollectionId`:

```diff
-    uint256 public nextCollectionId = 100;
+    uint256 public nextCollectionId = 1;
```

Additionally, refactor `FestivalPass::getUserMemorabiliaDetailed` to eliminate the two-pass array allocation pattern and avoid redundant memory copying. A single-pass solution using inline assembly can significantly reduce memory operations and improve execution efficiency. This approach minimizes memory overhead, eliminates unnecessary condition checks, and scales better with user holdings especially in read-heavy environments like off-chain calls or dashboards.

```solidity
function getUserMemorabiliaDetailed(address user)
    external
    view
    returns (uint256[] memory tokenIds, uint256[] memory collectionIds, uint256[] memory itemIds)
{
    uint256 start = 100;
    uint256 max = nextCollectionId;

    // Preallocate a large enough buffer in memory manually via assembly
    uint256 maxSlots = 1000; // max collectibles a user can own (adjust safely)

    assembly {
        // Allocate memory for 3 arrays: tokenIds, collectionIds, itemIds
        let ptr := mload(0x40) // Free memory pointer

        // Reserve space for lengths + 3 arrays
        // Format: [len][data ...] [len][data ...] [len][data ...]
        // Each length takes 32 bytes; each data element takes 32 bytes

        mstore(ptr, 0) // tokenIds length = 0
        mstore(add(ptr, add(32, mul(maxSlots, 32))), 0) // collectionIds length = 0
        mstore(add(ptr, add(64, mul(maxSlots, 64))), 0) // itemIds length = 0
    }

    uint256 found = 0;

    for (uint256 cId = start; cId < max; ++cId) {
        uint256 itemCount = collections[cId].currentItemId;
        for (uint256 iId = 0; iId < itemCount; ++iId) {
            uint256 tokenId = encodeTokenId(cId, iId);
            if (balanceOf(user, tokenId) > 0) {
                require(found < maxSlots, "Too many owned tokens");

                assembly {
                    let base := mload(0x40)

                    // Store tokenId
                    mstore(add(base, add(32, mul(found, 32))), tokenId)

                    // Store collectionId
                    mstore(add(base, add(add(32, mul(maxSlots, 32)), add(32, mul(found, 32)))), cId)

                    // Store itemId
                    mstore(add(base, add(add(32, mul(maxSlots, 64)), add(32, mul(found, 32)))), iId)

                    // Update lengths
                    mstore(base, add(mload(base), 1)) // tokenIds length
                    mstore(add(base, add(32, mul(maxSlots, 32))), add(mload(add(base, add(32, mul(maxSlots, 32)))), 1)) // collectionIds length
                    mstore(add(base, add(64, mul(maxSlots, 64))), add(mload(add(base, add(64, mul(maxSlots, 64)))), 1)) // itemIds length
                }

                ++found;
            }
        }
    }

    assembly {
        // Return arrays using memory layout
        let base := mload(0x40)
        let size := add(96, mul(found, 96)) // estimate full size

        // Update free memory pointer
        mstore(0x40, add(base, size))

        // Return data
        tokenIds := base
        collectionIds := add(base, add(32, mul(maxSlots, 32)))
        itemIds := add(base, add(64, mul(maxSlots, 64)))
    }
}
```

### [L-2] Missing Validation on reward in `FestivalPass::createPerformance` Allows Silent BEAT Minting Failure 

**Description:** The `FestivalPass::createPerformance` function does not validate that the reward parameter is greater than zero. As a result, a performance can be created with a reward of 0, which leads to a silent failure: holders of any PASS type will not receive BEAT tokens after attending the performance.

This occurs because BEAT rewards are calculated as:
```solidity
    baseReward * multiplier;
```
Where baseReward = 0, the result will always be 0 — regardless of the pass type (General, VIP, or Backstage).

**Impact:** Pass holders receive no BEAT tokens for attending performances with reward = 0, breaking core reward expectations. While the organizer is a trusted role, accidental misconfiguration is possible — especially if the UI does not enforce a minimum value. This results in confusing behavior and erodes user trust in the reward mechanism.

**Proof of Concept:** Add the following test to FestivalPass.t.sol, and ensure a third user (user3) is initialized in the setUp() function:
```solidity
function test_rewardAfterAttendingAPerformance() public {
        uint256 startTime = block.timestamp + 30 minutes;
        uint256 duration = 2 hours;
        uint256 reward = 0; // Invalid reward
        
        vm.prank(organizer);
        uint256 perfId = festivalPass.createPerformance(startTime, duration, reward);
        
        // All users buy different types of passes
        vm.prank(user1);
        festivalPass.buyPass{value: BACKSTAGE_PRICE}(3);

        vm.prank(user2);
        festivalPass.buyPass{value: VIP_PRICE}(2);

        vm.prank(user3);
        festivalPass.buyPass{value: GENERAL_PRICE}(1);

        // Advance time to active performance window
        vm.warp(startTime + 30 minutes);

        // All users attend the performance
        vm.prank(user1);
        festivalPass.attendPerformance(perfId);

        vm.prank(user2);
        festivalPass.attendPerformance(perfId);

        vm.prank(user3);
        festivalPass.attendPerformance(perfId);

        // Validate balances
        console.log(beatToken.balanceOf(user1)); // Only 15 BEAT (from purchase)
        console.log(beatToken.balanceOf(user2)); // Only 5 BEAT (from purchase)
        console.log(beatToken.balanceOf(user3)); // 0 BEAT (General Pass — received nothing)
    }
```

**Recommended Mitigation:** Add the following validation inside the `FestivalPass::createPerformance` function:
```diff
function createPerformance(
        uint256 startTime,
        uint256 duration,
        uint256 reward
    ) external onlyOrganizer returns (uint256) {
        require(startTime > block.timestamp, "Start time must be in the future");
        require(duration > 0, "Duration must be greater than 0");
+       require(reward > 0, "Reward must be greater than 0");
        // Set start/end times
        performances[performanceCount] = Performance({
            startTime: startTime,
            endTime: startTime + duration,
            baseReward: reward
        });
        emit PerformanceCreated(performanceCount, startTime, startTime + duration);
        return performanceCount++;
    }
```
This ensures that performances must always include a non-zero reward, thereby guaranteeing that all pass holders can benefit from attending.


### [L-3] Important Event `IFestivalPass::FundsWithdrawn` Declared but Not Emitted on `FestivalPass::withdraw` function.

**Description:** The `IFestivalPass::FundsWithdrawn` event is declared but the `FestivalPass::withdraw` function does not emit this event when funds are withdrawn. This reduces protocol transparency and makes it harder for off-chain services and users to monitor withdrawals and track on-chain activity.
While the access control issue (onlyOwner vs onlyOrganizer) is addressed separately in [H-1], this finding specifically focuses on the absence of an event.

**Impact:** 
- Off-chain services, block explorers, and users cannot reliably detect when funds are withdrawn from the contract.
- Reduces protocol transparency and makes it difficult to monitor or audit withdrawals.
- May hinder integration with monitoring tools, analytics platforms, or alerting systems.

**Proof of Concept:** Add this into your FestivalPass.t.sol:
```javascript
function    test_withdrawEvent() public {
    // Users buy passes
    vm.prank(user1);
    festivalPass.buyPass{value: GENERAL_PRICE}(1);
        
    vm.prank(user2);
    festivalPass.buyPass{value: VIP_PRICE}(2);
        
    // This test fails, proving no FundsWithdrawn event is emitted during withdrawal
            
    vm.prank(owner);
    vm.expectEmit(true, false, false, true);
    festivalPass.withdraw(organizer);
}
```
A Foundry test using vm.expectEmit(...) fails when calling festivalPass.withdraw(), proving that the `IFestivalPass::FundsWithdrawn` event is not emitted.

**Recommended Mitigation:** Add the event emission to the withdraw function to ensure that all withdrawals are logged on-chain:
```diff
    function withdraw(address target) external onlyOwner {
+       uint256 amount = address(this).balance;
-       payable(target).transfer(address(this).balance);
+       payable(target).transfer(amount);
+       emit FundsWithdrawn(msg.sender, amount);        
    }
```
This ensures transparent and traceable withdrawals.

