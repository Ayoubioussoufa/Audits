# 🛡️Smart Contract Security Report study – [Snowman Protocol](https://github.com/CodeHawks-Contests/2025-06-snowman-merkle-airdrop)

In this audit, I wasn't to detect the medium and low vulnerabilities (Only got the 2 highs) so I'll be studying it to get it in the future.

# Medium Risk Findings

## [M-1] DoS to a user trying to claim a Snowman

Interesting, so sending 1 token to someone who is about the claim the NFT, won't be able to claim it anymore  due to :
```Solidity
function getMessageHash(address receiver) public view returns (bytes32) {
...
  // @audit HIGH An attacker could send 1 wei of Snow token to the receiver and invalidate the signature, causing the receiver to never be able to claim their Snowman
  uint256 amount = i_snow.balanceOf(receiver);

  return _hashTypedDataV4(
      keccak256(abi.encode(MESSAGE_TYPEHASH, SnowmanClaim({receiver: receiver, amount: amount})))
  );
```

* Because the current amount of Snow owned by the user is used in the verification, an attacker could forcefully send Snow to the receiver in a front-running attack, to prevent the receiver from claiming the NFT.
* 
## Recommended Mitigation

Include the amount to be claimed in both `getMessageHash` and `claimSnowman` instead of reading it from the Snow contract. Showing only the new code in the section below

```Solidity
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

we specify the amount of tokens we want to use to claim the NFT.

Yesterday and today study cases were both on front-running, i'll start paying more attention to it.

# Low Risk Findings

## [L-1] Missing Claim Status Check Allows Multiple Claims in `SnowmanAirdrop.sol::claimSnowman`

* **Normal Behavior:** Airdrop mechanisms should enforce one claim per eligible user to ensure fair distribution and prevent abuse of the reward system.
* **Specific Issue:** The function sets the claim status to true after processing but never validates if `s_hasClaimedSnowman[receiver]` is already true at the beginning, allowing users to claim multiple times as long as they have Snow tokens and valid proofs.

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

## [L-2] Global Timer Reset in `Snow::buySnow` Denies Free Claims for All Users

Oh,  i didn't play attention at that time for this. The `Snow::buySnow` function contains a critical flaw where it resets a global timer `(s_earnTimer)` to the current block timestamp on every invocation.
Any token purchase `(via buySnow)` blocks all free claims for all users for 7 days
```Solidity
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


I gotta pay more attention to DoS attacks [!!!!!front-running!!!!]