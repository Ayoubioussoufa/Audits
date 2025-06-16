# 🛡️ My First Smart Contract Security Report – [Snowman Protocol](https://github.com/CodeHawks-Contests/2025-06-snowman-merkle-airdrop)

This repository documents my **first security audit** of the Snowman Protocol — a project that combines:

- 🧊 ERC20-based staking (`Snow.sol`)
- ⛓️ Merkle-based NFT airdrops (`SnowmanAirdrop.sol`)
- ✍️ EIP-712 signature verification (`getMessageHash()`)

## 🔧 Tools Used
- 🔍 **Slither** – Static analysis and vulnerability detection  
- 🐦 **Aderyn** – Cross-verification of known smart contract issues  
- 🔨 **Foundry** – Testing, fuzzing, and custom Proof-of-Concepts (PoCs)

# Table of Contents
- [🛡️ My First Smart Contract Security Report – Snowman Protocol](#️-my-first-smart-contract-security-report--snowman-protocol)
  - [🔧 Tools Used](#-tools-used)
- [Table of Contents](#table-of-contents)
- [Summary](#summary)
  - [Files Summary](#files-summary)
  - [Files Details](#files-details)
  - [Issue Summary](#issue-summary)
- [High Issues](#high-issues)
    - [\[H-1\] Typo in `SnowmanAirdrop::MESSAGE_TYPEHASH` Breaks EIP-712 Signature Verification.](#h-1-typo-in-snowmanairdropmessage_typehash-breaks-eip-712-signature-verification)
    - [\[H-2\] Global `Snow::s_earnTimer` Prevents Multiple Users from Claiming earnSnow Independently once a week.](#h-2-global-snows_earntimer-prevents-multiple-users-from-claiming-earnsnow-independently-once-a-week)
    - [\[H-3\] Unrestricted Access to Snowman::mintSnowman() Enables Infinite NFT Minting and Bypasses Protocol Rules.](#h-3-unrestricted-access-to-snowmanmintsnowman-enables-infinite-nft-minting-and-bypasses-protocol-rules)
- [Low Issues](#low-issues)
    - [L-0 Unchecked Return Value in collectFee() May Lead to Silent Fee Transfer Failures](#l-0-unchecked-return-value-in-collectfee-may-lead-to-silent-fee-transfer-failures)
  - [L-1: Centralization Risk](#l-1-centralization-risk)
  - [L-2: Unsafe ERC20 Operation](#l-2-unsafe-erc20-operation)
  - [L-3: Unspecific Solidity Pragma](#l-3-unspecific-solidity-pragma)
  - [L-4: PUSH0 Opcode](#l-4-push0-opcode)
  - [L-5: Unused Error](#l-5-unused-error)
  - [L-6: Loop Contains `require`/`revert`](#l-6-loop-contains-requirerevert)
  - [L-7: Unused State Variable](#l-7-unused-state-variable)
  - [L-8: Costly operations inside loop](#l-8-costly-operations-inside-loop)
  - [L-9: State Variable Could Be Immutable](#l-9-state-variable-could-be-immutable)
  - [L-10: Unchecked Return](#l-10-unchecked-return)

# Summary

## Files Summary

| Key | Value |
| --- | --- |
| .sol Files | 4 |
| Total nSLOC | 230 |


## Files Details

| Filepath | nSLOC |
| --- | --- |
| src/Snow.sol | 84 |
| src/Snowman.sol | 49 |
| src/SnowmanAirdrop.sol | 89 |
| src/mock/MockWETH.sol | 8 |
| **Total** | **230** |


## Issue Summary

| Category | No. of Issues |
| --- | --- |
| High | 2 |
| Low | 10 |

# High Issues

### [H-1] Typo in `SnowmanAirdrop::MESSAGE_TYPEHASH` Breaks EIP-712 Signature Verification.

**Description:** The contract defines an EIP-712 typeHash for the struct SnowmanClaim, but contains a typo in the struct's type string:
```javascript
bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(addres receiver, uint256 amount)");
```
The word "addres" is not a valid Solidity type and should be "address". Since EIP-712 requires exact string encoding of struct types for hashing and signature verification, this typo causes the hash to mismatch the intended structure.
As a result, the getMessageHash() function will produce an incorrect digest, leading to signature verification failure when using _hashTypedDataV4().

**Impact:** 
- Any off-chain EIP-712 signatures will not match the on-chain MESSAGE_TYPEHASH, causing signature validation logic to fail silently.
- The airdrop mechanism becomes non-functional.
- Users will be unable to claim Snowman NFTs using valid signatures.
- The entire airdrop or delegation mechanism becomes non-functional, defeating the core purpose of signature-based access control.
- This may result in loss of trust, inaccessible rewards, or a complete failure of the signature-based claim flow.

**Proof of Concept:** This test shows how the incorrect MESSAGE_TYPEHASH breaks EIP-712 signature validation, even if everything else is correct.

Alice’s off-chain signature is based on: `keccak256("SnowmanClaim(address receiver, uint256 amount)")`
The contract computes the digest using:
`keccak256("SnowmanClaim(addres receiver, uint256 amount)")`
→ This changes the keccak256 output entirely.

As a result: ecrecover(digest, v, r, s) will return the wrong address.

Add this into the TestSnowmanAirdrop.t.sol: 

```javascript
function testInvalidTypeHashBreaksSignature() public {
        vm.prank(alice);
        snow.approve(address(airdrop), 1);

        uint256 amount = snow.balanceOf(alice);

        // ✅ Construct the CORRECT typeHash manually (should be in frontend or external signer)
        bytes32 correctTypeHash = keccak256("SnowmanClaim(address receiver, uint256 amount)");

        // ❌ The contract used keccak256("SnowmanClaim(addres receiver, uint256 amount)")
        // So this digest should differ

        // Reconstruct structHash manually using correct type string
        bytes32 structHash = keccak256(abi.encode(correctTypeHash, alice, amount));

        // Get domain separator from contract (after adding getDomainSeparator())
        bytes32 domainSeparator = airdrop.getDomainSeparator();

        // Final EIP-712 digest (as frontend/off-chain would compute it)
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01", domainSeparator, structHash
        ));

        // Alice signs correct digest (what the frontend would do)
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alKey, digest);

        // Revert expected: contract will hash something different (wrong MESSAGE_TYPEHASH)
        vm.expectRevert(); 
        vm.prank(satoshi);
        airdrop.claimSnowman(alice, AL_PROOF, v, r, s);
    }
```

Also add this into SnowAirdrop.sol:

```javascript
function getDomainSeparator() external view returns (bytes32) {
    return _domainSeparatorV4();
}
```

**Recommended Mitigation:** Fix the typo in the type string:
```diff
- bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(addres receiver, uint256 amount)");
+ bytes32 private constant MESSAGE_TYPEHASH = keccak256("SnowmanClaim(address receiver, uint256 amount)");
```

<!--  -->

### [H-2] Global `Snow::s_earnTimer` Prevents Multiple Users from Claiming earnSnow Independently once a week.

**Description:** The `Snow::earnSnow()` function uses a single uint256 private `Snow::s_earnTimer` state variable to enforce a cooldown period for earning Snow tokens. However, this timer is global, meaning once any user calls `Snow::earnSnow()`, no other user can call it again until 1 week has passed, regardless of their individual activity. This introduces severe limitations in a multi-user environment.

**Impact:** 
- Only one user can call `Snow::earnSnow()` every 7 days.
- All other users will be reverted with `Snow::S__Timer()` even if they never called the function before.
- This breaks the expected functionality of a decentralized system where users should act independently.
- Severely restricts adoption and usability.

**Proof of Concept:** Add this into your TestSnow.t.sol
```javascript
function testCanEarnSnowOnceAWeek() public {
        vm.prank(ashley);
        snow.earnSnow();

        assert(snow.balanceOf(ashley) == 1);

        vm.prank(jerry);
        vm.expectRevert();
        snow.earnSnow(); // Reverts due to global cooldown
    }
```
Here, jerry is prevented from calling `Snow::earnSnow()` immediately after ashley, even though jerry has never interacted before.

**Recommended Mitigation:** Change `Snow::s_earnTimer` from a single global variable to a per-user mapping:
```diff
- uint256 private s_earnTimer;
+ mapping(address => uint256) private s_earnTimer;
```

```diff
function earnSnow() external canFarmSnow {
-    if (s_earnTimer != 0 && block.timestamp < (s_earnTimer + 1 weeks))
+    if (s_earnTimer[msg.sender] != 0 && block.timestamp < (s_earnTimer[msg.sender] + 1 weeks)) {
        revert S__Timer();
    }
    _mint(msg.sender, 1);
-    s_earnTimer = block.timestamp;
+    s_earnTimer[msg.sender] = block.timestamp;
}
```

### [H-3] Unrestricted Access to Snowman::mintSnowman() Enables Infinite NFT Minting and Bypasses Protocol Rules.

**Description:** The Snowman contract implements the `Snowman::mintSnowman()` function that allows any external caller to mint an arbitrary number of NFTs to any address, without restrictions:

```javascript
function mintSnowman(address receiver, uint256 amount) external {
    for (uint256 i = 0; i < amount; i++) {
        _safeMint(receiver, s_TokenCounter);
        emit SnowmanMinted(receiver, s_TokenCounter);
        s_TokenCounter++;
    }
}
```

There are no access controls, no token gating, and no maximum mint cap. This undermines the protocol’s intended design, where NFTs are supposed to be earned through staking Snow tokens or claimed via SnowmanAirdrop using a Merkle proof and valid signature.

**Impact:** 
- Any user can call `Snowman::mintSnowman()` directly and mint thousands of NFTs without owning any Snow tokens or passing a Merkle proof.
- This bypasses all staking, signature validation, or Merkle-tree-based restrictions from SnowmanAirdrop.sol.
- Severe inflation of the NFT supply becomes possible, ruining scarcity and trust in the system.
- NFT marketplaces and indexers may be spammed with illegitimate tokens.
- Potential economic exploitation if NFTs have value, utility, or claimable rewards.

**Proof of Concept:** Add this into your TestSnowman.t.sol:

```javascript
function testAnyoneCanMintUnlimitedNFTs() public {
        // Anyone can call mintSnowman without restrictions
        snowman.mintSnowman(alice, 1000);

        assertEq(snowman.balanceOf(alice), 1000);
    }
```
**Recommended Mitigation:** Restrict mintSnowman() to only authorized contract SnowmanAirdrop.
i_airdrop would be a state variable in the Snowman.sol contract, and it should store the address of the trusted SnowmanAirdrop contract — the only contract allowed to call `Snowman::mintSnowman()`.

```javascript
modifier onlyAirdrop() {
    require(msg.sender == i_airdrop, "Not authorized");
    _;
}

function mintSnowman(address receiver, uint256 amount) external onlyAirdrop {
    ...
}
```


# Low Issues

### L-0 Unchecked Return Value in collectFee() May Lead to Silent Fee Transfer Failures

**Description:** The `Snow::collectFee()` function calls i_weth.transfer() to send collected WETH to the collector. However, it does not check the return value of the transfer() call. While this isn't dangerous in the current context (where the protocol controls the WETH contract), failing to check return values violates best practices and could silently fail in future upgrades or token changes.

**Impact:** 
- If transfer() fails silently, fees will not be collected, but the protocol will behave as if they were.
- Creates confusion or inconsistencies during audits or operations.
- May break invariants if token contracts are updated or swapped in the future.

**Proof of Concept:**
```solidity
i_weth.transfer(s_collector, collection); // no check!
```
**Recommended Mitigation:** 
```diff
- i_weth.transfer(s_collector, collection);
+ require(i_weth.transfer(s_collector, collection), "Transfer failed");
```

## L-1: Centralization Risk

Contracts have owners with privileged rights to perform admin tasks and need to be trusted to not perform malicious updates or drain funds.

<details><summary>2 Found Instances</summary>


- Found in src/Snow.sol [Line: 18](src/Snow.sol#L18)

    ```solidity
    contract Snow is ERC20, Ownable {
    ```

- Found in src/Snowman.sol [Line: 17](src/Snowman.sol#L17)

    ```solidity
    contract Snowman is ERC721, Ownable {
    ```

</details>



## L-2: Unsafe ERC20 Operation

ERC20 functions may not behave as expected. For example: return values are not always meaningful. It is recommended to use OpenZeppelin's SafeERC20 library.

<details><summary>1 Found Instances</summary>


- Found in src/Snow.sol [Line: 103](src/Snow.sol#L103)

    ```solidity
            i_weth.transfer(s_collector, collection);
    ```

</details>



## L-3: Unspecific Solidity Pragma

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>4 Found Instances</summary>


- Found in src/Snow.sol [Line: 2](src/Snow.sol#L2)

    ```solidity
    pragma solidity ^0.8.24;
    ```

- Found in src/Snowman.sol [Line: 2](src/Snowman.sol#L2)

    ```solidity
    pragma solidity ^0.8.24;
    ```

- Found in src/SnowmanAirdrop.sol [Line: 2](src/SnowmanAirdrop.sol#L2)

    ```solidity
    pragma solidity ^0.8.24;
    ```

- Found in src/mock/MockWETH.sol [Line: 2](src/mock/MockWETH.sol#L2)

    ```solidity
    pragma solidity ^0.8.24;
    ```

</details>



## L-4: PUSH0 Opcode

Solc compiler version 0.8.20 switches the default target EVM version to Shanghai, which means that the generated bytecode will include PUSH0 opcodes. Be sure to select the appropriate EVM version in case you intend to deploy on a chain other than mainnet like L2 chains that may not support PUSH0, otherwise deployment of your contracts will fail.

<details><summary>4 Found Instances</summary>


- Found in src/Snow.sol [Line: 2](src/Snow.sol#L2)

    ```solidity
    pragma solidity ^0.8.24;
    ```

- Found in src/Snowman.sol [Line: 2](src/Snowman.sol#L2)

    ```solidity
    pragma solidity ^0.8.24;
    ```

- Found in src/SnowmanAirdrop.sol [Line: 2](src/SnowmanAirdrop.sol#L2)

    ```solidity
    pragma solidity ^0.8.24;
    ```

- Found in src/mock/MockWETH.sol [Line: 2](src/mock/MockWETH.sol#L2)

    ```solidity
    pragma solidity ^0.8.24;
    ```

</details>



## L-5: Unused Error

Consider using or removing the unused error.

<details><summary>1 Found Instances</summary>


- Found in src/Snowman.sol [Line: 20](src/Snowman.sol#L20)

    ```solidity
        error SM__NotAllowed();
    ```

</details>



## L-6: Loop Contains `require`/`revert`

Avoid `require` / `revert` statements in a loop because a single bad item can cause the whole transaction to fail. It's better to forgive on fail and return failed elements post processing of the loop

<details><summary>1 Found Instances</summary>


- Found in src/Snowman.sol [Line: 37](src/Snowman.sol#L37)

    ```solidity
            for (uint256 i = 0; i < amount; i++) {
    ```

</details>



## L-7: Unused State Variable

State variable appears to be unused. No analysis has been performed to see if any inline assembly references it. Consider removing this unused variable.

<details><summary>1 Found Instances</summary>


- Found in src/SnowmanAirdrop.sol [Line: 42](src/SnowmanAirdrop.sol#L42)

    ```solidity
        address[] private s_claimers; // array to store addresses of claimers
    ```

</details>



## L-8: Costly operations inside loop

Invoking `SSTORE` operations in loops may waste gas. Use a local variable to hold the loop computation result.

<details><summary>1 Found Instances</summary>


- Found in src/Snowman.sol [Line: 37](src/Snowman.sol#L37)

    ```solidity
            for (uint256 i = 0; i < amount; i++) {
    ```

</details>



## L-9: State Variable Could Be Immutable

State variables that are only changed in the constructor should be declared immutable to save gas. Add the `immutable` attribute to state variables that are only changed in the constructor

<details><summary>3 Found Instances</summary>


- Found in src/Snow.sol [Line: 31](src/Snow.sol#L31)

    ```solidity
        uint256 public s_buyFee;
    ```

- Found in src/Snow.sol [Line: 34](src/Snow.sol#L34)

    ```solidity
        IERC20 i_weth;
    ```

- Found in src/Snowman.sol [Line: 24](src/Snowman.sol#L24)

    ```solidity
        string private s_SnowmanSvgUri;
    ```

</details>



## L-10: Unchecked Return

Function returns a value but it is ignored. Consider checking the return value.

<details><summary>1 Found Instances</summary>


- Found in src/Snow.sol [Line: 103](src/Snow.sol#L103)

    ```solidity
            i_weth.transfer(s_collector, collection);
    ```

</details>

