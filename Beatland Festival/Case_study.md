# 🛡️ Smart Contract Security Report Study – [Beatland Festival](https://github.com/CodeHawks-Contests/2025-07-beatland-festival)

All the submissions i made were all just infos/wrong natspec nothing special ...

there was 1high 4 medium 2low and i didn't get any of them ..fml

### High:

## [H-1] Pass Lending Reward Multiplication Enables Unlimited Performance Rewards

we check by user and not by pass ... so we can attend to a performance and send our pass to another address and attend with it the performance also and get the rewards ... Why didn't I think about it .. It's was kinda obvious but it's okey im in a learning process, rewiring my brain to get these kind of vulnerabilities in the future

## Recommended mitigation

it's to have a mapping(uint256 => mapping(uint256 => bool)) public passUsedForPermance;
that we will check with if the user with that pass has attended a performance or not.

### Medium:

## [M-1] Reseting the current pass supply to 0 in the `FestivalPass::configurePass` function allows users to bypass the max supply cap of a pass

If you reset passSupply[passId] to 0 in the `FestivalPass::configurePass` function after passes have been sold, the next buyer will be able to mint as if no passes have been sold.

## [M-2] Function `FestivalPass:buyPass` Lacks Defense Against Reentrancy Attacks, Leading to Exceeding the Maximum NFT Pass Supply

```Solidity
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

Attack : 

```Solidity
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
		if (hackMintCount == festivalPass.passMaxSupply(targetPassId));
	}
}
```

refactor the function by following the **Checks-Effects-Interactions** principle.
```diff
-        _mint(msg.sender, collectionId, 1, ""); 
        ++passSupply[collectionId];
+        emit PassPurchased(msg.sender, collectionId);        
+        _mint(msg.sender, collectionId, 1, "");    
```

## [M-3] Off-by-One in `redeemMemorabilia` Prevents Last NFT From Being Redeemed

* The `redeemMemorabilia` function checks if `collection.currentItemId` is less than `collection.maxSupply`. However, the `currentItemId` starts with 1 in the `createMemorabiliaCollection` function. This prevents the final item (where `currentItemId` equals `maxSupply`) from being redeemed.

... obvious vulnerability that i didn't catch ...

## [M-4] A malicious contract can monopolize all memorabilia in a single transaction via ERC1155 reentrancy

* When a user calls `redeemMemorabilia`, the contract:

  &#x20;

  * Checks the collection is active and not sold out.

  * Burns the caller’s `BEAT` tokens as payment.

  * Mints a unique memorabilia NFT to the user.

  * Emits a `MemorabiliaRedeemed` event.

* Due to the `ERC1155` standard, minting to a **smart contract** address triggers the recipient’s `onERC1155Received` hook.\
  If the recipient is **malicious**, this hook can immediately **re-enter** `redeemMemorabilia` **before the first call finishes**, repeatedly minting new NFTs within a single transaction until the collection is exhausted

## Recommended Mitigation

OpenZeppelin ReentrancyGuard with a mapping(address => bool) hasClaimed
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

### Low:

## [L-1] Inactive Collections — Indefinite BEAT Lock-up

Normal behaviour: Organizer creates memorabilia collections with activateNow = true so users can immediately redeem BEAT for NFTs.

Issue: Collections can be created with activateNow = false and there is no mechanism to activate them later, nor any timeout. Users may acquire BEAT expecting to redeem specific memorabilia, but the organizer can indefinitely prevent access.

```Solidity
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

## [L-2] FestivalPass.sol - URI Function Returns Metadata for Non-Existent Items

The uri function returns metadata URLs for any token ID that belongs to an existing collection, even if the specific item within that collection was never minted. This creates confusion about which tokens actually exist and can cause integration issues with external systems that rely on URI responses to determine token validity.

```Solidity
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

## Recommended Mitigation

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