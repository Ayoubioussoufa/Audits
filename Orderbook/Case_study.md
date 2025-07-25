# 🛡️ Smart Contract Security Report study – [OrderBook](https://github.com/CodeHawks-Contests/2025-07-orderbook)

In this audit, I wasn't able to detect any vulnerabilities, so this file will be me discussion what things I should pay more attention to in the future audits.

Let's start with the lows first, there were 5.


#### Low : 

## [L-1] Protocol Suffers Potential Revenue Leakage due to Precision Loss in Fee Calculation:


```solidity
// src/OrderBook.sol:203
uint256 protocolFee = (order.priceInUSDC * FEE) / PRECISION; // FEE = 3, PRECISION = 100
```
so if order.priceInUSDC is <= 33 wei, we will always get 0, so the protocol won't get any fees.

This vulnerability can be exploited by splitting a large sale into multiple small fee free orders causing a cumulative loss of revenue for the protocol.

**The recommended mitigation here is to increase the precision or change how to calculate the fee**:

They did this in the report and to be honest, i don't get it:
```diff
// src/OrderBook.sol

-    uint256 public constant FEE = 3; // 3%
-    uint256 public constant PRECISION = 100;
+    uint256 public constant FEE = 300; // 300 bps = 3.00%
+    uint256 public constant PRECISION = 10000; // Represents 100.00%
```

With this change the fee calculation becomes significantly more precise. While a price of 33 wei would still result in a zero fee, the threshold for earning a fee is much lower. for more realistic low-value transaction if 1USDC (1,000,000 wei), the fee would be 30,000wei (0.03USDC). This ensures that fees are collected fairly and consistently across almost all non-trivial 

the problem persists : 
33 * 300 / 10000 is still 0 so ? 

Why couldn't we just using a ceil division and we will never be in this situation ??
uint256 protocolFee = (order.priceInUSDC * FEE + PRECISION - 1) / PRECISION;
(33 * 3 + 100 - 1) / 100 = 1%


## [L-2] Expired Orders Not Cancellable by Anyone (Design Flaw)
I saw this when i was auditing the smart contract but I felt unmotivated to do so because I spent a lot of time and couldn't see any high vulnerability.
Also this scenario where the seller doesn't cancel their order (if he lost his wallet for exemple) so his tokens will stay on the contract isn't really our fault in the first place and he would have lost his tokens eitherway.
But we would need to remove expired orders in UI.
so we can allow anyone to cancel an expired order.
```diff
- if (order.seller != msg.sender) revert NotOrderSeller();
+ if (order.seller != msg.sender && block.timestamp < order.deadlineTimestamp) revert NotOrderSeller();
// Allow anyone to cancel an order if it is expired
```

## [L-3]. Missing Event Indexing + Poor dApp Integration
* Events should have proper indexing to enable efficient filtering and querying by dApps and indexing services.
* Several events lack indexed parameters which reduces their usefulness for front-end applications and analytics tools.
so we have to report any parameters that aren't indexed and might be used as a filter  hmmm

```solidity
event OrderAmended(
    uint256 indexed orderId, 
    uint256 newAmountToSell,      // Should be indexed
    uint256 newPriceInUSDC,       // Should be indexed  
    uint256 newDeadlineTimestamp  // Could be indexed
);

event TokenAllowed(
    address indexed token,         // Correctly indexed
    bool indexed status            // Correctly indexed
);

event EmergencyWithdrawal(
    address indexed token,         // Correctly indexed
    uint256 indexed amount,        // Should not be indexed (unlikely to filter by amount)
    address indexed receiver       // Correctly indexed
);
```
* When building analytics dashboards or order tracking systems
* When users need to query their order history efficiently
* Reduced performance for dApp event filtering and querying
* Increased infrastructure costs for indexing services
* Poor user experience in front-end applications

**Real-world impact on dApps**:
* **Inefficient queries**: Cannot filter events by price ranges or token amounts
* **Higher infrastructure costs**: Must fetch all events and filter client-side
* **Slower user experience**: Loading all events takes more time than filtered queries
* **Analytics limitations**: Order book analytics and dashboards perform poorly
* **Mobile app issues**: Limited bandwidth makes downloading all events impractical

## [L-4] No Token Transfer Check in emergencyWithdrawERC20
The `emergencyWithdrawERC20` function does not check if the token transfer was successful, which could lead to inconsistent state if the transfer fails silently.
The contract proceeds as if the transfer was successful, emitting the `EmergencyWithdrawal` event.
this is the function: 
```solidity
function emergencyWithdrawERC20(address _tokenAddress, uint256 _amount, address _to) external onlyOwner {
        if (
            _tokenAddress == address(iWETH) || _tokenAddress == address(iWBTC) || _tokenAddress == address(iWSOL)
                || _tokenAddress == address(iUSDC)
        ) {
            revert("Cannot withdraw core order book tokens via emergency function");
        }
        if (_to == address(0)) {
            revert InvalidAddress();
        }
        IERC20 token = IERC20(_tokenAddress);
        token.safeTransfer(_to, _amount);
@> // no checks
        emit EmergencyWithdrawal(_tokenAddress, _amount, _to);
    }
```
Although SafeERC20's safeTransfer already provides significant protection, for maximum safety, consider checking the token balance before and after the transfer to ensure it was successful, especially for critical functions like emergency withdrawals.

#### Code to fix the problem
```solidity
function emergencyWithdrawERC20(address _tokenAddress, uint256 _amount, address _to) external onlyOwner {
    if (
        _tokenAddress == address(iWETH) || _tokenAddress == address(iWBTC) || _tokenAddress == address(iWSOL)
            || _tokenAddress == address(iUSDC)
    ) {
        revert("Cannot withdraw core order book tokens via emergency function");
    }
    if (_to == address(0)) {
        revert InvalidAddress();
    }
    IERC20 token = IERC20(_tokenAddress);
    uint256 balanceBefore = token.balanceOf(address(this));
    if (balanceBefore < _amount) {
        revert InvalidAmount();
    }
    token.safeTransfer(_to, _amount);
    uint256 balanceAfter = token.balanceOf(address(this));
    if (balanceBefore - balanceAfter != _amount) {
        revert("Transfer failed or incorrect amount transferred");
    }
    emit EmergencyWithdrawal(_tokenAddress, _amount, _to);
}
```


## [L-4] Inconsistent Order State Management - Expired Orders Remain Active
The `buyOrder()` function checks if an order is expired but fails to update the `isActive` flag when reverting, causing expired orders to remain marked as active in storage.
Update the order state to inactive before reverting when an order is expired, ensuring consistent state management throughout the contract.

```diff
function buyOrder(uint256 _orderId) public {
    Order storage order = orders[_orderId];

    if (order.seller == address(0)) revert OrderNotFound();
    if (!order.isActive) revert OrderNotActive();
-   if (block.timestamp >= order.deadlineTimestamp) revert OrderExpired();
+   if (block.timestamp >= order.deadlineTimestamp) {
+       order.isActive = false;
+       emit OrderExpired(_orderId);
+       revert OrderExpired();
+   }

    order.isActive = false;
    uint256 protocolFee = (order.priceInUSDC * FEE) / PRECISION;
    uint256 sellerReceives = order.priceInUSDC - protocolFee;
    // ... rest of function
}
```

#### High:

## [H-1] Mitigating Front-Running Vulnerabilities in DeFi

hmmmm, so attackers can exploit the public mempool to front-run amendSellOrder and cancelSellOrder by submitting buyOrder transactions with higher gas prices, buying assets at outdates prices and before cancellation ... Why didn't I taught about this ... but wait isn't only validators who have access to the mempool of transactions that haven't being confirmed yet ? Gotta search because that's what I thought.
After research I remember that i got that idea from Solana, transactions are way faster and validators have access to see txs ~200ms earlier than others. You can't front run transactions in Solana unless if you are a validator.

## Recommended Mitigation - 

Use time lock mechanism.

so we will have a request and confirmation setup, where we call the first function to make our request to Amend our order / and then after a delay to confirm it to be sure that it's the price we actually want. Same thing for canceling a sell order.

```Solidity
//updated code 
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

contract OrderBook is Ownable {
    using SafeERC20 for IERC20;
    using Strings for uint256;

    struct Order {
        uint256 id;
        address seller;
        address tokenToSell;
        uint256 amountToSell;
        uint256 priceInUSDC;
        uint256 deadlineTimestamp;
        bool isActive;
    }

    // --- New State Variables for Time-Lock ---
    struct PendingAmendment {
        uint256 newAmountToSell;
        uint256 newPriceInUSDC;
        uint256 newDeadlineTimestamp;
        uint256 requestTimestamp;
    }
    mapping(uint256 => PendingAmendment) public pendingAmendments;
    mapping(uint256 => uint256) public pendingCancellations;
    uint256 public constant TIME_LOCK_DELAY = 60; // 60 seconds delay

    // --- Existing State Variables (unchanged) ---
    uint256 public constant MAX_DEADLINE_DURATION = 3 days;
    uint256 public constant FEE = 3;
    uint256 public constant PRECISION = 100;
    IERC20 public immutable iWETH;
    IERC20 public immutable iWBTC;
    IERC20 public immutable iWSOL;
    IERC20 public immutable iUSDC;
    mapping(address => bool) public allowedSellToken;
    mapping(uint256 => Order) public orders;
    uint256 private _nextOrderId;
    uint256 public totalFees;

    // --- Existing Events (unchanged) ---
    event OrderCreated(uint256 indexed orderId, address indexed seller, address indexed tokenToSell, uint256 amountToSell, uint256 priceInUSDC, uint256 deadlineTimestamp);
    event OrderAmended(uint256 indexed orderId, uint256 newAmountToSell, uint256 newPriceInUSDC, uint256 newDeadlineTimestamp);
    event OrderCancelled(uint256 indexed orderId, address indexed seller);
    event OrderFilled(uint256 indexed orderId, address indexed buyer, address indexed seller);
    event TokenAllowed(address indexed token, bool indexed status);
    event EmergencyWithdrawal(address indexed token, uint256 indexed amount, address indexed receiver);
    event FeesWithdrawn(address indexed receiver);

    // --- New Events for Time-Lock ---
    event AmendmentRequested(uint256 indexed orderId, uint256 newAmountToSell, uint256 newPriceInUSDC, uint256 newDeadlineTimestamp, uint256 requestTimestamp);
    event CancellationRequested(uint256 indexed orderId, uint256 requestTimestamp);

    // --- Existing Errors (unchanged) ---
    error OrderNotFound();
    error NotOrderSeller();
    error OrderNotActive();
    error OrderExpired();
    error OrderAlreadyInactive();
    error InvalidToken();
    error InvalidAmount();
    error InvalidPrice();
    error InvalidDeadline();
    error InvalidAddress();

    // --- New Error for Time-Lock ---
    error TimeLockNotElapsed();

    // --- Constructor (unchanged) ---
    constructor(address _weth, address _wbtc, address _wsol, address _usdc, address _owner) Ownable(_owner) {
        if (_weth == address(0) || _wbtc == address(0) || _wsol == address(0) || _usdc == address(0)) revert InvalidToken();
        if (_owner == address(0)) revert InvalidAddress();
        iWETH = IERC20(_weth);
        allowedSellToken[_weth] = true;
        iWBTC = IERC20(_wbtc);
        allowedSellToken[_wbtc] = true;
        iWSOL = IERC20(_wsol);
        allowedSellToken[_wsol] = true;
        iUSDC = IERC20(_usdc);
        _nextOrderId = 1;
    }

    // --- Modified amendSellOrder: Split into Request and Confirm ---
    function requestAmendSellOrder(
        uint256 _orderId,
        uint256 _newAmountToSell,
        uint256 _newPriceInUSDC,
        uint256 _newDeadlineDuration
    ) external {
        Order storage order = orders[_orderId];
        if (order.seller == address(0)) revert OrderNotFound();
        if (order.seller != msg.sender) revert NotOrderSeller();
        if (!order.isActive) revert OrderAlreadyInactive();
        if (block.timestamp >= order.deadlineTimestamp) revert OrderExpired();
        if (_newAmountToSell == 0) revert InvalidAmount();
        if (_newPriceInUSDC == 0) revert InvalidPrice();
        if (_newDeadlineDuration == 0 || _newDeadlineDuration > MAX_DEADLINE_DURATION) revert InvalidDeadline();

        uint256 newDeadlineTimestamp = block.timestamp + _newDeadlineDuration;
        pendingAmendments[_orderId] = PendingAmendment({
            newAmountToSell: _newAmountToSell,
            newPriceInUSDC: _newPriceInUSDC,
            newDeadlineTimestamp: newDeadlineTimestamp,
            requestTimestamp: block.timestamp
        });

        emit AmendmentRequested(_orderId, _newAmountToSell, _newPriceInUSDC, newDeadlineTimestamp, block.timestamp);
    }

    function confirmAmendSellOrder(uint256 _orderId) external {
        Order storage order = orders[_orderId];
        PendingAmendment memory amendment = pendingAmendments[_orderId];
        if (order.seller == address(0)) revert OrderNotFound();
        if (order.seller != msg.sender) revert NotOrderSeller();
        if (amendment.requestTimestamp == 0) revert("No pending amendment");
        if (block.timestamp < amendment.requestTimestamp + TIME_LOCK_DELAY) revert TimeLockNotElapsed();
        if (!order.isActive) revert OrderAlreadyInactive();
        if (block.timestamp >= order.deadlineTimestamp) revert OrderExpired();

        IERC20 token = IERC20(order.tokenToSell);
        if (amendment.newAmountToSell > order.amountToSell) {
            uint256 diff = amendment.newAmountToSell - order.amountToSell;
            token.safeTransferFrom(msg.sender, address(this), diff);
        } else if (amendment.newAmountToSell < order.amountToSell) {
            uint256 diff = order.amountToSell - amendment.newAmountToSell;
            token.safeTransfer(order.seller, diff);
        }

        order.amountToSell = amendment.newAmountToSell;
        order.priceInUSDC = amendment.newPriceInUSDC;
        order.deadlineTimestamp = amendment.newDeadlineTimestamp;

        // Clear pending amendment
        delete pendingAmendments[_orderId];

        emit OrderAmended(_orderId, amendment.newAmountToSell, amendment.newPriceInUSDC, amendment.newDeadlineTimestamp);
    }

    // --- Modified cancelSellOrder: Split into Request and Confirm ---
    function requestCancelSellOrder(uint256 _orderId) external {
        Order storage order = orders[_orderId];
        if (order.seller == address(0)) revert OrderNotFound();
        if (order.seller != msg.sender) revert NotOrderSeller();
        if (!order.isActive) revert OrderAlreadyInactive();
        pendingCancellations[_orderId] = block.timestamp;

        emit CancellationRequested(_orderId, block.timestamp);
    }

    function confirmCancelSellOrder(uint256 _orderId) external {
        Order storage order = orders[_orderId];
        if (order.seller == address(0)) revert OrderNotFound();
        if (order.seller != msg.sender) revert NotOrderSeller();
        if (pendingCancellations[_orderId] == 0) revert("No pending cancellation");
        if (block.timestamp < pendingCancellations[_orderId] + TIME_LOCK_DELAY) revert TimeLockNotElapsed();
        if (!order.isActive) revert OrderAlreadyInactive();

        order.isActive = false;
        IERC20(order.tokenToSell).safeTransfer(order.seller, order.amountToSell);

        // Clear pending cancellation
        delete pendingCancellations[_orderId];

        emit OrderCancelled(_orderId, order.seller);
    }

    // --- Modified buyOrder to Prevent Buying Pending Orders ---
    function buyOrder(uint256 _orderId) public {
        Order storage order = orders[_orderId];
        if (order.seller == address(0)) revert OrderNotFound();
        if (!order.isActive) revert OrderNotActive();
        if (block.timestamp >= order.deadlineTimestamp) revert OrderExpired();
        // Check for pending amendment or cancellation
        if (pendingAmendments[_orderId].requestTimestamp != 0 || pendingCancellations[_orderId] != 0) {
            revert("Order has pending amendment or cancellation");
        }

        order.isActive = false;
        uint256 protocolFee = (order.priceInUSDC * FEE) / PRECISION;
        uint256 sellerReceives = order.priceInUSDC - protocolFee;

        iUSDC.safeTransferFrom(msg.sender, address(this), protocolFee);
        iUSDC.safeTransferFrom(msg.sender, order.seller, sellerReceives);
        IERC20(order.tokenToSell).safeTransfer(msg.sender, order.amountToSell);

        totalFees += protocolFee;

        emit OrderFilled(_orderId, msg.sender, order.seller);
    }

    // --- Other Functions (Unchanged) ---
    // Include createSellOrder, getOrder, getOrderDetailsString, setAllowedSellToken, emergencyWithdrawERC20, withdrawFees as in the original contract
}
```
Interesting approach

## [H-2] Buy orders can be front-run and edited before being confirmed causing users a loss of funds

so vice versa hmmmm
Users can use the `buyOrder()` function to fulfil sell orders, however, sell orders can be edited while the order is still active, this allows the seller to front-run a buy call for their sell order, editing their order so that the buyer ends up overpaying.

## Recommended Mitigation

Consider allowing buyers to set a slippage, reverting the transaction if the order is too unfavorable.

```diff
function buyOrder(
uint256 _orderId,
+uint256 minReceiveAmount,
+uint256 maxPrice
) public {
    Order storage order = orders[_orderId];

    // Validation checks
    if (order.seller == address(0)) revert OrderNotFound();
    if (!order.isActive) revert OrderNotActive();
    if (block.timestamp >= order.deadlineTimestamp) revert OrderExpired();
+   if (order.priceInUSDC > maxPrice) revert PriceTooHigh();
+   if (order.amountToSell < minReceiveAmount) revert InsufficientAmount();    .
    ...
}
```

hmmm so we learned here about front running, indexing events, check in case transfer revert and potential revenue leakage due to precision loss in fee calculation and use ceil division for that.