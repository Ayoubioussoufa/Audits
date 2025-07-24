# OrderBook - Findings Report

# Table of contents
- ### [Contest Summary](#contest-summary)
- ### [Results Summary](#results-summary)
- ## High Risk Findings
    - [H-01. Mitigating Front-Running Vulnerabilities in DeFi](#H-01)
    - [H-02. Buy orders can be front-run and edited before being confirmed causing users a loss of funds](#H-02)

- ## Low Risk Findings
    - [L-01. Protocol Suffers Potential Revenue Leakage due to Precision Loss in Fee Calculation](#L-01)
    - [L-02. Expired Orders Not Cancellable by Anyone (Design Flaw)](#L-02)
    - [L-03. Missing Event Indexing + Poor dApp Integration](#L-03)
    - [L-04. Inconsistent Order State Management - Expired Orders Remain Active](#L-04)
    - [L-05. No Token Transfer Check in emergencyWithdrawERC20](#L-05)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: First Flight #43

### Dates: Jul 3rd, 2025 - Jul 10th, 2025

[See more contest details here](https://codehawks.cyfrin.io/c/2025-07-orderbook)

# <a id='results-summary'></a>Results Summary

### Number of findings:
   - High: 2
   - Medium: 0
   - Low: 5


# High Risk Findings

## <a id='H-01'></a>H-01. Mitigating Front-Running Vulnerabilities in DeFi

_Submitted by [hemantcode](https://profiles.cyfrin.io/u/hemantcode), [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [yashkhare9815](https://profiles.cyfrin.io/u/yashkhare9815), [jufel](https://profiles.cyfrin.io/u/jufel), [shahraj2605](https://profiles.cyfrin.io/u/shahraj2605), [pexy](https://profiles.cyfrin.io/u/pexy), [romans](https://profiles.cyfrin.io/u/romans), [0xshuayb](https://profiles.cyfrin.io/u/0xshuayb). Selected submission by: [hemantcode](https://profiles.cyfrin.io/u/hemantcode)._      
            


# Root + Impact

## Description

* Describe the normal behavior in one or more sentences - 

   Attackers can exploit the public mempool to front-run amendSellOrder or cancelSellOrder transactions by submitting buyOrder transactions with higher gas prices, buying assets at outdated prices or before cancellation.\
  This undermines the seller’s ability to update or cancel orders reliably. 

* **Root Cause**:

  Blockchain transactions are visible in the public mempool before confirmation, allowing attackers to observe and outpace **amendSellOrder or cancelSellOrder calls**.\
  The contract lacks mechanisms like time-locks or commit-reveal to obscure or delay these actions.

  <br />

* Explain the specific issue or problem in one or more sentences

```solidity
// Root cause in the codebase with @> marks to highlight the relevant section
```

## Risk

**Likelihood**:

* Reason 1 - High likelihood due to easy mempool monitoring, automated MEV bots, and strong financial incentives in volatile markets.

* Reason 2 - No built-in protections make successful front-running attacks highly probable.

**Impact**:

* Impact 1 - Sellers face financial losses by selling at unintended prices or losing assets they meant to cancel, potentially in the thousands of USDC.

* Impact 2 - User trust and platform reputation suffer, risking reduced adoption and market inefficiency.

<br />

## Recommended Mitigation - 

&#x20;&#x20;

Use time lock mechanism 

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

## <a id='H-02'></a>H-02. Buy orders can be front-run and edited before being confirmed causing users a loss of funds

_Submitted by [wolf_kalp](https://profiles.cyfrin.io/u/wolf_kalp), [alexscherbatyuk](https://profiles.cyfrin.io/u/alexscherbatyuk), [tenderflower378](https://profiles.cyfrin.io/u/tenderflower378), [vceb](https://profiles.cyfrin.io/u/vceb), [chaos304](https://profiles.cyfrin.io/u/chaos304), [0xkatrix](https://profiles.cyfrin.io/u/0xkatrix), [perun84](https://profiles.cyfrin.io/u/perun84), [mentemdeus](https://profiles.cyfrin.io/u/mentemdeus), [0xrektified](https://profiles.cyfrin.io/u/0xrektified), [vincent71399](https://profiles.cyfrin.io/u/vincent71399), [xgrybto](https://profiles.cyfrin.io/u/xgrybto), [vasquez](https://profiles.cyfrin.io/u/vasquez), [neomartis](https://profiles.cyfrin.io/u/neomartis), [pexy](https://profiles.cyfrin.io/u/pexy), [accessdenied](https://profiles.cyfrin.io/u/accessdenied), [igdbaxe](https://profiles.cyfrin.io/u/igdbaxe), [romans](https://profiles.cyfrin.io/u/romans). Selected submission by: [chaos304](https://profiles.cyfrin.io/u/chaos304)._      
            


# Buy orders can be front-run and edited before being confirmed causing buyers a loss of funds

## Description

Users can use the `buyOrder()` function to fulfil sell orders, however, sell orders can be edited while the order is still active, this allows the seller to front-run a buy call for their sell order, editing their order so that the buyer ends up overpaying.

## Risk

**Likelihood**:

* This can happen whenever a malicious seller's order is being fulfilled

**Impact**:

* Loss of funds for the buyer

## Proof of Concept

Append the following test to `TestOrderBook.t.sol` and run `forge test --mt test_frontRun`

```solidity
function test_frontRun() public {
    address attacker = makeAddr("attacker");
    address user = makeAddr("user");

    uint256 amountToSell = 2e8;
    uint256 price = 180_000e6;

    wbtc.mint(attacker, amountToSell);
    usdc.mint(user, price);

    // The attacker creates sell order for wbtc
    vm.startPrank(attacker);
    wbtc.approve(address(book), 2e8);
    uint256 orderId = book.createSellOrder(address(wbtc), amountToSell, price, 2 days);
    vm.stopPrank();

    // The user submits a transaction trying to fulfil the attacker's sell order
    // The attacker sees this pending transaction and front-runs it, reducing the number of tokens inside the order but keeping the price the same
    vm.startPrank(attacker);
    book.amendSellOrder(orderId, 1, price, 2 days);
    vm.stopPrank();

    // The user's buy transaction is confirmed, receiving significantly less tokens than what they were expecting
    vm.startPrank(user);
    usdc.approve(address(book), price);
    book.buyOrder(orderId);
    vm.stopPrank();

    uint256 amountReceivedAfterFees = price - (price * book.FEE() / book.PRECISION());

    assertEq(usdc.balanceOf(attacker), amountReceivedAfterFees);
    assert(wbtc.balanceOf(user) != amountToSell);
}
```

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
    .
    .
}
```


# Medium Risk Findings



# Low Risk Findings

## <a id='L-01'></a>L-01. Protocol Suffers Potential Revenue Leakage due to Precision Loss in Fee Calculation

_Submitted by [amro135ali](https://profiles.cyfrin.io/u/amro135ali), [blee](https://profiles.cyfrin.io/u/blee), [whoami](https://profiles.cyfrin.io/u/whoami), [robertnvt](https://profiles.cyfrin.io/u/robertnvt), [microwise](https://profiles.cyfrin.io/u/microwise), [flavius](https://profiles.cyfrin.io/u/flavius), [shieldrey](https://profiles.cyfrin.io/u/shieldrey), [anchabadze](https://profiles.cyfrin.io/u/anchabadze), [vishal772pixel](https://profiles.cyfrin.io/u/vishal772pixel), [0x27281m](https://profiles.cyfrin.io/u/0x27281m), [0xsyntellect](https://profiles.cyfrin.io/u/0xsyntellect), [howiecht](https://profiles.cyfrin.io/u/howiecht), [gwish08](https://profiles.cyfrin.io/u/gwish08), [fredo182](https://profiles.cyfrin.io/u/fredo182), [sg_milad](https://profiles.cyfrin.io/u/sg_milad), [khandelwalmoksh787](https://profiles.cyfrin.io/u/khandelwalmoksh787), [nagatejakachapuram](https://profiles.cyfrin.io/u/nagatejakachapuram), [0xrektified](https://profiles.cyfrin.io/u/0xrektified), [forbverse](https://profiles.cyfrin.io/u/forbverse), [perun84](https://profiles.cyfrin.io/u/perun84), [ciphermalware](https://profiles.cyfrin.io/u/ciphermalware), [The Best Audit Group](https://codehawks.cyfrin.io/team/cm87ase2s000djw03cbgkwr5s), [hosam](https://profiles.cyfrin.io/u/hosam), [0xriz0](https://profiles.cyfrin.io/u/0xriz0), [pexy](https://profiles.cyfrin.io/u/pexy), [faran](https://profiles.cyfrin.io/u/faran), [ksiddharth346](https://profiles.cyfrin.io/u/ksiddharth346), [jufel](https://profiles.cyfrin.io/u/jufel), [0x00t1](https://profiles.cyfrin.io/u/0x00t1), [superdevfavour](https://profiles.cyfrin.io/u/superdevfavour), [akronim26](https://profiles.cyfrin.io/u/akronim26), [igdbaxe](https://profiles.cyfrin.io/u/igdbaxe), [0xshuayb](https://profiles.cyfrin.io/u/0xshuayb). Selected submission by: [hosam](https://profiles.cyfrin.io/u/hosam)._      
            


#### **Finding Title**

Protocol Suffers Potential Revenue Leakage due to Precision Loss in Fee Calculation

#### **Summary**

The protocol's fee calculation, which uses integer division with low precision (`/ 100`), creates a rounding error that can be exploited. For any trade priced at 33 wei of USDC or less, the calculated 3% fee rounds down to zero, allowing the trade to be processed fee-free. While the high gas cost of performing many small transactions makes a large-scale economic attack impractical today, this represents a fundamental design flaw that causes a **verifiable and permanent leakage of protocol revenue**. This flaw undermines the economic model and should be remediated as a matter of protocol robustness and best practice.

#### **Finding Description**

The `buyOrder` function calculates the protocol fee using the formula `(order.priceInUSDC * 3) / 100`. Due to Solidity's integer division, any result with a remainder is truncated. Consequently, if the numerator `(order.priceInUSDC * 3)` is less than `100`, the resulting `protocolFee` is `0`. This is true for any `priceInUSDC` value between 1 and 33.

```solidity
// src/OrderBook.sol:203
uint256 protocolFee = (order.priceInUSDC * FEE) / PRECISION; // FEE = 3, PRECISION = 100
```

This creates a scenario where users can intentionally price their orders just below the 34 wei threshold to avoid fees. Although a single such transaction has a negligible impact, it establishes a pattern of value leakage that is built into the protocol's core logic.

#### **Impact**

The primary impact is a **direct, albeit small, loss of protocol revenue on certain trades**. While the economic viability of a large-scale attack is questionable due to gas costs, the existence of this flaw has several negative consequences:

* **Protocol Value Leak:** The protocol fails to capture fees it is entitled to, creating a small but persistent drain on its treasury.

* **Design Flaw:** It demonstrates a weakness in the handling of financial calculations. In DeFi, even minor rounding errors can be aggregated or combined with other exploits to cause significant issues.

* **Future Risk:** A reduction in L2 gas fees or the introduction of new protocol features could potentially make this exploit more economically viable in the future.

#### **Likelihood**

**Medium.** From a technical standpoint, the flaw is easy to trigger. Any user can create a low-priced order. However, the economic incentive to do so at scale is currently low, which reduces the practical likelihood of a major exploit.

#### **Proof of Concept**

The following test demonstrates that an order priced at 33 wei of USDC results in zero fees being collected by the protocol, confirming the rounding vulnerability.

**Test File:** `test/FeeRoundingVulnerabilityV2.t.sol`

```solidity

// SPDX-License-Identifier: SEE LICENSE IN LICENSE
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {OrderBook} from "../src/OrderBook.sol";
import {MockUSDC} from "./mocks/MockUSDC.sol";
import {MockWETH} from "./mocks/MockWETH.sol";

/**
 * @title Fee Rounding Vulnerability PoC
 * @notice Demonstrates how integer division in fee calculations leads to revenue loss for the protocol.
 */
contract FeeRoundingExploitTest is Test {
    OrderBook book;
    MockWETH weth;
    MockUSDC usdc;

    address owner = makeAddr("owner");
    address seller = makeAddr("seller");
    address buyer = makeAddr("buyer");

    function setUp() public {
        weth = new MockWETH(18);
        usdc = new MockUSDC(6);
        
        vm.prank(owner);
        book = new OrderBook(address(weth), address(weth), address(weth), address(usdc), owner);

        // Mint tokens to participants
        weth.mint(seller, 10e18); // 10 WETH for multiple orders
        usdc.mint(buyer, 1000e6); // 1000 USDC
    }

    /// @notice This test proves that a single order with a low price (e.g., 33 wei of USDC)
    ///         results in a calculated fee of zero, allowing a trade to occur fee-free.
    function test_PoC_SingleOrderFeeEvasion() public {
        // A price of 33 will result in a fee calculation of (33 * 3) / 100, which rounds down to 0.
        uint256 exploitablePrice = 33;
        
        // --- Execution ---
        vm.startPrank(seller);
        weth.approve(address(book), 1e18);
        uint256 orderId = book.createSellOrder(address(weth), 1e18, exploitablePrice, 1 days);
        vm.stopPrank();

        uint256 feesBefore = book.totalFees();
        assertEq(feesBefore, 0, "Initial fees should be zero");

        vm.startPrank(buyer);
        usdc.approve(address(book), exploitablePrice);
        book.buyOrder(orderId);
        vm.stopPrank();

        // --- Assertion ---
        uint256 feesAfter = book.totalFees();
        console2.log("Price per order:", exploitablePrice);
        console2.log("Protocol fees collected for this trade:", feesAfter - feesBefore);

        // The key assertion: The protocol failed to collect any fee for this transaction.
        assertEq(feesAfter, 0, "VULNERABILITY: Protocol should have collected a fee, but it rounded down to zero.");
    }

    /// @notice This test demonstrates how an attacker can exploit the rounding error repeatedly
    ///         by splitting a large sale into multiple small, fee-free orders, causing
    ///         a cumulative loss of revenue for the protocol.
    function test_PoC_CumulativeFeeLoss() public {
        uint256 numOrders = 20;
        uint256 exploitablePrice = 33; // This price results in a fee of 0
        
        // --- Execution ---
        for (uint256 i = 0; i < numOrders; i++) {
            vm.startPrank(seller);
            weth.approve(address(book), 1e17); // Sell 0.1 WETH per order
            uint256 orderId = book.createSellOrder(address(weth), 1e17, exploitablePrice, 1 days);
            vm.stopPrank();

            vm.startPrank(buyer);
            usdc.approve(address(book), exploitablePrice);
            book.buyOrder(orderId);
            vm.stopPrank();
        }

        // --- Assertion ---
        uint256 totalFeesCollected = book.totalFees();
        
        console2.log("Number of fee-free orders processed:", numOrders);
        console2.log("Total fees collected by protocol:", totalFeesCollected);

        // The key assertion: After 20 trades, the protocol has still earned nothing.
        assertEq(totalFeesCollected, 0, "VULNERABILITY: Protocol revenue remains zero after multiple trades due to rounding exploit.");
    }
}
```

**Successful Test Output:**

```Solidity
[PASS] test_PoC_SingleOrderFeeEvasion()
Logs:
  Price per order: 33
  Protocol fees collected for this trade: 0
```

The successful test confirms that it is possible to execute a trade without paying any fees, validating the existence of the revenue leakage flaw.

#### **Recommended Mitigation**

The standard industry practice to prevent such rounding issues is to increase the precision of the calculation by using basis points (1 bp = 0.01%).

```diff
// src/OrderBook.sol

-    uint256 public constant FEE = 3; // 3%
-    uint256 public constant PRECISION = 100;
+    uint256 public constant FEE = 300; // 300 bps = 3.00%
+    uint256 public constant PRECISION = 10000; // Represents 100.00%
```

**Impact of the Fix:**
With this change, the fee calculation becomes significantly more precise. While a price of 33 wei would still result in a zero fee (`(33 * 300) / 10000 = 0`), the threshold for earning a fee is much lower. For a more realistic low-value transaction of **1 USDC (1,000,000 wei)**, the fee would be:
`(1,000,000 * 300) / 10000 = 30,000 wei` (or 0.03 USDC).
This ensures that fees are collected fairly and consistently across almost all non-trivial trades, patching the revenue leak.

## <a id='L-02'></a>L-02. Expired Orders Not Cancellable by Anyone (Design Flaw)

_Submitted by [ishwar](https://profiles.cyfrin.io/u/ishwar), [deadmanxxxii](https://profiles.cyfrin.io/u/deadmanxxxii), [amro135ali](https://profiles.cyfrin.io/u/amro135ali), [kerget95](https://profiles.cyfrin.io/u/kerget95), [whoami](https://profiles.cyfrin.io/u/whoami), [geeby](https://profiles.cyfrin.io/u/geeby), [wolf_kalp](https://profiles.cyfrin.io/u/wolf_kalp), [evmninja](https://profiles.cyfrin.io/u/evmninja), [gwish08](https://profiles.cyfrin.io/u/gwish08), [nagatejakachapuram](https://profiles.cyfrin.io/u/nagatejakachapuram), [soarinskysagar](https://profiles.cyfrin.io/u/soarinskysagar), [radiumx](https://profiles.cyfrin.io/u/radiumx), [mukulkolpe](https://profiles.cyfrin.io/u/mukulkolpe), [0x00t1](https://profiles.cyfrin.io/u/0x00t1), [pexy](https://profiles.cyfrin.io/u/pexy), [20162020lxm](https://profiles.cyfrin.io/u/20162020lxm). Selected submission by: [ishwar](https://profiles.cyfrin.io/u/ishwar)._      
            


# Root + Impact

## Description

* Normally, once an order has expired (past its deadline), it should be possible to remove the order and return tokens to the seller, freeing up storage and preventing locked funds.

* In the current implementation, only the original seller can cancel their expired order. If the seller becomes inactive or loses access, the expired order cannot be cancelled by anyone else, resulting in tokens being locked in the contract and permanent storage bloat.

```solidity
function cancelSellOrder(uint256 _orderId) public {
    Order storage order = orders[_orderId];

    // Validation checks
    if (order.seller == address(0)) revert OrderNotFound();
    if (order.seller != msg.sender) revert NotOrderSeller(); // @> Only the seller can cancel, even if expired
    if (!order.isActive) revert OrderAlreadyInactive(); // Already inactive (filled or cancelled)

    // Mark as inactive
    order.isActive = false;

    // Return locked tokens to the seller
    IERC20(order.tokenToSell).safeTransfer(order.seller, order.amountToSell);

    emit OrderCancelled(_orderId, order.seller);
}
```

## Risk

**Likelihood**:

* Sellers frequently lose private keys, abandon accounts, or become inactive over time, especially on public DeFi platforms.

* As time passes and the number of users grows, the contract will accumulate more expired orders that cannot be cancelled by anyone else.

**Impact**:

* User funds may become permanently locked in expired orders, reducing trust in the protocol.

* Contract storage will bloat with unremovable expired orders, increasing gas costs and potentially hindering future upgrades or migrations.

## Proof of Concept

```solidity
// Seller creates a sell order
orderBook.createSellOrder(...); // Seller's address

// Seller loses access to their account (private key lost)

// Order expires (block.timestamp > order.deadlineTimestamp)

// No one except the seller can call cancelSellOrder, so tokens remain locked forever
orderBook.cancelSellOrder(orderId); // Reverts for anyone except seller
```

*Explanation: This PoC demonstrates how an expired order becomes unremovable if the seller is inactive, which could lead to permanent token lockup and contract clutter.*

## Recommended Mitigation

```diff
- if (order.seller != msg.sender) revert NotOrderSeller();
+ if (order.seller != msg.sender && block.timestamp < order.deadlineTimestamp) revert NotOrderSeller();
// Allow anyone to cancel an order if it is expired
```

*Explanation: The mitigation allows anyone to cancel an order after its deadline has passed, ensuring that expired orders can always be cleaned up and locked tokens can be released, even if the seller is inactive.*

## <a id='L-03'></a>L-03. Missing Event Indexing + Poor dApp Integration

_Submitted by [blee](https://profiles.cyfrin.io/u/blee), [shieldrey](https://profiles.cyfrin.io/u/shieldrey), [agilegypsy](https://profiles.cyfrin.io/u/agilegypsy), [whoami](https://profiles.cyfrin.io/u/whoami), [ishwar](https://profiles.cyfrin.io/u/ishwar), [shahraj2605](https://profiles.cyfrin.io/u/shahraj2605). Selected submission by: [blee](https://profiles.cyfrin.io/u/blee)._      
            


## Description

* Events should have proper indexing to enable efficient filtering and querying by dApps and indexing services.

* Several events lack indexed parameters which reduces their usefulness for front-end applications and analytics tools.

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

## Risk

**Likelihood**:

* When dApps need to filter events by specific criteria

* When building analytics dashboards or order tracking systems

* When users need to query their order history efficiently

**Impact**:

* Reduced performance for dApp event filtering and querying

* Increased infrastructure costs for indexing services

* Poor user experience in front-end applications

## Proof of Concept

**dApp Integration Challenge**: This demonstrates how poor event indexing affects front-end applications.

```solidity
// Current: Cannot efficiently filter orders by price range
// web3.eth.getPastEvents('OrderAmended', {
//     filter: {
//         newPriceInUSDC: {$gte: 1000, $lte: 5000}  // This doesn't work
//     }
// });

// With indexed parameters, this would be possible:
// web3.eth.getPastEvents('OrderAmended', {
//     filter: {
//         newPriceInUSDC: [1000, 2000, 3000, 4000, 5000]  // More efficient
//     }
// });
```

**Real-world impact on dApps**:

* **Inefficient queries**: Cannot filter events by price ranges or token amounts

* **Higher infrastructure costs**: Must fetch all events and filter client-side

* **Slower user experience**: Loading all events takes more time than filtered queries

* **Analytics limitations**: Order book analytics and dashboards perform poorly

* **Mobile app issues**: Limited bandwidth makes downloading all events impractical

## Recommended Mitigation

**Solution**: Add proper indexing to enable efficient event filtering and querying.

```diff
event OrderAmended(
    uint256 indexed orderId,
-   uint256 newAmountToSell,
-   uint256 newPriceInUSDC,
+   uint256 indexed newAmountToSell,
+   uint256 indexed newPriceInUSDC,
    uint256 newDeadlineTimestamp
);

event EmergencyWithdrawal(
    address indexed token,
-   uint256 indexed amount,
+   uint256 amount,
    address indexed receiver
);
```

**Why this works**:

* **Efficient filtering**: dApps can filter by price ranges and token amounts

* **Better performance**: Indexed parameters enable faster event queries

* **Lower costs**: Reduces infrastructure costs for dApps and indexing services

* **Enhanced UX**: Faster loading times improve user experience

**Indexing best practices**:

* **Limit to 3 indexed parameters** per event (EVM limitation)

* **Index commonly filtered fields**: orderId, amounts, prices, addresses

* **Don't index large data**: Avoid indexing strings or large arrays

* **Consider query patterns**: Index parameters that dApps will filter by most often

## <a id='L-04'></a>L-04. Inconsistent Order State Management - Expired Orders Remain Active

_Submitted by [robertnvt](https://profiles.cyfrin.io/u/robertnvt), [geeby](https://profiles.cyfrin.io/u/geeby), [nomadic_bear](https://profiles.cyfrin.io/u/nomadic_bear), [civil](https://profiles.cyfrin.io/u/civil), [faran](https://profiles.cyfrin.io/u/faran), [allanbnb2](https://profiles.cyfrin.io/u/allanbnb2). Selected submission by: [robertnvt](https://profiles.cyfrin.io/u/robertnvt)._      
            


# Root + Impact

## Description

* The OrderBook contract is designed to automatically handle order lifecycle management where expired orders should become inactive and unavailable for purchase, ensuring users only see and can interact with valid, active orders.

* &#x20;

  The `buyOrder()` function checks if an order is expired but fails to update the `isActive` flag when reverting, causing expired orders to remain marked as active in storage. This creates a state inconsistency where orders appear available but cannot be purchased, leading to failed transactions and poor user experience.

```Solidity
// Root cause in the codebase with @> marks to highlight the relevant sectionl
function buyOrder(uint256 _orderId) public {
    Order storage order = orders[_orderId];

    // Validation checks
    if (order.seller == address(0)) revert OrderNotFound();
    if (!order.isActive) revert OrderNotActive();
@>  if (block.timestamp >= order.deadlineTimestamp) revert OrderExpired();

@>  order.isActive = false;  // This line only executes if order is NOT expired
    uint256 protocolFee = (order.priceInUSDC * FEE) / PRECISION;
    uint256 sellerReceives = order.priceInUSDC - protocolFee;
    // ... rest of function
}
```

## Risk

**Likelihood**:

* Occurs automatically for every order that reaches its deadline timestamp without being filled, making this a guaranteed issue for any order that expires

* &#x20;

  No cleanup mechanism exists in the contract, so expired orders accumulate over time with inconsistent state

**Impact**:

* Users see "active" orders in the UI that cannot be purchased, resulting in failed transactions and wasted gas fees for buyers attempting to purchase expired orders

* &#x20;

  Storage bloat from accumulated expired orders that display as active, degrading overall contract efficiency and user experience over time

## Proof of Concept

```Solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test, console2} from "forge-std/Test.sol";
import {OrderBook} from "../src/OrderBook.sol";
import {MockERC20} from "../test/mocks/MockERC20.sol";

contract OrderBookStateInconsistencyPoC is Test {
    OrderBook public orderBook;
    MockERC20 public weth;
    MockERC20 public usdc;
    
    address public seller = makeAddr("seller");
    address public buyer = makeAddr("buyer");
    
    function setUp() public {
        weth = new MockERC20("Wrapped Ether", "WETH", 18);
        usdc = new MockERC20("USD Coin", "USDC", 6);
        
        orderBook = new OrderBook(
            address(weth),
            address(0), // wbtc
            address(0), // wsol
            address(usdc),
            address(this)
        );
        
        // Setup balances
        weth.mint(seller, 100 ether);
        usdc.mint(buyer, 1000000 * 10**6);
        
        vm.prank(seller);
        weth.approve(address(orderBook), 100 ether);
        
        vm.prank(buyer);
        usdc.approve(address(orderBook), 1000000 * 10**6);
    }
    
    function testStateInconsistency_ExpiredOrderRemainsActive() public {
        console2.log("=== ORDER STATE INCONSISTENCY EXPLOIT ===");
        
        // Create order with 1 hour deadline
        vm.prank(seller);
        uint256 orderId = orderBook.createSellOrder(
            address(weth),
            1 ether,
            2000 * 10**6, // 2000 USDC
            1 hours
        );
        
        // Verify order is active
        OrderBook.Order memory order = orderBook.getOrder(orderId);
        console2.log("Order created - isActive:", order.isActive);
        console2.log("Order deadline:", order.deadlineTimestamp);
        console2.log("Current time:", block.timestamp);
        
        // Fast forward past deadline
        vm.warp(block.timestamp + 2 hours);
        console2.log("Time warped - Current time:", block.timestamp);
        
        // Check order state - should be inactive but isn't
        order = orderBook.getOrder(orderId);
        console2.log("After expiration - isActive:", order.isActive);
        console2.log("Order expired?", block.timestamp >= order.deadlineTimestamp);
        
        // Try to buy expired order - should fail but state remains inconsistent
        vm.prank(buyer);
        vm.expectRevert(); // Will revert with OrderExpired
        orderBook.buyOrder(orderId);
        
        // Verify state inconsistency persists
        order = orderBook.getOrder(orderId);
        console2.log("After failed purchase - isActive:", order.isActive);
        console2.log("STATE INCONSISTENCY: Order shows active but is expired!");
        
        // Demonstrate the issue: order appears active but cannot be purchased
        assertTrue(order.isActive, "Order should appear active due to bug");
        assertTrue(block.timestamp >= order.deadlineTimestamp, "Order should be expired");
    }
}
```

**PoC Results:**

```Solidity
forge test --match-test testStateInconsistency_ExpiredOrderRemainsActive -vv
[⠑] Compiling...
[⠢] Compiling 1 files with Solc 0.8.29
[⠰] Solc 0.8.29 finished in 1.45s
Compiler run successful!

Ran 1 test for test/OrderBookStateInconsistencyPoC.t.sol:OrderBookStateInconsistencyPoC
[PASS] testStateInconsistency_ExpiredOrderRemainsActive() (gas: 245680)
Logs:
  === ORDER STATE INCONSISTENCY EXPLOIT ===
  Order created - isActive: true
  Order deadline: 3600
  Current time: 1
  Time warped - Current time: 7201
  After expiration - isActive: true
  Order expired? true
  After failed purchase - isActive: true
  STATE INCONSISTENCY: Order shows active but is expired!

Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 4.28ms (3.58ms CPU time)

Ran 1 test suite in 10.15ms (4.28ms CPU time): 1 tests passed, 0 failed, 0 skipped (1 total tests)
```

## Recommended Mitigation

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

## <a id='L-05'></a>L-05. No Token Transfer Check in emergencyWithdrawERC20

_Submitted by [evmninja](https://profiles.cyfrin.io/u/evmninja)._      
            


### Summary
The `emergencyWithdrawERC20` function does not check if the token transfer was successful, which could lead to inconsistent state if the transfer fails silently.

### Description
The `emergencyWithdrawERC20` function is designed to allow the contract owner to withdraw any non-core tokens that might have been sent to the contract by mistake. While the function correctly uses `safeTransfer` from OpenZeppelin's SafeERC20 library, which will revert if the transfer fails, there is still a potential issue with tokens that have unusual behaviour or non-standard implementations. Some ERC20 tokens, despite being compliant with the standard interface, might have custom behaviour that could cause transfers to fail silently or return false without reverting. In such cases, the contract would proceed as if the transfer was successful, emitting the `EmergencyWithdrawal` event. The tokens remain in the contract, but the contract and off-chain systems believe they have been withdrawn.

### Step-by-step analysis
1. A non-standard ERC20 token is accidentally sent to the contract.
2. The owner calls `emergencyWithdrawERC20` to recover these tokens.
3. The token's transfer function silently fails without reverting.
4. The contract proceeds as if the transfer was successful, emitting the `EmergencyWithdrawal` event.
5. The tokens remain in the contract, but the contract and off-chain systems believe they have been withdrawn.

### Severity classification
- **Impact**: Low - The potential impact is limited to non-standard tokens and would only affect emergency withdrawals.
- **Likelihood**: Low - Most ERC20 tokens follow the standard behaviour, and SafeERC20 mitigates many issues.

### File name with issue
OrderBook.sol

### Code with issue
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
    emit EmergencyWithdrawal(_tokenAddress, _amount, _to);
}
```

### Recommendation
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

The proposed fix adds balance checks before and after the token transfer to ensure that the expected amount was actually transferred. This provides an additional layer of safety beyond what SafeERC20 offers, ensuring that the contract's state accurately reflects the token balances.




    