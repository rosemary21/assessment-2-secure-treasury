// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import "../interfaces/IGovernanceAttack.sol";

contract GovernanceAttack is IGovernanceAttack {

    uint256 public constant DEFAULT_DRAIN_BPS = 500;
    uint256 public constant DAY_SECONDS    = 86_400;
    address public immutable coordinator;
    mapping(address => BalanceSnapshot) private _snapshots;





modifier onlyCoordinator() {
        if (msg.sender != coordinator) revert GG_OnlyCoordinator();
        _;
}

struct DrainState {
        uint256 limitBps;        
        uint256 dailyDrained;  
 }

error GG_OnlyCoordinator();
error GG_DrainLimitExceeded(address token, uint256 requested, uint256 remaining);


 mapping(address => DrainState)      private _drain;



    struct BalanceSnapshot {
        uint256 balance;
        uint256 blockNumber;
    }


 function checkAndRecordDrain(address token, uint256 amount) external onlyCoordinator {
        DrainState storage d = _drain[token];

        if (d.limitBps == 0) {
            d.limitBps = DEFAULT_DRAIN_BPS;
        }

        uint256 today = (block.timestamp / DAY_SECONDS) * DAY_SECONDS;
        if (d.dayTimestamp < today) {
            d.dailyDrained   = 0;
            d.dayTimestamp   = today;
        }

        BalanceSnapshot storage snap = _snapshots[token];
        uint256 referenceBalance = (snap.blockNumber > 0) ? snap.balance : _getBalance(token);
        if (referenceBalance == 0) {
            d.dailyDrained += amount;
            emit DrainRecorded(token, amount, d.dailyDrained);
            return;
        }
        uint256 limit = (referenceBalance * d.limitBps) / 10_000;

        if (d.dailyDrained + amount > limit) {
            emit DrainLimitBreached(token, amount, limit - d.dailyDrained);
            revert GG_DrainLimitExceeded(token, amount, limit > d.dailyDrained ? limit - d.dailyDrained : 0);
        }

        d.dailyDrained += amount;
        emit DrainRecorded(token, amount, d.dailyDrained);
    }
}