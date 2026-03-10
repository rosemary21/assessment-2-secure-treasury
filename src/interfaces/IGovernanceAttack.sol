// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


interface IGovernanceAttack {

    function isPaused()  external view returns (bool);
    event DrainRecorded(address indexed token, uint256 amount, uint256 dailyTotal);

       event DrainLimitBreached(address indexed token, uint256 requested, uint256 available);

}
