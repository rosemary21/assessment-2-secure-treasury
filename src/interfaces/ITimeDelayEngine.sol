

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITimeDelayEngine {

    

function queue(bytes32 proposalId, uint256 delay) external returns (uint256 eta);
event EntryQueued(bytes32 indexed proposalId, uint256 eta, uint256 expiresAt);



struct TimelockEntry {
        bytes32 proposalId;
        uint256 queuedAt;
        uint256 eta;       
        uint256 expiresAt;
        bool    executed;
        bool    cancelled;
    }
}

