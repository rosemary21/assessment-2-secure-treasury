// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;


interface IAction {

    enum ActionType {
        TRANSFER,   
        CALL,      
        UPGRADE    
    }


struct ProposalAction { 
        ActionType actionType;
        address    target;     // token address (TRANSFER) or call target (CALL/UPGRADE)
        address    recipient;  // destination for TRANSFER
        uint256    value;      // native ETH attached to CALL
        uint256    amount;     // token quantity for TRANSFER
        bytes      callData;   // ABI-encoded calldata for CALL / UPGRADE
    }

    

     function propose(
        address                  proposer,
        ProposalAction[] calldata actions,
        uint256                  approvalWindow
    ) external returns (bytes32 proposalId);

   
}
