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
        address    target;     
        address    recipient;  
        uint256    value;     
        uint256    amount;    
        bytes      callData;   
    }

    

     function propose(
        address                  proposer,
        ProposalAction[] calldata actions,
        uint256                  approvalWindow
    ) external returns (bytes32 proposalId);

   
}
