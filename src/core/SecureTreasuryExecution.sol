// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "../interfaces/IAction.sol";
import "../interfaces/IGovernanceAttack.sol";
import "../interfaces/IAction.sol";




interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

contract SecureTreasuryExecution{


    event Proposal(bytes32 indexed proposalId, address indexed proposer);

        IGovernanceAttack  public govPrevention;
        IAction public actionManager;


       error AT_ActionFailed(uint256 actionIndex);
        error AT_InsufficientBalance();


        modifier notPaused() {
            require(!govPrevention.isPaused(), "AT: Paused");
            _;
        }

        constructor(  address proposalManager_){
           actionManager = IAction(proposalManager_);

        }


        function propose(
            IAction.ProposalAction[] calldata actions,
            uint256 approvalWindow
        ) external notPaused returns (bytes32 proposalId) {

        proposalId = actionManager.propose(msg.sender, actions ,approvalWindow);
            emit Proposal(proposalId, msg.sender);
        }


      function _executeTransfer(IAction.ProposalAction memory action, uint256 idx) internal {
        if (action.target == address(0)) {
            if (address(this).balance < action.amount) revert AT_InsufficientBalance();
            (bool ok, ) = action.recipient.call{value: action.amount}("");
            if (!ok) revert AT_ActionFailed(idx);
        } else {
            bool ok = IERC20(action.target).transfer(action.recipient, action.amount);
            if (!ok) revert AT_ActionFailed(idx);
        }
    }



    function _executeCall(IAction.ProposalAction memory action, uint256 idx) internal {
        (bool ok, ) = action.target.call{value: action.value}(action.callData);
        if (!ok) revert AT_ActionFailed(idx);
    }


}