// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "../interfaces/IRewardDistributor.sol";
import "../libraries/MerkleLib.sol";


interface IERC20Minimal {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}


contract RewardDistributor is IRewardDistributor {

    using MerkleLib for bytes32;

    error RD_ETHTransferFailed();
    error RD_EpochNotFound();
    error RD_ZeroAmount();
    error RD_InvalidProof();
    error RD_AlreadyClaimed();



    mapping(uint256 => mapping(address => bool))  private _claimed;

    mapping(uint256 => RewardEpoch)               private _epochs;


    function _transferOut(address token, address recipient, uint256 amount) internal {
        if (token == address(0)) {
            (bool ok, ) = recipient.call{value: amount}("");
            if (!ok) revert RD_ETHTransferFailed();
        } else {
            bool ok = IERC20Minimal(token).transfer(recipient, amount);
            require(ok, "RD: transfer failed");
        }
    }


     struct RewardEpoch {
        bytes32 merkleRoot;
        address token;           
        uint256 totalDeposited;
        uint256 totalClaimed;
        uint256 createdAt;
        bool    finalized;      
    }


     function _requireEpoch(uint256 epochId)
        internal view returns (RewardEpoch storage epoch)
    {
        epoch = _epochs[epochId];
        if (epoch.createdAt == 0) revert RD_EpochNotFound();
    }



    function claim(
        uint256          epochId,
        address          recipient,
        uint256          amount,
        bytes32[] calldata proof
    ) external {
        if (recipient == address(0)) revert RD_EpochNotFound();

        RewardEpoch storage epoch = _requireEpoch(epochId);
        if (amount == 0)                          revert RD_ZeroAmount();
        if (_claimed[epochId][recipient])          revert RD_AlreadyClaimed();

        bytes32 leaf = MerkleLib.computeLeaf(recipient, amount);
        if (!MerkleLib.verify(epoch.merkleRoot, leaf, proof)) revert RD_InvalidProof();

        _claimed[epochId][recipient]  = true;
        epoch.totalClaimed           += amount;

        _transferOut(epoch.token, recipient, amount);

        emit RewardClaimed(epochId, recipient, amount);
    }


}