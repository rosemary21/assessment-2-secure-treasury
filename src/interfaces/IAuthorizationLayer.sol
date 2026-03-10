// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
interface IAuthorizationLayer {

    struct SignerState {
        bool    active;
        uint256 nonce;  
    }

     event SignatureConsumed(
        address indexed signer,
        bytes32 indexed proposalId,
        uint256         consumedNonce
    );
}
