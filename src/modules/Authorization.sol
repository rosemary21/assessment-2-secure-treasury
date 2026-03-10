// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import "../interfaces/IAuthorizationLayer.sol";
import "../libraries/SignatureLib.sol";



contract Authorization is IAuthorizationLayer{


    address public immutable coordinator;

    modifier onlyCoordinator() {
        if (msg.sender != coordinator) revert AL_OnlyCoordinator();
        _;
    }



    mapping(address => SignerState) private _signers;

    error AL_OnlyCoordinator();


    error AL_ArrayLengthMismatch();
    mapping(bytes32 => mapping(address => bool)) private _proposalApprovals;
    bytes32 private immutable _domainSeparator;


    function verifyAndConsume(
        bytes32           proposalId,
        bytes32           actionsHash,
        address[] calldata signers,
        bytes[]   calldata signatures
    ) external onlyCoordinator returns (uint256 validCount, address[] memory validSigners) {
        if (signers.length != signatures.length) revert AL_ArrayLengthMismatch();

        address[] memory tempValid = new address[](signers.length);
        
        uint256 count;

        for (uint256 i; i < signers.length; ) {
            address claimedSigner = signers[i];

            if (!_signers[claimedSigner].active || _proposalApprovals[proposalId][claimedSigner]) {
                unchecked { ++i; }
                continue;
            }

            uint256 currentNonce = _signers[claimedSigner].nonce;

           
            address recovered = SignatureLib.tryRecoverSigner(
                _domainSeparator,
                proposalId,
                actionsHash,
                claimedSigner,
                currentNonce,
                signatures[i]
            );

            if (recovered != claimedSigner) {
                unchecked { ++i; }
                continue;
            }

            _proposalApprovals[proposalId][claimedSigner] = true;
            _signers[claimedSigner].nonce = currentNonce + 1;

            tempValid[count] = claimedSigner;
            unchecked { ++count; ++i; }

            emit SignatureConsumed(claimedSigner, proposalId, currentNonce);
        }

        validSigners = new address[](count);
        for (uint256 j; j < count; ) {
            validSigners[j] = tempValid[j];
            unchecked { ++j; }
        }
        validCount = count;
    }


    
}