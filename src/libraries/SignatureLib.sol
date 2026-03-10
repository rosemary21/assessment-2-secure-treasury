// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library SignatureLib {


bytes32 internal constant APPROVAL_TYPEHASH = keccak256(
        "ProposalApproval("
            "bytes32 proposalId,"
            "bytes32 actionsHash,"
            "address signer,"
            "uint256 signerNonce,"
            "uint256 chainId"
        ")"
    );


     uint256 internal constant HALF_N =
        0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

  function tryRecoverSigner(
        bytes32        domainSeparator,
        bytes32        proposalId,
        bytes32        actionsHash,
        address        signer,
        uint256        signerNonce,
        bytes calldata signature
    ) internal view returns (address recovered) {
        if (signature.length != 65) return address(0);

        bytes32 r;
        bytes32 s;
        uint8   v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        // Reject high-s (malleability) — return zero rather than revert
        if (uint256(s) > HALF_N) return address(0);

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return address(0);

        bytes32 structHash = keccak256(abi.encode(
            APPROVAL_TYPEHASH,
            proposalId,
            actionsHash,
            signer,
            signerNonce,
            block.chainid
        ));

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        recovered = ecrecover(digest, v, r, s);
    }

}