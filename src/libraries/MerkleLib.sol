// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;
library MerkleLib {

    function computeLeaf(address recipient, uint256 amount) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(keccak256(abi.encodePacked(recipient, amount))));
    }



     function verify(
        bytes32            root,
        bytes32            leaf,
        bytes32[] calldata proof
    ) internal pure returns (bool valid) {
        bytes32 computed = leaf;
        uint256 len = proof.length;

        for (uint256 i; i < len; ) {
            bytes32 sibling = proof[i];
            computed = (computed < sibling)
                ? keccak256(abi.encodePacked(computed, sibling))
                : keccak256(abi.encodePacked(sibling, computed));
            unchecked { ++i; }
        }

        valid = (computed == root);
    }
}