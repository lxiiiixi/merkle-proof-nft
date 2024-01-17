// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleProofToken is ERC721, Ownable {
    bytes32 public root;
    mapping(address => bool) public whitelistClaimed;

    constructor(
        bytes32 _root
    ) ERC721("MerkleProofToken", "MPT") Ownable(msg.sender) {
        root = _root;
    }

    function safeMint(
        address to,
        uint256 tokenId,
        bytes32[] memory proof
    ) public {
        require(
            !whitelistClaimed[msg.sender],
            "Whitelist spot already claimed byt his address"
        );
        bytes32 leaf = keccak256(
            bytes.concat(keccak256(abi.encode(msg.sender, tokenId)))
        );
        require(
            isValidWhitelistAddress(leaf, proof),
            "Not a valid whitelist address"
        );
        whitelistClaimed[msg.sender] = true;
        _safeMint(to, tokenId);
    }

    function isValidWhitelistAddress(
        bytes32 leaf,
        bytes32[] memory proof
    ) public view returns (bool) {
        return MerkleProof.verify(proof, root, leaf);
    }
}
