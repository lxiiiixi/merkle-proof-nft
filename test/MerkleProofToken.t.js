const {
  loadFixture,
} = require("@nomicfoundation/hardhat-toolbox/network-helpers");
const { expect } = require("chai");
const { MerkleTree } = require("merkletreejs");
const keccak256 = require("keccak256");
const { ethers } = require("hardhat");

describe("Deploy", function () {
  const abiCoder = new ethers.AbiCoder();
  let owner, otherAccount;

  async function deployFixture() {
    [owner, ...otherAccount] = await ethers.getSigners();

    const leaves = otherAccount.map((x, i) => keccak256(keccak256(abiCoder.encode(["address", "uint256"], [x.address, i]))));
    const tree = new MerkleTree(leaves, keccak256, { sortPairs: true });
    const root = tree.getRoot().toString("hex");

    console.log(`tree: ${tree.toString()}`);
    console.log(`root: ${root}`);

    const MerkleProofToken = await ethers.getContractFactory("MerkleProofToken");
    const instance = await MerkleProofToken.deploy("0x" + root);

    return { instance, tree, root };
  }

  function getProof(tree, address, tokenId) {
    const leaf = keccak256(keccak256(abiCoder.encode(["address", "uint256"], [address, tokenId])));
    const proof = tree.getProof(leaf).map(x => x.data);
    return proof
  }

  describe("Deployment", function () {
    it("Verify", async function () {
      const { instance, tree, root } = await loadFixture(deployFixture);

      // verify owner
      const leaf = keccak256(keccak256(abiCoder.encode(["address", "uint256"], [otherAccount[0].address, 0])));
      const proof = tree.getProof(leaf);
      for (let i = 0; i < proof.length; i++) {
        console.log(`${i} element position: ${proof[i].position} data: ${MerkleTree.bufferToHex(proof[i].data)}`)
      }
      // verify by MerkleTree
      expect(tree.verify(proof, leaf, root)).to.equal(true);
      // verify by contract function
      expect(await instance.isValidWhitelistAddress(leaf, getProof(tree, otherAccount[0].address, 0))).to.equal(true);
      // wrong tokenId will return false
      expect(await instance.isValidWhitelistAddress(leaf, getProof(tree, otherAccount[0].address, 1))).to.equal(false);
      // by getHexProof
      expect(await instance.isValidWhitelistAddress(leaf, tree.getHexProof(otherAccount[0].address, 0))).to.equal(true);
    });

    it("SafeMint", async function () {
      const { instance, tree } = await loadFixture(deployFixture);

      // owner is not included in the whitelist: will fail
      await expect(instance.safeMint(owner.address, 0, getProof(tree, owner.address, 0)))
        .to.revertedWith('Not a valid whitelist address')
      // wrong tokenId will fail
      await expect(instance.connect(otherAccount[0]).safeMint(otherAccount[0].address, 0, getProof(tree, otherAccount[0].address, 1)))
        .to.revertedWith('Not a valid whitelist address')
      // wrong caller
      await expect(instance.connect(otherAccount[1]).safeMint(otherAccount[0].address, 0, getProof(tree, otherAccount[0].address, 0)))
        .to.revertedWith('Not a valid whitelist address')
      // will success
      await instance.connect(otherAccount[0]).safeMint(otherAccount[0].address, 0, getProof(tree, otherAccount[0].address, 0))
      // only once
      await expect(instance.connect(otherAccount[0]).safeMint(otherAccount[0].address, 0, getProof(tree, otherAccount[0].address, 2)))
        .to.revertedWith('Whitelist spot already claimed byt his address')

      expect(await instance.ownerOf(0)).to.equal(otherAccount[0].address);
    });
  });
});
