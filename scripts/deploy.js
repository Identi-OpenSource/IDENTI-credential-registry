// We require the Hardhat Runtime Environment explicitly here. This is optional
// but useful for running the script in a standalone fashion through `node <script>`.
//
// You can also run a script with `npx hardhat run <script>`. If you do that, Hardhat
// will compile your contracts, add the Hardhat Runtime Environment's members to the
// global scope, and execute the script.
// const hre = require("hardhat");
// const fs = require('fs');
// const path = require('path');

const { lacchain, ethers } = require('hardhat');

async function main() {
  const accounts = lacchain.getSigners();

  const CredentialRegistry = await ethers.getContractFactory('CredentialRegistry', accounts[0]);
  const credentialRegistry = await lacchain.deployContract(CredentialRegistry);

  const ClaimsVerifier = await ethers.getContractFactory('IDENTIClaimsVerifier', accounts[0]);
  const claimsVerifier = await lacchain.deployContract(ClaimsVerifier, credentialRegistry.address);

  console.log('Credential Registry Addres:', credentialRegistry.address);
  console.log('IDENTI Claims Addres:', claimsVerifier.address);
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
