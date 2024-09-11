# IDENTI credential registry

## Introduction.

In this repository are the smart contracts based on [EIP-712](https://eips.ethereum.org/EIPS/eip-712) and [EIP-1812](https://eips.ethereum.org/EIPS/eip-1812) for Structured Data Types and Verifiable Claims respectively, adapted dto IDENTI claims proposal incluiding Schemas to perform the registration and verification process of [Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) on-chain.

## Schemas Concept Introduces.

We have introduced a Schema Register Concept to the Credential Registry SmartContract, where
VCs need to be referenced with a Schema ID built by author DID, name of the Schema, Version and
Timestamp.

```solidity
  function registerNewSchema(
    string calldata name,
    uint16 version,
    string calldata description,
    uint256 timestamp,
    address author,
    string calldata category,
    bytes32 TYPEHASH,
    bytes32[] memory attributeIDs
  ) external {
    bytes32 schema_identifier = keccak256(abi.encode(author, name, version, timestamp));

    schemas[schema_identifier] = schema({
      name: name,
      version: version,
      description: description,
      registerTimeStamp: timestamp,
      author: author,
      category: category,
      attributesIDs: attributeIDs,
      TYPEHASH: TYPEHASH
    });

    schemaCounter++;

    emit schemaRegistered(schema_identifier, schemaCounter);
  }
```

This helps to keep a standard for VCs format and help data shareability between members of the
IDENTI ecosystem.

## Usage.

### OpenZepellin.

We are currently using las version 5.x of Open Zepellin contracts.

### Polygon and Celo

For interacting with Celo and Polygon mainnets CredentialRegistry SmartContract and IDENTIClaimsVerifier Proxy Smart Contract can be deployed without modification

### DID Registries.

DID Registries follows the DID:Ethr method developed by uPort and current deployed implementations for testing and usage can be found here.
DID Registry Celo: 0x110A4b86550f3f7eda49bA7542507cb01A4d09F6
DID Registry Polygon: 0x0B4495F64826d5C8FfA5b88fc9716A54d3C3AEAc

### Lacchain Gas Station Network

To use this repository for Lacchain GSN implementation, change these two Smart Contracts.

- Access Control

```solidity
function _checkRole(bytes32 role) internal virtual {
        _checkRole(role, _msgSender());
    }
```

Here we should change the type of function deleting "view" modificator, because now \_msgSender modificates de state of the block, performing an operation to check for the forwarder address, but in next version this will be adapted to current Open Gas Station Network Standard.

- Context

```solidity
abstract contract Context {

    address internal trustedForwarder = "Trusded Fordwarder Address";

    function _msgSender() internal virtual returns (address sender) {
        bytes memory bytesSender;
        (,bytesSender) = trustedForwarder.call(abi.encodeWithSignature("getMsgSender()"));

        if( msg.sender != trustedForwarder ) return msg.sender;
        return abi.decode(bytesSender, (address));
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}
```

Trusted fordwarder should be changed. Currently our Address for Trusted Fordwarder is: [address]

hardhat.config need to be updated incluiding lacnet network params, and at least 3 private keys in array format for building accounts and accomplish the tests and implement lacnet functionalities.

```javascript
require("@nomiclabs/hardhat-waffle");
require("./extender");
module.exports = {
solidity: "0.8.20",
lacchain: {
      url: '',
      nodeAddress: '',
      expiration: ,
      gasPrice: 0,
      accounts: [
        'Acc0',
        'Acc1',
        'Acc2'
      ],
    }
}
```

Finally use this commands.

```shell
npx hardhat help
npx hardhat test --network lacchain
npx hardhat run scripts/deploy.js
```
