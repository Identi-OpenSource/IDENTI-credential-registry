// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

contract Schemas {
  //This version deletes the AttributeRegistry to avoid memory exced during calls and still has no implemented the Attributes funcionts.
  //Attributes functions will be changed to Attributes Verification and Schema Verification functions.

  struct schema {
    string name;
    uint16 version;
    string description;
    uint256 registerTimeStamp;
    address author;
    string category;
    bytes32[] attributesIDs;
    bytes32 TYPEHASH;
  }

  struct VerifiableCredential {
    address issuer;
    address subject;
    uint256 validFrom;
    uint256 validTo;
    bytes32[] claims;
    bytes32 evidence;
    bytes32 schemaID;
  }

  uint32 internal schemaCounter = 0;
  uint256 internal testVar = 0;

  mapping(bytes32 => schema) schemas;

  address owner;

  event schemaRegistered(bytes32 identifier, uint32 counter);

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

  function getSchema(bytes32 identifier) external view returns (schema memory) {
    return schemas[identifier];
  }

  function getSchemaCounter() external view returns (uint32) {
    return schemaCounter;
  }

  function getOwner() external view returns (address) {
    return owner;
  }

  //function getAttribute(bytes32 identifier) external view returns (attribute memory) {
  //  return attributeRegistry[identifier];
  //}

  function hashVerifiableCredential(VerifiableCredential memory vc) internal view returns (bytes32) {
    schema memory schemaReference = schemas[vc.schemaID];
    return keccak256(abi.encode(schemaReference.TYPEHASH, vc.issuer, vc.subject, vc.validFrom, vc.validTo, vc.claims, vc.evidence));
  }
}
