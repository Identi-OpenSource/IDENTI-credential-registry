//SPDX-License-Identifier: UNLICENSED

pragma solidity >=0.8;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/extensions/AccessControlEnumerable.sol";
import "./AbstractClaimsVerifier.sol";
import "./Schemas.sol";

contract IDENTIClaimsVerifier is AbstractClaimsVerifier, Schemas, AccessControlEnumerable {

    using ECDSA for bytes32;

    bytes32 public constant ISSUER_ROLE = keccak256("ISSUER_ROLE");
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    constructor (address _registryAddress)
    AbstractClaimsVerifier(
        "EIP712Domain",
        "1",
        648529,
        address(this),
        _registryAddress
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function verifyClaim(VerifiableCredential memory vc, uint8 v, bytes32 r, bytes32 s) public view returns (bool, bool, bool, bool, bool) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                hashVerifiableCredential(vc)
            )
        );

        return (_exist(digest, vc.issuer), _isActive(digest, vc.issuer), _verifyIssuer(digest, vc.issuer, v, r, s), (_verifySigners(digest, vc.issuer) == getRoleMemberCount(keccak256("SIGNER_ROLE"))), _validPeriod(vc.validFrom, vc.validTo));
    }

    function verifyClaimSigner(VerifiableCredential memory vc, bytes calldata _signature) public view returns (bool){
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                hashVerifiableCredential(vc)
            )
        );

        address signer = digest.recover(_signature);
        return hasRole(SIGNER_ROLE, signer) && _isSigner(digest, vc.issuer, _signature);
    }

    function registerCredential(address _subject, bytes32 _credentialHash, uint256 _from, uint256 _exp, bytes calldata _signature) public onlyIssuer returns (bool) {
        address signer = _credentialHash.recover(_signature);
        require(_msgSender() == signer, "Sender hasn't signed the credential");
        return _registerCredential(_msgSender(), _subject, _credentialHash, _from, _exp);
    }

    function registerSignature(bytes32 _credentialHash, address issuer, bytes calldata _signature) public onlySigner returns (bool){
        address signer = _credentialHash.recover(_signature);
        require(_msgSender() == signer, "Sender hasn't signed the credential");
        return _registerSignature(_credentialHash, issuer, _signature);
    }

    modifier onlyAdmin(){
        require(hasRole(DEFAULT_ADMIN_ROLE, _msgSender()), "Caller is not Admin");
        _;
    }

    modifier onlySigner() {
        require(hasRole(SIGNER_ROLE, _msgSender()), "Caller is not a signer");
        _;
    }

    modifier onlyIssuer() {
        require(hasRole(ISSUER_ROLE, _msgSender()), "Caller is not a issuer 1");
        _;
    }

}
