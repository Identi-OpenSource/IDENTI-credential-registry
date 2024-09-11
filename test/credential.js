const crypto = require('crypto');
const moment = require( "moment" );
const web3Abi = require( "web3-eth-abi" );
const web3Utils = require( "web3-utils" );
const ethUtil = require( "ethereumjs-util" );
const { expect } = require("chai");
const { ethers, lacchain } = require("hardhat");
const exp = require('constants');

const VERIFIABLE_CREDENTIAL_TYPEHASH = web3Utils.soliditySha3( "VerifiableCredential(address issuer,address subject,bytes32 data,uint256 validFrom,uint256 validTo)" );
const EIP712DOMAIN_TYPEHASH = web3Utils.soliditySha3( "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" );

const sleep = seconds => new Promise( resolve => setTimeout( resolve, seconds * 1e3 ) );

let attributes = [
    { name: 'nombre', value_type: 'string' },
    { name: 'edad', value_type: 'uint' },
    { name: 'fields', value_type: 'bool' },
    { name: 'size', value_type: 'uint' },
    { name: 'yield', value_type: 'uint' },
    { name: 'productivity', value_type: 'uint' },
    { name: 'sales', value_type: 'uint' },
    { name: 'sales2', value_type: 'uint' },
    { name: 'sales3', value_type: 'uint' },
    { name: 'sales4', value_type: 'uint' },
    { name: 'sales5', value_type: 'uint' },
    { name: 'sales6', value_type: 'uint' },
    { name: 'sales7', value_type: 'uint' }
  ];

let now = moment().toISOString();
let timestamp = Math.round(moment(now).valueOf() / 1000);

function getCredentialTYPEHASH(attributes) {
    let credentialString = 'VerifiableCredential(address issuer, address subject, uint256 validFrom, uint256 validTo, [';
    for (let i = 0; i < attributes.length; i++) {
      credentialString = credentialString + String(attributes[i].value_type) + ' ' + String(attributes[i].name) + ', ';
    }
    return web3Utils.soliditySha3(credentialString + '], bytes32 evidence)');
  }

function getSchemaID(author, name, version, timestamp) {
const encodeHashCredential = web3Abi.encodeParameters(
    ['address', 'string', 'uint16', 'uint256'],
    [author, name, version, timestamp]
);
const hashCredential = web3Utils.soliditySha3(encodeHashCredential);
return hashCredential;
}

function getArrayAttributeIDs(attributes) {
    let arrayAttributeIDs = [];
    for (let i = 0; i < attributes.length; i++) {
      arrayAttributeIDs.push(web3Utils.soliditySha3(String(attributes[i].value_type + ' ' + String(attributes[i].name))));
    }
    return arrayAttributeIDs;
  }

function sha256( data ) {
	const hashFn = crypto.createHash( 'sha256' );
	hashFn.update( data );
	return hashFn.digest( 'hex' );
}



function getCredentialHash(vc, attributes, issuer, claimsVerifierContractAddress) {
    const claim0 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[0]))}`;
    const claim1 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[1]))}`;
    const claim2 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[2]))}`;
    const claim3 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[3]))}`;
    const claim4 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[4]))}`;
    const claim5 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[5]))}`;
    const claim6 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[6]))}`;
    const claim7 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[7]))}`;
    const claim8 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[8]))}`;
    const claim9 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[9]))}`;
    const claim10 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[10]))}`;
    const claim11 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[11]))}`;
    const evidence = `0x${sha256(JSON.stringify(vc.credentialSubject.evidence))}`;
    const VERIFIABLE_CREDENTIAL_TYPEHASH = getCredentialTYPEHASH(attributes);
  
    const encodeEIP712Domain = web3Abi.encodeParameters(
      ['bytes32', 'bytes32', 'bytes32', 'uint256', 'address'],
      [EIP712DOMAIN_TYPEHASH, web3Utils.sha3('EIP712Domain'), web3Utils.sha3('1'), 648529, claimsVerifierContractAddress]
    );
    const hashEIP712Domain = web3Utils.soliditySha3(encodeEIP712Domain);
  
    const validFrom = new Date(vc.issuanceDate).getTime();
    const validTo = new Date(vc.expirationDate).getTime();
    const subjectAddress = vc.credentialSubject.id.split(':').slice(-1)[0];
    const encodeHashCredential = web3Abi.encodeParameters(
      ['bytes32', 'address', 'address', 'uint256', 'uint256', 'bytes32[]', 'bytes32'],
      [
        VERIFIABLE_CREDENTIAL_TYPEHASH,
        issuer.address,
        subjectAddress,
        Math.round(validFrom / 1000),
        Math.round(validTo / 1000),
        [claim0, claim1, claim2, claim3, claim4, claim5, claim6, claim7, claim8, claim9, claim10, claim11],
        evidence
      ]
    );
    const hashCredential = web3Utils.soliditySha3(encodeHashCredential);
  
    const encodedCredentialHash = web3Abi.encodeParameters(
      ['bytes32', 'bytes32'],
      [hashEIP712Domain, hashCredential.toString(16)]
    );
    return web3Utils.soliditySha3('0x1901'.toString(16) + encodedCredentialHash.substring(2, 131));
  }

function signCredential( credentialHash, issuer ) {
	const rsv = ethUtil.ecsign(
		Buffer.from( credentialHash.substring( 2, 67 ), 'hex' ),
		Buffer.from( issuer.privateKey, 'hex' )
	);
	return ethUtil.toRpcSig( rsv.v, rsv.r, rsv.s );
}

describe("Verifiable Credentials", function () {
	this.timeout(400000);

	let credentialRegistryAddress, claimsVerifierAddress;

	const accounts = lacchain.getSigners();

	const subject = accounts[1].address;
	const issuer = {
		address: accounts[0].address, //
		privateKey: ''
	};
	const signers = [{
		address: accounts[2].address, //
		privateKey: ''
	}];

	const vc = {
        '@context': 'https://www.w3.org/2018/credentials/v1',
        id: '73bde252-cb3e-44ab-94f9-eba6a8a2f28d',
        type: 'VerifiableCredential',
        issuer: `did:lac:main:${issuer.address}`,
        issuanceDate: moment().toISOString(),
        expirationDate: moment().add(1, 'years').toISOString(),
        credentialSubject: {
          id: `did:lac:main:${subject}`,
          claims: ['Robinson Lopez', 32, true, 2, 500, 1200, 14500, 14500, 14500, 14500, 14500, 14500],
          evidence: 'https://agros.tech/evidence/123af2.png',
          schemaID: getSchemaID(accounts[0].address, 'Test Schema', 1, timestamp)
        },
        proof: []
      };

    before( async() => {
        const CredentialRegistry = await ethers.getContractFactory("CredentialRegistry", accounts[0]);        
		const credentialRegistry = await lacchain.deployContract(CredentialRegistry);

		const ClaimsVerifier = await ethers.getContractFactory("IDENTIClaimsVerifier", accounts[0]);
		const claimsVerifier = await lacchain.deployContract(ClaimsVerifier, credentialRegistry.address);

        claimsVerifierAddress = claimsVerifier.address;
		credentialRegistryAddress = credentialRegistry.address;
		console.log('ClaimsVerifier', claimsVerifier.address);
		console.log('CredentialRegistry', credentialRegistry.address);

        const tx1 = await credentialRegistry.grantRole( '0x114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa122', claimsVerifier.address );
		await tx1.wait();
		const tx2 = await claimsVerifier.grantRole( '0x114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa122', issuer.address );
		await tx2.wait();
		const tx3 = await claimsVerifier.grantRole( '0xe2f4eaae4a9751e85a3e4a7b9587827a877f29914755229b07a7b2da98285f70', signers[0].address );
		await tx3.wait();
    } )

    it('should register a new Schema', async () => {
        const ClaimsVerifier = await ethers.getContractFactory("IDENTIClaimsVerifier", accounts[0]);
        const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );
        const tx = await claimsVerifier.registerNewSchema(
          'Test Schema',
          1,
          'Schema Designed for Test',
          timestamp,
          accounts[0].address,
          'Test',
          getCredentialTYPEHASH(attributes),
          getArrayAttributeIDs(attributes)
        );
        await tx.wait();
        let counter = await claimsVerifier.getSchemaCounter();
        expect(counter).to.equal(1);
        //assert.equal(counter, 1);
      });

    it( "should register a VC", async() => {
        const ClaimsVerifier = await ethers.getContractFactory("IDENTIClaimsVerifier", accounts[0]);
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

        const credentialHash = getCredentialHash( vc, attributes, issuer, claimsVerifier.address );
        console.log('credentialHash >>', credentialHash);

		const signature = await signCredential( credentialHash, issuer);

        const tx = await claimsVerifier.registerCredential( subject, credentialHash,
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 ),
			signature, { from: issuer.address } );

		vc.proof.push( {
			id: vc.issuer,
			type: "EcdsaSecp256k1Signature2019",
			proofPurpose: "assertionMethod",
			verificationMethod: `${vc.issuer}#vm-0`,
			domain: claimsVerifier.address,
			proofValue: signature
		} );

		await tx.wait();

		return expect( tx.hash ).to.not.null;
    }  );

    it( "should verify a VC", async() => {
		const ClaimsVerifier = await ethers.getContractFactory("IDENTIClaimsVerifier");
		const claimsVerifier = ClaimsVerifier.attach( claimsVerifierAddress );

        const claim0 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[0]))}`;
        const claim1 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[1]))}`;
        const claim2 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[2]))}`;
        const claim3 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[3]))}`;
        const claim4 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[4]))}`;
        const claim5 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[5]))}`;
        const claim6 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[6]))}`;
        const claim7 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[7]))}`;
        const claim8 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[8]))}`;
        const claim9 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[9]))}`;
        const claim10 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[10]))}`;
        const claim11 = `0x${sha256(JSON.stringify(vc.credentialSubject.claims[11]))}`;
        
        const evidence = `0x${sha256(JSON.stringify(vc.credentialSubject.evidence))}`;
		
		const rsv = ethUtil.fromRpcSig( vc.proof[0].proofValue );

		const tx = await claimsVerifier.verifyClaim( [
			vc.issuer.replace( 'did:lac:main:', '' ),
			vc.credentialSubject.id.replace( 'did:lac:main:', '' ),
			Math.round( moment( vc.issuanceDate ).valueOf() / 1000 ),
			Math.round( moment( vc.expirationDate ).valueOf() / 1000 ),
            [claim0, claim1, claim2, claim3, claim4, claim5, claim6, claim7, claim8, claim9, claim10, claim11],
            evidence,
            vc.credentialSubject.schemaID
		], rsv.v, rsv.r, rsv.s );
        
        //await tx.wait();

        console.log('result >>', tx);
		const credentialExists = tx[0];
		const isNotRevoked = tx[1];
		const issuerSignatureValid = tx[2];
		const additionalSigners = tx[3];
		const isNotExpired = tx[4];

		expect( credentialExists ).to.equal( true );
		expect( isNotRevoked) .to.equal( true );
		expect( issuerSignatureValid ).to.equal( true );
		expect( additionalSigners ).to.equal( false );
		expect( isNotExpired ).to.equal( true );
	} );
    

});
