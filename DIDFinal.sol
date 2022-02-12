// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

// import "../interface/IDid.sol";
// import "./MixinDidStorage.sol";
// import "../libs/DidUtils.sol";
// import "../libs/KeyUtils.sol";
// import "../libs/BytesUtils.sol";
// import "../libs/ZeroCopySink.sol";
// import "../libs/ZeroCopySource.sol";
// import "../libs/StorageUtils.sol";

/**
 * @title DIDContract
 * @dev This contract is did logic implementation
 */


contract DIDContract {

    struct PublicKey {
        string id;
        string owner;
        string methodType;
        string publicKey;
    }

    struct DIDDocument {
        string[] context;
        string id;
        PublicKey publicKey;
    }

    event CreateDidEvent(string id);
    event GetDidEvent(DIDDocument did);

    mapping(string => DIDDocument) public didStore;
    string empty = "";

    string[] context = ["https://www.w3.org/ns/did/v1","https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld"];

    modifier checkDidExists(string memory _did) {
        require(bytes(didStore[_did].id).length != 0,"DID does not exist");
        _;
    }

    function getDid(string memory did) public checkDidExists(did) returns (DIDDocument memory)  {
        emit GetDidEvent(didStore[did]);
        return didStore[did];
    }

    function createDID(string memory addr, string memory pubKey) public returns (string memory) {
        // require(addr!=address(0x0),"Parameters cannot be null");
        // require(keccak256(bytes(pubKey).length) == keccak256(bytes(empty)),"Parameters cannot be null");
        require(bytes(pubKey).length != 0,"Parameters cannot be null");
        require(bytes(addr).length != 0,"Parameters cannot be null");
        bytes memory b;
        b = abi.encodePacked("did:ethr:");
        b = abi.encodePacked(b, addr);  
        // string memory base = "did:ethr:";
        string memory id= string(b);
        PublicKey memory publicKey;
        b = abi.encodePacked(id);
        b = abi.encodePacked(b, "#keys-1");  
        // string memory base = "did:ethr:";
        // string memory id= string(b);
        publicKey.id = string(b);
        publicKey.owner= id;
        publicKey.methodType= "Ed25519VerificationKey2020";
        publicKey.publicKey= pubKey;
        // DIDDocument memory did;
        didStore[id].context = context;
        didStore[id].id = id;
        didStore[id].publicKey=publicKey; 
        emit CreateDidEvent(id);
        return id;
    } 
}