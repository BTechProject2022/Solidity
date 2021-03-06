// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "./DID.sol";

contract CredentialSchema is DIDContract {
    struct CredSchema {
        string[] context;
        string id;
        string ipfsHash;
    }

    event CreateCredSchema(string did);
    event GetCredSchema(CredSchema credSchema);

    mapping(string => CredSchema) public credSchemaStore;

    string[] schemaContext = [
        "https://w3id.org/did/v1",
        "https://w3id.org/security/v2",
        "https://w3c-ccg.github.io/vc-json-schemas/context/vc-json-schema-v0.0.jsonld"
    ];

    function getCredSchema(string memory did)
        public
        returns (CredSchema memory)
    {
        require(
            bytes(credSchemaStore[did].id).length != 0,
            "DID does not exist"
        );
        emit GetCredSchema(credSchemaStore[did]);
        return credSchemaStore[did];
    }

    function createCredSchema(
        string memory issuerDid,
        string memory hash,
        string memory ipfsHash
    ) public checkDidExists(issuerDid) returns (string memory) {
        bytes memory b;
        b = abi.encodePacked("did:schm:");
        b = abi.encodePacked(b, hash);
        string memory did = string(b);
        credSchemaStore[did].id = did;
        credSchemaStore[did].ipfsHash = ipfsHash;
        credSchemaStore[did].context = schemaContext;
        emit CreateCredSchema(did);
        return did;
    }
}
