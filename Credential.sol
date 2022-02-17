// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.6.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "./CredentialSchema.sol";

contract CredContract is CredentialSchema {
    struct Credential {
        string id;
        string owner;
        string issuer;
        string ipfsHash;
    }

    // event GiveAccess(string);
    // event RevokeAccess(string);
    event CreateCredential(string did);
    event GetCredential(Credential credential);

    // mapping(string => string[]) accessStore;
    mapping(string => Credential) credentialStore;

    // function giveAccess(string memory ownerDID, string memory credDID, string memory recieverDID)
    //     public checkDidExists(ownerDID) checkDidExists(recieverDID) {
    //     require(
    //         bytes(credentialStore[credDID].id).length != 0,
    //         "Credential Schema does not exist"
    //     );
    //     Credential memory tempCred = credentialStore[credDID];
    //     require(
    //         keccak256(abi.encodePacked(ownerDID)) != keccak256(abi.encodePacked(tempCred.owner)),
    //         "Not the owner"
    //     );
    //     string[] storage tempArr = accessStore[recieverDID];
    //     for(uint i = 0; i < tempArr.length; i++) {
    //         if(keccak256(abi.encodePacked(credDID)) == keccak256(abi.encodePacked(tempArr[i]))) {
    //             emit GiveAccess("Access already given");
    //             return;
    //         }
    //     }
    //     tempArr.push(credDID);
    //     accessStore[recieverDID] = tempArr;
    //     emit GiveAccess("Access given to new user");
    // }

    // function revokeAccess(string memory ownerDID, string memory credDID, string memory recieverDID)
    //     public checkDidExists(ownerDID) checkDidExists(recieverDID) {
    //     require(
    //         bytes(credentialStore[credDID].id).length != 0,
    //         "Credential Schema does not exist"
    //     );
    //     Credential memory tempCred = credentialStore[credDID];
    //     require(
    //         keccak256(abi.encodePacked(ownerDID)) != keccak256(abi.encodePacked(tempCred.owner)),
    //         "Not the owner"
    //     );
    //     string[] storage tempArr = accessStore[recieverDID];
    //     for(uint i = 0; i < tempArr.length; i++) {
    //         if(keccak256(abi.encodePacked(credDID)) == keccak256(abi.encodePacked(tempArr[i]))) {
    //             emit RevokeAccess("Access revoked");
    //             delete tempArr[i];
    //             accessStore[recieverDID] = tempArr;
    //             return;
    //         }
    //     }
    //     emit RevokeAccess("No access to begin with");
    // }

    function getCredential(string memory did)
        public
        returns (Credential memory)
    {
        require(
            bytes(credentialStore[did].id).length != 0,
            "Credential does not exist"
        );
        emit GetCredential(credentialStore[did]);
        return credentialStore[did];
    }

    function createCredential(
        string memory ownerDID,
        string memory issuerDID,
        string memory hash,
        string memory ipfsHash
    ) public checkDidExists(ownerDID) checkDidExists(issuerDID) returns(string memory) {
        bytes memory b = abi.encodePacked("did:cred:");
        b = abi.encodePacked(b, hash);
        string memory did = string(b);
        credentialStore[did].id = did;
        credentialStore[did].owner = ownerDID;
        credentialStore[did].issuer = issuerDID;
        credentialStore[did].ipfsHash = ipfsHash;
        // string[] storage tempArr = accessStore[ownerDID];
        // tempArr.push(did);
        // tempArr = accessStore[issuerDid];
        // tempArr.push(did);
        emit CreateCredential(did);
        return did;
    }
}
