// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EvidenceManagement {

    struct Evidence {
        string evidenceId;
        string fileHash;
        string fileName;
        string caseId;
        address owner;
        uint256 timestamp;
        bool exists;
    }

    struct CustodyRecord {
        string evidenceId;
        string action;
        address actor;
        string note;
        uint256 timestamp;
    }

    mapping(string => Evidence) public evidences;
    mapping(string => CustodyRecord[]) public custodyChain;
    mapping(bytes32 => bool) public accessRequests;

    event EvidenceAdded(string evidenceId, string fileHash, address owner, uint256 timestamp);
    event CustodyTransferred(string evidenceId, string action, address actor, uint256 timestamp);
    event AccessGranted(bytes32 evidenceHash, address requester, string token, uint256 timestamp);

    function addEvidence(
        string memory _id,
        string memory _hash,
        string memory _fileName,
        string memory _caseId
    ) public {
        require(!evidences[_id].exists, "Evidence already registered");

        evidences[_id] = Evidence({
            evidenceId: _id,
            fileHash: _hash,
            fileName: _fileName,
            caseId: _caseId,
            owner: msg.sender,
            timestamp: block.timestamp,
            exists: true
        });

        custodyChain[_id].push(CustodyRecord({
            evidenceId: _id,
            action: "Collected",
            actor: msg.sender,
            note: "Initial evidence registration",
            timestamp: block.timestamp
        }));

        emit EvidenceAdded(_id, _hash, msg.sender, block.timestamp);
    }

    function transferEvidence(
        string memory _id,
        string memory _action,
        string memory _note
    ) public {
        require(evidences[_id].exists, "Evidence not found");

        custodyChain[_id].push(CustodyRecord({
            evidenceId: _id,
            action: _action,
            actor: msg.sender,
            note: _note,
            timestamp: block.timestamp
        }));

        emit CustodyTransferred(_id, _action, msg.sender, block.timestamp);
    }

    function getEvidence(string memory _id)
        public view returns (
            string memory fileHash,
            string memory fileName,
            string memory caseId,
            address owner,
            uint256 timestamp
        )
    {
        require(evidences[_id].exists, "Evidence not found");
        Evidence memory e = evidences[_id];
        return (e.fileHash, e.fileName, e.caseId, e.owner, e.timestamp);
    }

    function getCustodyCount(string memory _id) public view returns (uint256) {
        return custodyChain[_id].length;
    }

    function getCustodyRecord(string memory _id, uint256 index)
        public view returns (
            string memory action,
            address actor,
            string memory note,
            uint256 timestamp
        )
    {
        require(index < custodyChain[_id].length, "Index out of bounds");
        CustodyRecord memory r = custodyChain[_id][index];
        return (r.action, r.actor, r.note, r.timestamp);
    }

    function evidenceExists(string memory _id) public view returns (bool) {
        return evidences[_id].exists;
    }

    function requestAccess(bytes32 evidenceHash, string memory token) public {
        require(bytes(token).length > 0, "Token required");
        accessRequests[evidenceHash] = true;
        emit AccessGranted(evidenceHash, msg.sender, token, block.timestamp);
    }
}
