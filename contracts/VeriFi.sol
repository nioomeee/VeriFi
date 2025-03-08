// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract VeriFi is AccessControl {
    using Strings for string;

    bytes32 public constant VERIFIER_ROLE = keccak256("VERIFIER_ROLE");

    struct Document {
        string title;
        string description;
        string documentType;
        string ipfsCID;
        address uploader;
    }

    mapping(uint256 => Document) public documents;
    mapping(uint256 => bool) public documentExists;
    mapping(address => uint256[]) public userDocuments;
    mapping(string => address) public hexCodeToUser;
    mapping(address => mapping(uint256 => address[])) public documentAccess;
    mapping(bytes32 => uint256) public expirationTimestamps; // Maps hash to expiration timestamp
    mapping(uint256 => bytes32) public documentHashes; // Maps documentId to its unique hash

    event DocumentUploaded(uint256 indexed documentId, string title, string description, string documentType, address indexed uploader, string ipfsCID);
    event DocumentDeleted(uint256 indexed documentId, address indexed verifier);
    event HexCodeGenerated(string indexed hexCode, address indexed user);
    event AccessRequested(address indexed user, uint256 indexed documentId, address indexed employer);
    event AccessApproved(address indexed employer, uint256 indexed documentId, address indexed user);
    event AccessRejected(address indexed employer, uint256 indexed documentId, address indexed user);
    event AccessRevoked(address indexed employer, uint256 indexed documentId, address indexed user);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

    function uploadDocument(
        uint256 documentId,
        string memory title,
        string memory description,
        string memory documentType,
        string memory ipfsCID,
        string memory ipfsURL,
        uint256 expirationTime // New parameter for expiration time
    ) external onlyRole(VERIFIER_ROLE) {
        require(!documentExists[documentId], "Document already exists");
        require(bytes(title).length > 0, "Title cannot be empty");
        require(bytes(documentType).length > 0, "Document type cannot be empty");
        require(bytes(ipfsCID).length > 0, "IPFS CID cannot be empty");
        require(bytes(ipfsURL).length > 0, "IPFS URL cannot be empty");
        require(expirationTime > block.timestamp, "Expiration time must be in the future");

        // Generate a unique hash for the document
        bytes32 hash = generateUniqueHash(documentId, msg.sender);

        // Store the document and its hash
        documents[documentId] = Document({
            title: title,
            description: description,
            documentType: documentType,
            ipfsCID: ipfsURL, // Store the IPFS URL for now
            uploader: msg.sender
        });

        documentExists[documentId] = true;
        userDocuments[msg.sender].push(documentId);

        // Store the hash and expiration timestamp
        documentHashes[documentId] = hash;
        expirationTimestamps[hash] = expirationTime;

        emit DocumentUploaded(documentId, title, description, documentType, msg.sender, ipfsURL);
    }

    function generateUniqueHash(uint256 documentId, address uploader) public view returns (bytes32) {
        return keccak256(abi.encodePacked(documentId, uploader, block.timestamp));
    }

    function getExpirationTimestamp(bytes32 hash) external view returns (uint256) {
        return expirationTimestamps[hash];
    }

    function getDocumentHash(uint256 documentId) external view returns (bytes32) {
        require(documentExists[documentId], "Document does not exist");
        return documentHashes[documentId];
    }

    function deleteDocument(uint256 documentId) external onlyRole(VERIFIER_ROLE) {
        require(documentExists[documentId], "Document does not exist");
        require(documents[documentId].uploader == msg.sender, "Only the uploader can delete the document");

        delete documents[documentId];
        delete documentExists[documentId];
        emit DocumentDeleted(documentId, msg.sender);
    }

    function generateHexCode(string memory hexCode) external {
        require(bytes(hexCode).length == 8, "Hex code must be 8 digits");
        require(hexCodeToUser[hexCode] == address(0), "Hex code already in use");

        hexCodeToUser[hexCode] = msg.sender;
        emit HexCodeGenerated(hexCode, msg.sender);
    }

    function requestAccess(string memory hexCode, uint256 documentId) external {
        address userAddress = hexCodeToUser[hexCode];
        require(userAddress != address(0), "Invalid hex code");
        require(documentExists[documentId], "Document does not exist");

        documentAccess[userAddress][documentId].push(msg.sender);
        emit AccessRequested(userAddress, documentId, msg.sender);
    }

    function approveAccess(uint256 documentId, address employer) external {
        require(documentExists[documentId], "Document does not exist");
        require(documentAccess[msg.sender][documentId].length > 0, "No access request found");

        documentAccess[msg.sender][documentId].push(employer);
        emit AccessApproved(employer, documentId, msg.sender);
    }

    function rejectAccess(uint256 documentId, address employer) external {
        require(documentExists[documentId], "Document does not exist");
        require(documentAccess[msg.sender][documentId].length > 0, "No access request found");

        delete documentAccess[msg.sender][documentId];
        emit AccessRejected(employer, documentId, msg.sender);
    }

    function revokeAccess(uint256 documentId, address employer) external {
        require(documentExists[documentId], "Document does not exist");

        // Check if the employer has access
        bool hasAccess = false;
        for (uint256 i = 0; i < documentAccess[msg.sender][documentId].length; i++) {
            if (documentAccess[msg.sender][documentId][i] == employer) {
                hasAccess = true;
                break;
            }
        }
        require(hasAccess, "No access granted");

        // Calculate the size of the new access list
        uint256 newSize = 0;
        for (uint256 i = 0; i < documentAccess[msg.sender][documentId].length; i++) {
            if (documentAccess[msg.sender][documentId][i] != employer) {
                newSize++;
            }
        }

        // Create a new array with the correct size
        address[] memory updatedAccessList = new address[](newSize);
        uint256 index = 0;

        // Populate the new array
        for (uint256 i = 0; i < documentAccess[msg.sender][documentId].length; i++) {
            if (documentAccess[msg.sender][documentId][i] != employer) {
                updatedAccessList[index] = documentAccess[msg.sender][documentId][i];
                index++;
            }
        }

        // Update the access list
        documentAccess[msg.sender][documentId] = updatedAccessList;

        emit AccessRevoked(employer, documentId, msg.sender);
    }

    function getDocument(uint256 documentId) external view returns (string memory title, string memory description, string memory documentType, string memory ipfsCID, address uploader) {
        require(documentExists[documentId], "Document does not exist");
        require(hasRole(VERIFIER_ROLE, msg.sender), "Only verifiers can retrieve documents");

        Document memory doc = documents[documentId];
        return (doc.title, doc.description, doc.documentType, doc.ipfsCID, doc.uploader);
    }

    function getUserDocuments(address user) external view returns (uint256[] memory) {
        return userDocuments[user];
    }

    function getPendingRequests(address user, uint256 documentId) external view returns (address[] memory) {
        return documentAccess[user][documentId];
    }
}