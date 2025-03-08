const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("VeriFi", function () {
    let VeriFi;
    let veriFi;
    let owner, verifier, student, employer;

    before(async function () {
        [owner, verifier, student, employer] = await ethers.getSigners();
        VeriFi = await ethers.getContractFactory("VeriFi");
    });

    beforeEach(async function () {
        veriFi = await VeriFi.deploy();
        await veriFi.connect(owner).grantRole(await veriFi.VERIFIER_ROLE(), verifier.address);
    });

    // Role Management Tests
    it("Should allow the owner to add a verifier", async function () {
        expect(await veriFi.hasRole(await veriFi.VERIFIER_ROLE(), verifier.address)).to.equal(true);
    });

    it("Should not allow a non-owner to add a verifier", async function () {
        await expect(
            veriFi.connect(student).grantRole(await veriFi.VERIFIER_ROLE(), student.address)
        ).to.be.revertedWithCustomError(veriFi, "AccessControlUnauthorizedAccount");
    });

    it("Should allow the owner to remove a verifier", async function () {
        await veriFi.connect(owner).revokeRole(await veriFi.VERIFIER_ROLE(), verifier.address);
        expect(await veriFi.hasRole(await veriFi.VERIFIER_ROLE(), verifier.address)).to.equal(false);
    });

    // Document Upload Tests
    it("Should allow a verifier to upload a document with an expiration time", async function () {
        const documentId = 1;
        const title = "Title";
        const description = "Description";
        const documentType = "Type";
        const ipfsCID = "ipfsCID";
        const ipfsURL = "ipfsURL";
        const expirationTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

        await veriFi.connect(verifier).uploadDocument(
            documentId,
            title,
            description,
            documentType,
            ipfsCID,
            ipfsURL,
            expirationTime
        );

        const doc = await veriFi.documents(documentId);
        expect(doc.title).to.equal(title);
        expect(doc.description).to.equal(description);
        expect(doc.documentType).to.equal(documentType);
        expect(doc.ipfsCID).to.equal(ipfsURL);

        // Check if the hash and expiration timestamp are stored correctly
        const hash = await veriFi.getDocumentHash(documentId);
        const storedExpirationTime = await veriFi.getExpirationTimestamp(hash);
        expect(storedExpirationTime).to.equal(expirationTime);
    });

    it("Should prevent uploading a document with an existing ID", async function () {
        await veriFi.connect(verifier).uploadDocument(1, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        await expect(
            veriFi.connect(verifier).uploadDocument(1, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600)
        ).to.be.revertedWith("Document already exists");
    });

    it("Should not allow a non-verifier to upload a document", async function () {
        await expect(
            veriFi.connect(student).uploadDocument(2, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600)
        ).to.be.revertedWithCustomError(veriFi, "AccessControlUnauthorizedAccount");
    });

    // Document Retrieval Tests
    it("Should allow a verifier to retrieve a document", async function () {
        await veriFi.connect(verifier).uploadDocument(1, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        const [title, description, documentType, ipfsCID, uploader] = await veriFi.connect(verifier).getDocument(1);
        expect(title).to.equal("Title");
        expect(description).to.equal("Description");
        expect(documentType).to.equal("Type");
        expect(ipfsCID).to.equal("ipfsURL");
        expect(uploader).to.equal(verifier.address);
    });

    it("Should not allow a non-verifier to retrieve a document", async function () {
        await veriFi.connect(verifier).uploadDocument(1, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        await expect(
            veriFi.connect(student).getDocument(1)
        ).to.be.revertedWith("Only verifiers can retrieve documents");
    });

    // Document Deletion Tests
    it("Should allow the uploader to delete a document", async function () {
        await veriFi.connect(verifier).uploadDocument(1, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        await veriFi.connect(verifier).deleteDocument(1);
        expect(await veriFi.documentExists(1)).to.equal(false);
    });

    it("Should not allow a non-uploader to delete a document", async function () {
        await veriFi.connect(verifier).uploadDocument(3, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        await expect(
            veriFi.connect(student).deleteDocument(3)
        ).to.be.revertedWithCustomError(veriFi, "AccessControlUnauthorizedAccount"); // Expect custom error
    });

    // Hex Code Logic Tests
    it("Should allow a student to generate a hex code", async function () {
        await veriFi.connect(student).generateHexCode("12345678");
        expect(await veriFi.hexCodeToUser("12345678")).to.equal(student.address);
    });

    it("Should not allow a duplicate hex code", async function () {
        await veriFi.connect(student).generateHexCode("12345678");
        await expect(
            veriFi.connect(student).generateHexCode("12345678")
        ).to.be.revertedWith("Hex code already in use");
    });

    // Access Request Tests
    it("Should allow an employer to request access", async function () {
        const hexCode = "12345678";
        await veriFi.connect(student).generateHexCode(hexCode); // Generate hex code
        await veriFi.connect(verifier).uploadDocument(4, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        await veriFi.connect(employer).requestAccess(hexCode, 4);
        const pendingRequests = await veriFi.getPendingRequests(student.address, 4);
        expect(pendingRequests.length).to.equal(1);
    });

    it("Should allow a student to approve access", async function () {
        const hexCode = "12345678";
        await veriFi.connect(student).generateHexCode(hexCode); // Generate hex code
        await veriFi.connect(verifier).uploadDocument(4, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        await veriFi.connect(employer).requestAccess(hexCode, 4); // Request access
        await veriFi.connect(student).approveAccess(4, employer.address); // Approve access
        const accessList = await veriFi.getPendingRequests(student.address, 4);
        expect(accessList.includes(employer.address)).to.equal(true);
    });

    it("Should allow a student to reject access", async function () {
        const hexCode = "12345678";
        await veriFi.connect(student).generateHexCode(hexCode); // Generate hex code
        await veriFi.connect(verifier).uploadDocument(4, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        await veriFi.connect(employer).requestAccess(hexCode, 4); // Request access
        await veriFi.connect(student).rejectAccess(4, employer.address); // Reject access
        const accessList = await veriFi.getPendingRequests(student.address, 4);
        expect(accessList.includes(employer.address)).to.equal(false);
    });

    it("Should allow a student to revoke access", async function () {
        const hexCode = "12345678";
        await veriFi.connect(student).generateHexCode(hexCode); // Generate hex code
        await veriFi.connect(verifier).uploadDocument(4, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        await veriFi.connect(employer).requestAccess(hexCode, 4); // Request access
        await veriFi.connect(student).approveAccess(4, employer.address); // Approve access
        await veriFi.connect(student).revokeAccess(4, employer.address); // Revoke access
        const accessList = await veriFi.getPendingRequests(student.address, 4);
        expect(accessList.includes(employer.address)).to.equal(false);
    });

    // User Document List Tests
    it("Should return the correct list of documents for a user", async function () {
        await veriFi.connect(verifier).uploadDocument(5, "Title", "Description", "Type", "ipfsCID", "ipfsURL", Math.floor(Date.now() / 1000) + 3600);
        const userDocs = await veriFi.getUserDocuments(verifier.address);
        expect(userDocs.length).to.equal(1); // Ensure only 1 document is uploaded
        expect(userDocs[0]).to.equal(5); // Ensure the document ID is correct
    });

    // New Tests for Self-Deprecating URL Functionality
    it("Should generate a unique hash for a document", async function () {
        const documentId = 6;
        const expirationTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

        await veriFi.connect(verifier).uploadDocument(
            documentId,
            "Title",
            "Description",
            "Type",
            "ipfsCID",
            "ipfsURL",
            expirationTime
        );

        const hash = await veriFi.getDocumentHash(documentId);
        expect(hash).to.not.equal(ethers.ZeroHash); // Ensure the hash is not zero
    });

    it("Should return the correct expiration timestamp for a hash", async function () {
        const documentId = 7;
        const expirationTime = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now

        await veriFi.connect(verifier).uploadDocument(
            documentId,
            "Title",
            "Description",
            "Type",
            "ipfsCID",
            "ipfsURL",
            expirationTime
        );

        const hash = await veriFi.getDocumentHash(documentId);
        const storedExpirationTime = await veriFi.getExpirationTimestamp(hash);
        expect(storedExpirationTime).to.equal(expirationTime);
    });

    it("Should revert if the expiration time is in the past", async function () {
        const documentId = 8;
        const expirationTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour in the past

        await expect(
            veriFi.connect(verifier).uploadDocument(
                documentId,
                "Title",
                "Description",
                "Type",
                "ipfsCID",
                "ipfsURL",
                expirationTime
            )
        ).to.be.revertedWith("Expiration time must be in the future");
    });
});