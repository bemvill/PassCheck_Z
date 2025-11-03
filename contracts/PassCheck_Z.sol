pragma solidity ^0.8.24;

import { FHE, euint32, externalEuint32 } from "@fhevm/solidity/lib/FHE.sol";
import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract PassCheck_Z is ZamaEthereumConfig {
    struct PasswordAnalysis {
        euint32 encryptedPassword;
        uint256 length;
        uint256 complexityScore;
        bool hasUpperCase;
        bool hasLowerCase;
        bool hasNumbers;
        bool hasSpecialChars;
        uint32 decryptedScore;
        bool isVerified;
    }

    mapping(string => PasswordAnalysis) public passwordEntries;
    string[] public entryIds;

    event PasswordAnalyzed(string indexed entryId, address indexed analyzer);
    event ScoreDecrypted(string indexed entryId, uint32 decryptedScore);

    constructor() ZamaEthereumConfig() {
    }

    function analyzePassword(
        string calldata entryId,
        externalEuint32 encryptedPassword,
        bytes calldata inputProof,
        uint256 length,
        uint256 complexityScore,
        bool hasUpperCase,
        bool hasLowerCase,
        bool hasNumbers,
        bool hasSpecialChars
    ) external {
        require(bytes(passwordEntries[entryId].encryptedPassword).length == 0, "Entry already exists");
        require(FHE.isInitialized(FHE.fromExternal(encryptedPassword, inputProof)), "Invalid encrypted input");

        passwordEntries[entryId] = PasswordAnalysis({
            encryptedPassword: FHE.fromExternal(encryptedPassword, inputProof),
            length: length,
            complexityScore: complexityScore,
            hasUpperCase: hasUpperCase,
            hasLowerCase: hasLowerCase,
            hasNumbers: hasNumbers,
            hasSpecialChars: hasSpecialChars,
            decryptedScore: 0,
            isVerified: false
        });

        FHE.allowThis(passwordEntries[entryId].encryptedPassword);
        FHE.makePubliclyDecryptable(passwordEntries[entryId].encryptedPassword);
        entryIds.push(entryId);

        emit PasswordAnalyzed(entryId, msg.sender);
    }

    function verifyScoreDecryption(
        string calldata entryId,
        bytes memory abiEncodedClearScore,
        bytes memory decryptionProof
    ) external {
        require(bytes(passwordEntries[entryId].encryptedPassword).length > 0, "Entry does not exist");
        require(!passwordEntries[entryId].isVerified, "Score already verified");

        bytes32[] memory cts = new bytes32[](1);
        cts[0] = FHE.toBytes32(passwordEntries[entryId].encryptedPassword);

        FHE.checkSignatures(cts, abiEncodedClearScore, decryptionProof);
        uint32 decodedScore = abi.decode(abiEncodedClearScore, (uint32));

        passwordEntries[entryId].decryptedScore = decodedScore;
        passwordEntries[entryId].isVerified = true;

        emit ScoreDecrypted(entryId, decodedScore);
    }

    function getEncryptedPassword(string calldata entryId) external view returns (euint32) {
        require(bytes(passwordEntries[entryId].encryptedPassword).length > 0, "Entry does not exist");
        return passwordEntries[entryId].encryptedPassword;
    }

    function getPasswordAnalysis(string calldata entryId) external view returns (
        uint256 length,
        uint256 complexityScore,
        bool hasUpperCase,
        bool hasLowerCase,
        bool hasNumbers,
        bool hasSpecialChars,
        uint32 decryptedScore,
        bool isVerified
    ) {
        require(bytes(passwordEntries[entryId].encryptedPassword).length > 0, "Entry does not exist");
        PasswordAnalysis storage analysis = passwordEntries[entryId];

        return (
            analysis.length,
            analysis.complexityScore,
            analysis.hasUpperCase,
            analysis.hasLowerCase,
            analysis.hasNumbers,
            analysis.hasSpecialChars,
            analysis.decryptedScore,
            analysis.isVerified
        );
    }

    function getAllEntryIds() external view returns (string[] memory) {
        return entryIds;
    }

    function isAvailable() public pure returns (bool) {
        return true;
    }
}

