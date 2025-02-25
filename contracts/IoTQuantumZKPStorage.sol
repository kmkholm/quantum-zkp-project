// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/**
 * @title IoTQuantumZKPStorage
 * @dev Enhanced storage system with Schnorr ZKP verification
 */
contract IoTQuantumZKPStorage is ReentrancyGuard, Ownable, Pausable {
    using Counters for Counters.Counter;

    // Custom errors
    error DeviceAlreadyRegistered();
    error DeviceNotRegistered();
    error DataAlreadyExists();
    error InvalidDataHash();
    error InvalidProof();
    error UnauthorizedAccess();
    error DataNotFound();
    error InvalidDeviceSignature();
    error InvalidThreshold();
    error InvalidSchnorrParameters();
    error ProofVerificationFailed();

    // Schnorr group parameters
    struct SchnorrParams {
        uint256 p;  // Prime modulus
        uint256 q;  // Subgroup order
        uint256 g;  // Generator
        bool isInitialized;
    }

    // Schnorr proof structure
    struct SchnorrProof {
        uint256 commitment;    // R = g^k mod p
        uint256 challenge;     // e = H(m, R, y)
        uint256 response;      // s = k - xe mod q
        bytes32 messageHash;   // Hash of the original message
        bool isVerified;       // Verification status
    }

    // IoT Device structure
    struct IoTDevice {
        bytes32 deviceId;          // Unique device identifier
        address owner;             // Device owner
        uint256 registrationTime;  // Registration timestamp
        bool isActive;             // Device status
        uint256 dataCount;         // Number of data points
        uint256 trustScore;        // Device trust score
        string metadata;           // Device metadata (JSON)
        DeviceType deviceType;     // Type of IoT device
        uint256 publicKey;         // Schnorr public key
        uint256 accessLevel;       // Device access level
        mapping(bytes32 => SchnorrProof) proofs;  // Device's proofs
    }

    // Protected data structure
    struct ProtectedData {
        bytes32 dataHash;          // Hash of the encrypted data
        bytes32 zkProof;          // Zero-knowledge proof reference
        address owner;             // Data owner
        bytes32 deviceId;          // Source device ID
        uint256 timestamp;         // Storage timestamp
        bool isValid;              // Validity flag
        uint256 accessLevel;       // Access level
        DataType dataType;         // Type of data
        mapping(address => bool) authorizedUsers;  // Access permissions
    }

    // Device type enumeration
    enum DeviceType {
        SENSOR,
        ACTUATOR,
        GATEWAY,
        EDGE_DEVICE,
        CUSTOM
    }

    // Data type enumeration
    enum DataType {
        TELEMETRY,
        CONFIGURATION,
        DIAGNOSTIC,
        SECURITY,
        CUSTOM
    }

    // State variables
    mapping(bytes32 => IoTDevice) public devices;
    mapping(bytes32 => ProtectedData) private dataStore;
    mapping(bytes32 => mapping(uint256 => bytes32)) public deviceDataHistory;
    
    SchnorrParams public schnorrParams;
    Counters.Counter private _deviceCount;
    
    // Constants
    uint256 public constant MIN_TRUST_SCORE = 100;
    uint256 public constant MAX_TRUST_SCORE = 1000;
    uint256 public constant BATCH_SIZE_LIMIT = 1000;
    uint256 public constant DEFAULT_ACCESS_LEVEL = 1;
    
    // Events
    event DeviceRegistered(
        bytes32 indexed deviceId,
        address indexed owner,
        uint256 publicKey,
        uint256 timestamp
    );
    
    event DeviceDeactivated(
        bytes32 indexed deviceId,
        uint256 timestamp
    );
    
    event DataStored(
        bytes32 indexed dataId,
        bytes32 indexed deviceId,
        address indexed owner,
        uint256 timestamp,
        bytes32 dataHash
    );
    
    event BatchProcessed(
        bytes32 indexed batchId,
        bytes32 indexed deviceId,
        uint256 count,
        uint256 timestamp
    );
    
    event ProofSubmitted(
        bytes32 indexed deviceId,
        bytes32 indexed proofId,
        uint256 commitment,
        uint256 timestamp
    );
    
    event ProofVerified(
        bytes32 indexed deviceId,
        bytes32 indexed proofId,
        bool success,
        uint256 timestamp
    );

    event DeviceTrustScoreUpdated(
        bytes32 indexed deviceId,
        uint256 oldScore,
        uint256 newScore,
        uint256 timestamp
    );

    // Modifiers
    modifier onlyRegisteredDevice(bytes32 deviceId) {
        if (!devices[deviceId].isActive) {
            revert DeviceNotRegistered();
        }
        _;
    }

    modifier onlyDeviceOwner(bytes32 deviceId) {
        if (devices[deviceId].owner != msg.sender) {
            revert UnauthorizedAccess();
        }
        _;
    }

    /**
     * @dev Initialize Schnorr parameters
     */
    function initializeSchnorrParams(
        uint256 p,
        uint256 q,
        uint256 g
    ) external onlyOwner {
        require(p > 3 && q > 3, "Invalid prime parameters");
        require(g > 1 && g < p, "Invalid generator");
        require(!schnorrParams.isInitialized, "Already initialized");
        
        schnorrParams = SchnorrParams({
            p: p,
            q: q,
            g: g,
            isInitialized: true
        });
    }

    /**
     * @dev Register new IoT device with ZKP capability
     */
    function registerDevice(
        bytes32 deviceId,
        DeviceType deviceType,
        uint256 publicKey,
        string calldata metadata
    ) external nonReentrant whenNotPaused {
        if (!schnorrParams.isInitialized) revert InvalidSchnorrParameters();
        if (devices[deviceId].isActive) revert DeviceAlreadyRegistered();
        if (publicKey <= 1 || publicKey >= schnorrParams.p) revert InvalidProof();

        IoTDevice storage newDevice = devices[deviceId];
        newDevice.deviceId = deviceId;
        newDevice.owner = msg.sender;
        newDevice.registrationTime = block.timestamp;
        newDevice.isActive = true;
        newDevice.trustScore = MIN_TRUST_SCORE;
        newDevice.metadata = metadata;
        newDevice.deviceType = deviceType;
        newDevice.publicKey = publicKey;
        newDevice.accessLevel = DEFAULT_ACCESS_LEVEL;

        _deviceCount.increment();

        emit DeviceRegistered(
            deviceId,
            msg.sender,
            publicKey,
            block.timestamp
        );
    }

    /**
     * @dev Store IoT data with proofs
     */
    function storeIoTData(
        bytes32 deviceId,
        bytes32 dataId,
        bytes32 dataHash,
        bytes32 proof,
        DataType dataType
    ) external nonReentrant whenNotPaused onlyRegisteredDevice(deviceId) {
        if (dataStore[dataId].isValid) revert DataAlreadyExists();
        if (dataHash == bytes32(0)) revert InvalidDataHash();
        if (proof == bytes32(0)) revert InvalidProof();

        IoTDevice storage device = devices[deviceId];
        SchnorrProof storage proofData = device.proofs[proof];
        
        // Additional validation
        require(proofData.commitment != 0, "Proof not found");
        require(proofData.isVerified, "Proof not verified");

        ProtectedData storage newData = dataStore[dataId];
        newData.dataHash = dataHash;
        newData.zkProof = proof;
        newData.owner = msg.sender;
        newData.deviceId = deviceId;
        newData.timestamp = block.timestamp;
        newData.isValid = true;
        newData.accessLevel = 1;
        newData.dataType = dataType;

        deviceDataHistory[deviceId][device.dataCount] = dataId;
        device.dataCount++;

        _updateDeviceTrustScore(deviceId, 5);

        emit DataStored(
            dataId,
            deviceId,
            msg.sender,
            block.timestamp,
            dataHash
        );
    }

    /**
     * @dev Submit Schnorr ZKP for verification
     */
    function submitProof(
        bytes32 deviceId,
        uint256 commitment,
        uint256 challenge,
        uint256 response,
        bytes32 messageHash
    ) external nonReentrant whenNotPaused onlyRegisteredDevice(deviceId) {
        bytes32 proofId = keccak256(
            abi.encodePacked(
                deviceId,
                commitment,
                challenge,
                response,
                block.timestamp
            )
        );

        IoTDevice storage device = devices[deviceId];
        device.proofs[proofId] = SchnorrProof({
            commitment: commitment,
            challenge: challenge,
            response: response,
            messageHash: messageHash,
            isVerified: false
        });

        deviceDataHistory[deviceId][device.dataCount] = proofId;
        device.dataCount++;

        emit ProofSubmitted(
            deviceId,
            proofId,
            commitment,
            block.timestamp
        );
    }

    /**
     * @dev Verify Schnorr ZKP
     */
    function verifyProof(
        bytes32 deviceId,
        bytes32 proofId
    ) external whenNotPaused returns (bool) {
        IoTDevice storage device = devices[deviceId];
        if (!device.isActive) revert DeviceNotRegistered();

        SchnorrProof storage proof = device.proofs[proofId];
        if (proof.commitment == 0) revert InvalidProof();

        uint256 gs = modExp(
            schnorrParams.g,
            proof.response,
            schnorrParams.p
        );

        uint256 rye = mulmod(
            proof.commitment,
            modExp(
                device.publicKey,
                proof.challenge,
                schnorrParams.p
            ),
            schnorrParams.p
        );

        bool isValid = (gs == rye);
        proof.isVerified = isValid;

        if (isValid) {
            _updateDeviceTrustScore(deviceId, 5);
        } else {
            _updateDeviceTrustScore(deviceId, -5);
        }

        emit ProofVerified(
            deviceId,
            proofId,
            isValid,
            block.timestamp
        );

        return isValid;
    }

    /**
     * @dev Get proof details
     */
    function getProofDetails(
        bytes32 deviceId,
        bytes32 proofId
    ) external view returns (
        uint256 commitment,
        uint256 challenge,
        uint256 response,
        bytes32 messageHash,
        bool isVerified
    ) {
        SchnorrProof storage proof = devices[deviceId].proofs[proofId];
        return (
            proof.commitment,
            proof.challenge,
            proof.response,
            proof.messageHash,
            proof.isVerified
        );
    }

    /**
     * @dev Get device details
     */
    function getDeviceDetails(bytes32 deviceId) external view returns (
        address owner,
        uint256 registrationTime,
        bool isActive,
        uint256 dataCount,
        uint256 trustScore,
        string memory metadata,
        DeviceType deviceType,
        uint256 publicKey
    ) {
        IoTDevice storage device = devices[deviceId];
        return (
            device.owner,
            device.registrationTime,
            device.isActive,
            device.dataCount,
            device.trustScore,
            device.metadata,
            device.deviceType,
            device.publicKey
        );
    }

    /**
     * @dev Update device trust score
     */
    function _updateDeviceTrustScore(bytes32 deviceId, int256 points) internal {
        IoTDevice storage device = devices[deviceId];
        uint256 oldScore = device.trustScore;
        uint256 newScore;
        
        if (points > 0) {
            newScore = bound(
                device.trustScore + uint256(points),
                MIN_TRUST_SCORE,
                MAX_TRUST_SCORE
            );
        } else {
            newScore = bound(
                device.trustScore - uint256(-points),
                MIN_TRUST_SCORE,
                MAX_TRUST_SCORE
            );
        }
        
        device.trustScore = newScore;
        
        emit DeviceTrustScoreUpdated(
            deviceId,
            oldScore,
            newScore,
            block.timestamp
        );
    }

    /**
     * @dev Modular exponentiation helper
     */
    function modExp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) internal pure returns (uint256) {
        if (modulus == 1) return 0;
        
        uint256 result = 1;
        base = base % modulus;
        
        while (exponent > 0) {
            if (exponent % 2 == 1) {
                result = mulmod(result, base, modulus);
            }
            base = mulmod(base, base, modulus);
            exponent >>= 1;
        }
        return result;
    }

    /**
     * @dev Bound value between min and max
     */
    function bound(
        uint256 value,
        uint256 min,
        uint256 max
    ) internal pure returns (uint256) {
        if (value < min) return min;
        if (value > max) return max;
        return value;
    }

    /**
     * @dev Emergency pause
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @dev Resume operations
     */
    // Batch data structure
    struct DataBatch {
        bytes32[] dataHashes;
        uint256 timestamp;
        bytes32 batchId;
        bytes32 deviceId;
        bool processed;
    }

    // Additional state variables
    mapping(bytes32 => DataBatch) public dataBatches;
    mapping(address => uint256) public userTrustScores;
    
    /**
     * @dev Store batch of IoT data
     * @param deviceId Source device ID
     * @param dataHashes Array of data hashes
     * @param proofs Array of proof IDs
     * @param dataType Type of data being stored
     */
    function storeBatchData(
        bytes32 deviceId,
        bytes32[] calldata dataHashes,
        bytes32[] calldata proofs,
        DataType dataType
    ) external nonReentrant whenNotPaused onlyRegisteredDevice(deviceId) {
        require(dataHashes.length == proofs.length, "Arrays length mismatch");
        require(dataHashes.length <= BATCH_SIZE_LIMIT, "Batch too large");

        bytes32 batchId = keccak256(
            abi.encodePacked(deviceId, block.timestamp, dataHashes.length)
        );

        IoTDevice storage device = devices[deviceId];
        
        // Verify all proofs first
        for (uint256 i = 0; i < proofs.length; i++) {
            SchnorrProof storage proof = device.proofs[proofs[i]];
            require(proof.commitment != 0, "Proof not found");
            require(proof.isVerified, "Proof not verified");
        }

        // Store batch metadata
        DataBatch storage batch = dataBatches[batchId];
        batch.dataHashes = dataHashes;
        batch.timestamp = block.timestamp;
        batch.batchId = batchId;
        batch.deviceId = deviceId;
        batch.processed = true;

        // Store individual data entries
        for (uint256 i = 0; i < dataHashes.length; i++) {
            bytes32 dataId = keccak256(
                abi.encodePacked(batchId, dataHashes[i], i)
            );

            ProtectedData storage newData = dataStore[dataId];
            newData.dataHash = dataHashes[i];
            newData.zkProof = proofs[i];
            newData.owner = msg.sender;
            newData.deviceId = deviceId;
            newData.timestamp = block.timestamp;
            newData.isValid = true;
            newData.accessLevel = 1;
            newData.dataType = dataType;

            deviceDataHistory[deviceId][device.dataCount + i] = dataId;
        }

        // Update device data count
        device.dataCount += dataHashes.length;

        // Update trust score
        _updateDeviceTrustScore(deviceId, int256(dataHashes.length));

        emit BatchProcessed(
            batchId,
            deviceId,
            dataHashes.length,
            block.timestamp
        );
    }

    /**
     * @dev Get batch details
     * @param batchId Batch identifier
     */
    function getBatchDetails(
        bytes32 batchId
    ) external view returns (
        bytes32[] memory dataHashes,
        uint256 timestamp,
        bytes32 deviceId,
        bool processed
    ) {
        DataBatch storage batch = dataBatches[batchId];
        return (
            batch.dataHashes,
            batch.timestamp,
            batch.deviceId,
            batch.processed
        );
    }

    /**
     * @dev Grant access to data
     * @param dataId Data identifier
     * @param user User address to grant access
     */
    function grantAccess(
        bytes32 dataId,
        address user
    ) external nonReentrant whenNotPaused {
        ProtectedData storage data = dataStore[dataId];
        if (!data.isValid) revert DataNotFound();
        if (data.owner != msg.sender) revert UnauthorizedAccess();
        
        data.authorizedUsers[user] = true;
    }

    /**
     * @dev Revoke access to data
     * @param dataId Data identifier
     * @param user User address to revoke access
     */
    function revokeAccess(
        bytes32 dataId,
        address user
    ) external nonReentrant whenNotPaused {
        ProtectedData storage data = dataStore[dataId];
        if (!data.isValid) revert DataNotFound();
        if (data.owner != msg.sender) revert UnauthorizedAccess();
        
        data.authorizedUsers[user] = false;
    }

    /**
     * @dev Check if user has access to data
     * @param dataId Data identifier
     * @param user User address to check
     */
    function hasAccess(
        bytes32 dataId,
        address user
    ) external view returns (bool) {
        ProtectedData storage data = dataStore[dataId];
        return data.owner == user || data.authorizedUsers[user];
    }

    /**
     * @dev Get data details
     * @param dataId Data identifier
     */
    function getDataDetails(
        bytes32 dataId
    ) external view returns (
        bytes32 dataHash,
        bytes32 zkProof,
        address owner,
        bytes32 deviceId,
        uint256 timestamp,
        bool isValid,
        uint256 accessLevel,
        DataType dataType
    ) {
        ProtectedData storage data = dataStore[dataId];
        return (
            data.dataHash,
            data.zkProof,
            data.owner,
            data.deviceId,
            data.timestamp,
            data.isValid,
            data.accessLevel,
            data.dataType
        );
    }

    /**
     * @dev Update user trust score
     * @param user User address
     * @param points Points to add
     */
    function _updateUserTrustScore(address user, uint256 points) internal {
        uint256 currentScore = userTrustScores[user];
        userTrustScores[user] = bound(
            currentScore + points,
            MIN_TRUST_SCORE,
            MAX_TRUST_SCORE
        );
    }

    /**
     * @dev Get user trust score
     * @param user User address
     */
    function getUserTrustScore(address user) external view returns (uint256) {
        return userTrustScores[user];
    }

    /**
     * @dev Set device access level
     * @param deviceId Device identifier
     * @param accessLevel New access level
     */
    function setDeviceAccessLevel(
        bytes32 deviceId,
        uint256 accessLevel
    ) external onlyOwner {
        require(accessLevel > 0, "Invalid access level");
        devices[deviceId].accessLevel = accessLevel;
    }

     /**
 * @dev Update IoT device metadata
 */
function updateDeviceMetadata(bytes32 deviceId, string calldata newMetadata) 
    external 
    onlyRegisteredDevice(deviceId) 
    onlyDeviceOwner(deviceId) 
{
    IoTDevice storage device = devices[deviceId];
    device.metadata = newMetadata;

    emit DeviceTrustScoreUpdated(
        deviceId,
        device.trustScore,
        device.trustScore, // No change in trust score for metadata update
        block.timestamp
    );
}


/**
 * @dev Activate an existing device
 */
function activateDevice(bytes32 deviceId) external onlyOwner {
    IoTDevice storage device = devices[deviceId];
    if (!device.isActive) {
        device.isActive = true;
        emit DeviceDeactivated(deviceId, block.timestamp);  // Optional: emit event if needed
    }
}




    /**
     * @dev Emergency data deletion
     * @param dataId Data identifier
     */
    function emergencyDeleteData(
        bytes32 dataId
    ) external onlyOwner whenPaused {
        delete dataStore[dataId];
    }

    /**
     * @dev Get total registered devices
     */
    function getTotalDevices() external view returns (uint256) {
        return _deviceCount.current();
    }

    /**
     * @dev Get total processed batches for device
     * @param deviceId Device identifier
     */
    function getDeviceBatchCount(
        bytes32 deviceId
    ) external view returns (uint256) {
        return devices[deviceId].dataCount;
    }
}



