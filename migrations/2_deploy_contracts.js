// migrations/2_deploy_contracts.js
const IoTQuantumZKPStorage = artifacts.require("IoTQuantumZKPStorage");

module.exports = async function(deployer, network, accounts) {
  try {
    // Deploy the contract
    await deployer.deploy(IoTQuantumZKPStorage);
    const storageInstance = await IoTQuantumZKPStorage.deployed();
    console.log('IoTQuantumZKPStorage deployed at:', storageInstance.address);

    // Initialize Schnorr parameters
    const p = '115792089237316195423570985008687907853269984665640564039457584007908834671663';
    const q = '57896044618658097711785492504343953926634992332820282019728792003954417335831';
    const g = '2';

    console.log('Initializing Schnorr parameters...');
    await storageInstance.initializeSchnorrParams(p, q, g);
    console.log('Schnorr parameters initialized');

    // Register test device
    const testDeviceId = web3.utils.soliditySha3('test-device-1');
    const deviceType = 0; // SENSOR type
    const publicKey = '65537';
    const metadata = JSON.stringify({
      name: 'Test Sensor 1',
      manufacturer: 'Test Corp',
      model: 'TS-001'
    });

    console.log('Registering test device...');
    await storageInstance.registerDevice(
      testDeviceId,
      deviceType,
      publicKey,
      metadata,
      { from: accounts[0] }
    );
    console.log('Test device registered');

    try {
      // Get and log device details
      const deviceDetails = await storageInstance.getDeviceDetails(testDeviceId);
      console.log('Device Details:', {
        owner: deviceDetails[0],
        registrationTime: deviceDetails[1] ? deviceDetails[1].toString() : '0',
        isActive: deviceDetails[2],
        dataCount: deviceDetails[3] ? deviceDetails[3].toString() : '0',
        trustScore: deviceDetails[4] ? deviceDetails[4].toString() : '0',
        metadata: deviceDetails[5],
        deviceType: deviceDetails[6] ? deviceDetails[6].toString() : '0',
        publicKey: deviceDetails[7] ? deviceDetails[7].toString() : '0'
      });
    } catch (error) {
      console.error('Error getting device details:', error.message);
    }

    // Submit test proof
    console.log('Submitting test proof...');
    const testCommitment = web3.utils.toBN('123456789');
    const testChallenge = web3.utils.toBN('987654321');
    const testResponse = web3.utils.toBN('543216789');
    const testMessageHash = web3.utils.soliditySha3('test-message');

    await storageInstance.submitProof(
      testDeviceId,
      testCommitment.toString(),
      testChallenge.toString(),
      testResponse.toString(),
      testMessageHash,
      { from: accounts[0] }
    );
    console.log('Test proof submitted');

    // Generate proofId
    const proofId = web3.utils.soliditySha3(
      testDeviceId,
      testCommitment.toString(),
      testChallenge.toString(),
      testResponse.toString(),
      web3.utils.toBN(Math.floor(Date.now() / 1000)).toString()
    );

    // Verify the proof
    console.log('Verifying proof...');
    await storageInstance.verifyProof(
      testDeviceId,
      proofId,
      { from: accounts[0] }
    );
    console.log('Proof verified');

    // Try to get proof details
    try {
      const proofDetails = await storageInstance.getProofDetails(testDeviceId, proofId);
      console.log('Proof Details:', {
        commitment: proofDetails[0] ? proofDetails[0].toString() : '0',
        challenge: proofDetails[1] ? proofDetails[1].toString() : '0',
        response: proofDetails[2] ? proofDetails[2].toString() : '0',
        messageHash: proofDetails[3],
        isVerified: proofDetails[4]
      });
    } catch (error) {
      console.error('Error getting proof details:', error.message);
    }

  } catch (error) {
    console.error('Deployment error:', {
      message: error.message,
      stack: error.stack
    });
    throw error;
  }
};