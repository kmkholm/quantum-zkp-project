const IoTQuantumZKPStorage = artifacts.require("IoTQuantumZKPStorage");

module.exports = function(deployer) {
  deployer.deploy(IoTQuantumZKPStorage);
};