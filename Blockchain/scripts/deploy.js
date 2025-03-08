const hre = require('hardhat');

async function main() {
  const [owner, verifier, student, employer] = await hre.ethers.getSigners();

  const VeriFi = await hre.ethers.getContractFactory('VeriFi');
  const veriFi = await VeriFi.deploy();

  console.log('VeriFi deployed to:', veriFi.target);
  console.log('Owner address:', owner.address);
  console.log('Verifier address:', verifier.address);
  console.log('Student address:', student.address);
  console.log('Employer address:', employer.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
