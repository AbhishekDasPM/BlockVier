require("@nomiclabs/hardhat-waffle");
require("hardhat-contract-sizer");
require("hardhat-storage-layout");

// This is a sample Hardhat task. To learn how to create your own go to
// https://hardhat.org/guides/create-task.html
task("accounts", "Prints the list of accounts", async () => {
  const accounts = await ethers.getSigners();

  for (const account of accounts) {
    console.log(account.address);
  }
});

// You need to export an object to set up your config
// Go to https://hardhat.org/config/ to learn more

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: {
    version: "0.8.13",
    settings: {
      optimizer: {
        enabled: true,
        runs: 1000,
      },
    },
  },
  // solidity: {
  //   version: "0.8.13",
  //   settings: {
  //     optimizer: {
  //       enabled: true,
  //       runs: 2000,
  //       details: {
  //         yul: true,
  //         yulDetails: {
  //           stackAllocation: true,
  //           optimizerSteps: "dhfoDgvulfnTUtnIf",
  //         },
  //       },
  //     },

  //   },
  // },

  defaultNetwork: "hardhat",
  networks: {
    hardhat: {},
    ganache: {
      url: "http://127.0.0.1:8545",
      accounts: {
        mnemonic:
          "exile enough midnight render domain pen always glimpse dry moon remind stairs",
      },

      // chainId: 1234,
    },
  },

  contractSizer: {
    alphaSort: true,
    disambiguatePaths: false,
    runOnCompile: true,
    strict: true,
    only: [],
  },
};
