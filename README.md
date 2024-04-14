# Tests for Lido/Aragon voting simple delegation
This repository serves as an example of tests written in a development and testing framework called [Wake](https://getwake.io).

![horizontal splitter](https://github.com/Ackee-Blockchain/wake-detect-action/assets/56036748/ec488c85-2f7f-4433-ae58-3d50698a47de)

## Setup

1. Clone this repository
2. `git submodule update --init --recursive` if not cloned with `--recursive`
3. `cd source && yarn install && cd ..` to install dependencies
4. `./compile.sh`  to generate bytecode for Solidity 0.4.24 contracts (Wake supports >= 0.6.2)
5. `wake up pytypes` to generate pytypes
6. `wake test` to run tests

Tested with `wake` version `4.6.0` and `anvil` version `anvil 0.2.0 (42a9d34 2024-03-18T00:19:07.671827733Z)`.
