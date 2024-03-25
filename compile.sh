#!/bin/bash

wake svm use 0.4.24
wake-solc --bin -o bin '@aragon/=source/node_modules/@aragon/' \
    source/apps/voting/contracts/Voting.sol \
    tests/ScriptExecutor.sol \
    source/node_modules/@aragon/os/contracts/acl/ACL.sol \
    source/node_modules/@aragon/os/contracts/kernel/Kernel.sol \
    source/node_modules/@aragon/os/contracts/evmscript/EVMScriptRegistry.sol \
    source/node_modules/@aragon/os/contracts/evmscript/executors/CallsScript.sol \
    --allow-paths "" --optimize --overwrite
