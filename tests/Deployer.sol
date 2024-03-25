contract Deployer {
    function deploy(bytes memory creationCode) public returns (address instance) {
        assembly {
            instance := create(0, add(creationCode, 0x20), mload(creationCode))
            if iszero(extcodesize(instance)) {
                revert(0, 0)
            }
        }
    }
}