import "source/node_modules/@aragon/os/contracts/evmscript/IEVMScriptExecutor.sol";

contract ScriptExecutor is IEVMScriptExecutor {
    event ScriptResult(bytes script, bytes input);

    function execScript(bytes script, bytes input, address[] blacklist) external returns (bytes) {
        emit ScriptResult(script, input);
        return new bytes(0);
    }

    function executorType() external pure returns (bytes32) {
        return keccak256("SCRIPT");
    }
}
