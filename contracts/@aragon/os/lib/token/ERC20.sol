// See https://github.com/OpenZeppelin/openzeppelin-solidity/blob/a9f910d34f0ab33a1ae5e714f69f9596a02b4d91/contracts/token/ERC20/ERC20.sol

pragma solidity ^0.6.2;


/**
 * @title ERC20 interface
 * @dev see https://github.com/ethereum/EIPs/issues/20
 */
abstract contract ERC20 {
    function totalSupply() external view virtual returns (uint256);

    function balanceOf(address _who) external view virtual returns (uint256);

    function allowance(address _owner, address _spender)
        external view virtual returns (uint256);

    function transfer(address _to, uint256 _value) external virtual returns (bool);

    function approve(address _spender, uint256 _value)
        external virtual returns (bool);

    function transferFrom(address _from, address _to, uint256 _value)
        external virtual returns (bool);

    event Transfer(
        address indexed from,
        address indexed to,
        uint256 value
    );

    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}
