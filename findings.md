### [S-#] Lopint through players array to check for duplicates in `PuppyRaffle::enterRaffle()` is a potential DoS attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle()` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more gas costs for future entrants. Every additional address in the `players` array is an additional check the loop have to make.
```javascript
 @>     for (uint256 i = 0; i < players.length - 1; i++) {
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users  from entering, and causing a rush at the start of a raffle to be one of the first to enter.

An attacker might make the `PuppyRaffle::players` array so big, that no one else enters, guarenteeing themselves the win.

**Proof of Concept:**

if we have 2 sets of 100 players enter, the gas costs will be as such: 
- 1st 100 players: ~6252037 gas
- 2nd 100 players: ~20376508 gas

<details> 
<summary>PoC</summary>
Place the folowing test into `PuppyRaffleTest.t.sol`

```javascript
 function test_denialOfService() public {
        vm.txGasPrice(1);
        address USER = makeAddr("user");
        vm.deal(USER, 1000000 ether);
        uint256 numPlayers = 200;
        address[] memory newPlayers = new address[](numPlayers);

        for (uint256 i = 0; i < numPlayers; i++) {
            newPlayers[i] = address(i);
        }

        uint256 gasStart = gasleft();

        puppyRaffle.enterRaffle{value: entranceFee * numPlayers}(newPlayers);

        uint256 gasEnd = gasleft();
        uint256 gasUsed = gasStart - gasEnd;
        console.log(gasUsed);

    }

```
</details>

**Likelihood:** High,

**Recommended Mitigation:** There are a few recommendations.

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check for duplicates. This would allow constant time lookup of whether a wallet has already entered.

```diff
+ uint256 public raffleID;
+ mapping (address => uint256) public usersToRaffleId;
.
.
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");

        for (uint256 i = 0; i < newPlayers.length; i++) {
+           // Check for duplicates
+           require(usersToRaffleId[newPlayers[i]] != raffleID, "PuppyRaffle: Already a participant");

            players.push(newPlayers[i]);
+           usersToRaffleId[newPlayers[i]] = raffleID;
        }

-       // Check for duplicates
-       for (uint256 i = 0; i < players.length - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
-               require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-           }
-       }

        emit RaffleEnter(newPlayers);
    }
.
.
.

function selectWinner() external {
        //Existing code
+    raffleID = raffleID + 1;        
    }

```



