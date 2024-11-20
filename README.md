Question
Write a rule in the K Framework that ensures a given withdraw() function in a Solidity contract can only be executed by the contract owner. Demonstrate how you would write this rule to enforce access control and prevent unauthorized users from withdrawing funds. Provide sample Solidity code for the vulnerable contract and the corresponding K rule.

Answer

The given Solidity contract CA2 has a withdraw function that does not include the onlyOwner modifier, making it vulnerable to unauthorized withdrawals. To secure this contract, we’ll define a rule in the K Framework to ensure only the owner can execute the withdraw() function. 
Here’s how the K Framework can be used to model this behavior and enforce access control.
1. Vulnerable Solidity Contract (Without Access Control)
In this version, anyone can call `withdraw`, which could allow unauthorized users to transfer funds:
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
contract CA3 {
    error isNotTheOwner(address caller);
    error balanceTooLow(uint256 currentBal, uint256 requestedBal);
   
 address owner;
    constructor(address _owner) {
        owner = _owner;
    }

 // Modifier for access control declared but not used with the withdraw function
  modifier onlyOwner() {
    if(owner!=msg.sender) revert isNotTheOwner(msg.sender);
   }
// Withdraw funds from the contract
    function withdraw(address payable to, uint256 amount) external {
        uint256 balance = address(this).balance;
        if (balance < amount) revert balanceTooLow(balance, amount);
        to.transfer(amount);
    }
   // Receive Ether
    receive() external payable {}
}

 2. K Framework Rule for Enforcing Owner-Only Withdrawals
In the K Framework, we define rules that simulate the contract’s access control logic. Our goal is to ensure that only the `owner` can execute the `withdraw` function by checking the caller’s address.
K Framework Rule to Enforce Access Control on `withdraw`
Below is a K Framework rule that enforces the access control logic for `CA3`. This rule verifies that the withdraw action can only proceed if the caller is the contract owner

module CA3-CONTRACT
    imports EVM

    // Define the contract state with `owner` and `balance`
    syntax Account ::= CA3(owner: Address, balance: Int)
    // Define the withdraw action
    syntax Action ::= "withdraw" "(" Address "," Int ")"
    syntax Account ::= withdraw(Account, Address, Int) [function]

    // Rule to allow `withdraw` only if the caller is the owner
    rule <k> withdraw(TO, AMOUNT) => . ... </k>
         <caller> CALLER </caller>
         <account> CA3(OWNER, BAL) </account>
         <balance> BAL </balance>
         requires CALLER == OWNER
         requires BAL >= AMOUNT
         ensures BAL -Int AMOUNT >=Int 0 // prevent underflow

    // Rule to revert `withdraw` if the caller is not the owner
    rule <k> withdraw(TO, AMOUNT) => revert ... </k>
         <caller> CALLER </caller>
         <account> CA3(OWNER, _) </account>
         requires CALLER =/=K OWNER

    // Rule to revert if balance is insufficient
    rule <k> withdraw(TO, AMOUNT) => revert ... </k>
         <caller> CALLER </caller>
         <account> CA3(OWNER, BAL) </account>
         requires CALLER == OWNER
         requires BAL < AMOUNT


Explanation of the Rules

1. Successful Withdrawal by Owner:
   - The first rule allows the withdraw action to proceed if:
     - The caller (`CALLER`) is the OWNER.
     - The contract’s balance (`BAL`) is greater than or equal to the withdrawal AMOUNT.
   - It includes a safety check to ensure no underflow occurs in the contract balance (BAL - AMOUNT >= 0).

2. Revert if Not Owner:
   - The second rule triggers a revert  if the CALLER is not the OWNER, simulating the onlyOwner  access control.

3. Revert if Insufficient Balance:
   - The third rule reverts if the CALLER  is OWNER, but the BAL  is less than the AMOUNT, simulating the balanceTooLow error condition.

Summary
This setup in the K Framework enforces that only the contract owner  can call withdraw, providing a formal way to analyze the contract’s security. By modeling access control rules and reversion cases, this K specification can help in formally verifying the contract’s behavior before deployment.


# Blockchain2
Samrt contract To enable owner rights for ether withdrawal usin K-Framework
