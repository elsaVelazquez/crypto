pragma solidity >=0.4.22 <0.6.0;
pragma experimental ABIEncoderV2;
//import "https://github.com/pipermerriam/ethereum-string-utils/blob/master/contracts/StringLib.sol";


contract RPS {
    address public manager; //only one that can make the contract happen
    address payable public player1;
    address payable public player2;
    
    address payable public gameWages;  //stores the total waged
    
    uint public winningPlayer; //might not be needeed
    address public winnerAddress; //might not be needed

   //in case there is an excess
   mapping(address => uint) public excess;
    
 
     //the state machine
    enum State{
        START,
        P1_PLAYED, 
        BOTH_PLAYED
    }
    
    State public gameState;
    
    constructor() public {
        manager = msg.sender;
        gameState = State.START;  //this is a state variable
    }
    
    //createa random numbers
    uint nonce = 100;  
    function random() public view returns (uint) {
        uint rand = uint(keccak256(abi.encodePacked(now, msg.sender, nonce))) % 900;
       // rand = rand + 100;
       // nonce++;
       //$$$$$$$$$$$$$$$$$$$$$$$$$$$$ IDK WHY THIS LIBRARY IMPORT  ISNT WORKING
       //rand = stringUtils.uintToBytes(rand); //using a call to an external library
       return rand; //this is now in string format
    }
   
    //get the players' input
    function encode_commitment_p1(string memory choice_p1, string memory rand) public pure returns (bytes32){
        //concatonate the strings
        //$$$$$$$$$$$$$$$$$$$$$$$$$$$$ IDK if this imported the rand from function random ^^above
        bytes memory _ch_p1 = bytes(choice_p1);
        bytes memory _rand = bytes(rand);
        string memory p1_string = new string(_ch_p1.length + _rand.length);
        bytes memory choice_p1_rand = bytes(p1_string); //the concatonated string
        return keccak256(bytes("choice_p1_rand")); //this is now in bytes
    }
    
    function encode_commitment_p2(string memory choice_p2, string memory rand) public pure returns (bytes32){
         //concatonate the strings
        //$$$$$$$$$$$$$$$$$$$$$$$$$$$$ IDK if this imported the rand from function random ^^above
        bytes memory _ch_p2 = bytes(choice_p2);
        bytes memory _rand = bytes(rand);
        string memory p2_string = new string(_ch_p2.length + _rand.length);
        bytes memory choice_p2_rand = bytes(p2_string); //the concatonated string
        return keccak256(bytes("choice_p2_rand")); //this is now in bytes
    }
    

    //STRUCT FOR BLINDING PLAYER1 RESPONSES
    struct blinded_p1 {
        bytes32 player1_choice;
        uint p1_waged;
    }
    
    mapping(address => blinded_p1) public p1_blinded_choice;
    
    //helper function
    function choicePlayer1() pure public returns(blinded_p1 memory) {
    }

   //STRUCT FOR BLINDING PLAYER2 RESPONSES
    struct blinded_p2 {
        bytes32 player2_choice;
        uint p1_waged;
    }
    
    mapping(address => blinded_p2) public p2_blinded_choice;
    
    //helper function
    function choicePlayer2() pure public returns(blinded_p2 memory) {
    }
    
    
       /* 
    Accepts a commitment (generated via encode_commitment) and a wager of ethereum
    */
    function play(bytes32 commitment) public payable {
        }
    ////$$$$$$$$$$$$$$$$$$$$$$$$$$$$ WAS WORKING ON THIS FUNCTION BELOW ///////
    
    function playStateStart() public payable notManager returns(bool start){
        require(gameState == State.START);
        require(msg.value > 0.00001 ether); //requires players to place a minimum bid
        
        uint currentWageP1 =  player1.balance;
        uint currentWageP2 =  player2.balance;
        
        //return money if bids are not equal
        if(currentWageP2 > currentWageP1){
            uint excessWager = player2.balance - player1.balance;
            // $$$$$$$$$$$$$$$$$$$$$$$$$$$$
            //$$$$$$$$$i dont know how to send back this money to player 2
            require(msg.sender.send(excessWager));
            //require(msg.sender.send(player2));
        }else{
            if(currentWageP2 < currentWageP1){
                gameState = State.START;
            }
        }
    return true;
    }
    
    
    function payWinner() public  {
        // uint index = random() % players.length;
        // address winnerAddress = players[index];
        require(msg.sender.send(manager.balance));
        require(msg.sender.send(address(this).balance));
        

        //only the manager pays the player out the balance
        require(msg.sender == manager);
        require(msg.sender.send(player1.balance));
        
        //resets the game to play again, put this at the end of paying out
        //players = new address(0);
    }    
        
        
        
        
    /* After both players reveal, this allows the winner
to claim their reward (both wagers).
In the event of a tie, this function should let
each player withdraw their initial wager.
*/   
    function withdraw() public {
        require(gameState == State.BOTH_PLAYED);
        
        address winner;
        uint winnings;
        
        if(gameState == State.BOTH_PLAYED){
            require(msg.sender == winner);
            require(msg.sender.send(winner.balance));
            //winner = msg.sender;
            //winnings = gameWages(msg.sender);
        }
    }
        
    
    
    
    // ////////MODIFIERS-- IDK IF TO BOTHER WITH THESE
    
        //modifer so only manager can do these things
    modifier restrictedManagerOnly() {
            require(msg.sender == manager);
            _;
    }
        
        //modifer so only player1 can do these things, player2 can't change player1's bid
    modifier restrictedP1Only() {
            require(msg.sender == player1);
            _;
    }
        
        //modifer so only player2 can do these things, player2 can't change player1's bid
    modifier restrictedP2Only() {
            require(msg.sender == player2);
            _;
    }        
          
          // makes sure they both wager same amount
          // $$$$$$$$$i I DON TTHINK THIS IS WORKING BUT DOESNT MATTER
    modifier wageSame {
        require(msg.sender.send(player1.balance) == msg.sender.send(player2.balance));
        _;
        //require(player1.)
    }
    
        //modifier so contract manager can't change other people's inputs
    modifier notManager() {
        require(msg.sender != manager);
        _;
    }
        

}


