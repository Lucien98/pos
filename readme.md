# Reductable Blockchain demo
This project is a naive project using 667 vrfs to consensus the editaion of a transaction in the history of blockchain. The fake chain copies the ouroborous chain in the leader eletion, using vrf to decide which pk to be eleced to be the slot leader. This program only simulate an epoch, so there is no dynamic changes in the stake of stakeholders.
There is also no simulation of broadcasting of the blocks and transactions. 

# Dependencies
- [secp256k1-vrf ](https://github.com/aergoio/secp256k1-vrf)
- [merkle-tree lib](https://github.com/IAIK/merkle-tree)

# How to run the project

Compile and install the up 2 libs and move the `.a` file in your system static lib path.
Using the command `make && ./pos_simu argv1 argv2`,  you can run the program. 
- argv1: a string which defines the filename of the generated csv file which records the single block validation time and blockchain valition time. The file will be in the root directory in the project(a bad position 😓)
- argv2:  should be an integer. It decides the frequency that a block with an edited transaction appears. 