package com.gyoung.util.crypto.blockchain;

import java.util.ArrayList;

public class SubCAChain {

    public static ArrayList<iBlock> blockchain = new ArrayList<iBlock>();
    public static int difficulty = 5;

    //TODO: If Exists: Read the existing SubCA block chain and start appending new blocks to it!
    public static void go(String[] args) {

        //add our blocks to the blockchain collection:
        System.out.println("Mining block 1... ");
        addBlock(new iBlock("The first block", "0"));

        System.out.println("Mining block 2... ");
        addBlock(new iBlock(args[0], blockchain.get(blockchain.size() - 1).hash));

        String blockchainJson = StringUtil.getJson(blockchain);
        System.out.println("\nThe Subordinate CA's block chain: ");
        System.out.println(blockchainJson);
    }

    public static Boolean isChainValid() {
        iBlock currentIBlock;
        iBlock previousIBlock;
        String hashTarget = new String(new char[difficulty]).replace('\0', '0');

        //loop through blockchain and valdate hashes:
        for (int i = 1; i < blockchain.size(); i++) {
            currentIBlock = blockchain.get(i);
            previousIBlock = blockchain.get(i - 1);
            //compare registered hash and calculated hash:
            if (!currentIBlock.hash.equals(currentIBlock.calculateHash())) {
                System.out.println("Current Hashes not equal");
                return false;
            }
            //compare previous hash and registered previous hash
            if (!previousIBlock.hash.equals(currentIBlock.previousHash)) {
                System.out.println("Previous Hashes not equal");
                return false;
            }
            //check if hash is solved
            if (!currentIBlock.hash.substring(0, difficulty).equals(hashTarget)) {
                System.out.println("This block hasn't been mined");
                return false;
            }

        }
        return true;
    }

    public static void addBlock(iBlock newIBlock) {
        newIBlock.mineBlock(difficulty);
        blockchain.add(newIBlock);
    }
}