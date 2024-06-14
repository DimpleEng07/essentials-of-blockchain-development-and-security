const crypto = require('crypto');
const { ec } = require('elliptic'); // npm install elliptic
const uuid = require('uuid');

const ecInstance = new ec('secp256k1'); // Using elliptic curve 'secp256k1'

/**
 * Block represents a block in the blockchain. It has the
 * following params:
 * @index represents its position in the blockchain
 * @timestamp shows when it was created
 * @transactions represents the data about transactions
 * added to the chain
 * @prevHash represents the hash of the previous block
 * @nonce is used in proof of work to vary the hash value
 * @merkleRoot is the root hash of the Merkle Tree for transactions
 * @hash represents the hash of the current block
 */
class Block {
    constructor(index, transactions, prevHash, nonce, merkleRoot, hash) {
        this.index = index;
        this.timestamp = Math.floor(Date.now() / 1000);
        this.transactions = transactions;
        this.prevHash = prevHash;
        this.nonce = nonce;
        this.merkleRoot = merkleRoot;
        this.hash = hash;
    }
}

/**
 * A blockchain transaction. Has an amount, sender and a
 * recipient (not UTXO).
 */
class Transaction {
    constructor(amount, sender, recipient) {
        this.amount = amount;
        this.sender = sender;
        this.recipient = recipient;
        this.tx_id = uuid.v4().split('-').join('');
        this.timestamp = Date.now();
        this.senderPubKey = ''; // Public key of the sender
        this.signature = ''; // Digital signature
    }

    /**
     * Signs the transaction using the sender's private key.
     */
    signTransaction(senderPrivateKey) {
        // Calculate the hash of the transaction data
        const txDataHash = this.calculateHash();
        // Sign the hash with the sender's private key
        const key = ecInstance.keyFromPrivate(senderPrivateKey, 'hex');
        const signature = key.sign(txDataHash, 'base64');
        this.signature = signature.toDER('hex'); // Convert signature to DER format
        this.senderPubKey = key.getPublic('hex'); // Set sender's public key
    }

    /**
     * Verifies the transaction signature using sender's public key.
     */
    verifyTransaction() {
        // If the transaction does not have a signature, return false
        if (!this.signature || this.signature === '') {
            return false;
        }

        // Calculate the hash of the transaction data
        const txDataHash = this.calculateHash();
        // Verify the signature using sender's public key
        const key = ecInstance.keyFromPublic(this.senderPubKey, 'hex');
        return key.verify(txDataHash, this.signature);
    }

    /**
     * Calculates the hash of the transaction data.
     */
    calculateHash() {
        return crypto.createHash('sha256').update(this.amount + this.sender + this.recipient + this.tx_id + this.timestamp).digest('hex');
    }
}

/**
 * Blockchain represents the entire blockchain with the
 * ability to create transactions, mine and validate
 * all blocks.
 */
class Blockchain {
    constructor() {
        this.chain = [];
        this.pendingTransactions = [];
        this.pendingMerkleTree = [];
        this.difficulty = 3; // Initial difficulty
        this.difficultyAdjustmentInterval = 5; // Adjust difficulty every 5 blocks
        this.blockGenerationInterval = 60; // Expected time to mine one block (in seconds)
        this.addBlock('0');
    }

    /**
     * Generates the Merkle Root from a list of transactions.
     */
    generateMerkleRoot(transactions) {
        if (transactions.length === 0) {
            return crypto.createHmac('sha256', "secret").update('').digest('hex');
        }

        let tree = transactions.map(tx => crypto.createHmac('sha256', "secret").update(tx.tx_id).digest('hex'));

        for (let sz = transactions.length; sz > 1; sz = Math.floor((sz + 1) / 2)) {
            for (let i = 0; i < sz; i += 2) {
                let i2 = Math.min(i + 1, sz - 1);
                tree.push(crypto.createHmac('sha256', "secret")
                    .update(tree[i] + tree[i2])
                    .digest('hex'));
            }
        }

        return tree[tree.length - 1];
    }

    /**
     * Creates a transaction on the blockchain.
     * @param {number} amount - Amount to be transferred.
     * @param {string} senderPrivateKey - Sender's private key for signing the transaction.
     * @param {string} recipient - Recipient's public key or identifier.
     */
    createTransaction(amount, senderPrivateKey, recipient) {
        let transaction = new Transaction(amount, ecInstance.keyFromPrivate(senderPrivateKey, 'hex').getPublic('hex'), recipient);
        transaction.signTransaction(senderPrivateKey); // Sign the transaction
        this.pendingTransactions.push(transaction);
        this.pendingMerkleTree.push(transaction.tx_id);
    }

    /**
     * Verifies all pending transactions before adding a new block.
     */
    verifyPendingTransactions() {
        for (const transaction of this.pendingTransactions) {
            if (!transaction.verifyTransaction()) {
                return false;
            }
        }
        return true;
    }

    /**
     * Adds a block to the blockchain.
     */
    addBlock(nonce) {
        let index = this.chain.length;
        let prevHash = this.chain.length !== 0 ? this.chain[this.chain.length - 1].hash : '0';
        let merkleRoot = this.generateMerkleRoot(this.pendingTransactions);
        let hash = this.getHash(prevHash, merkleRoot, nonce);
        let block = new Block(index, this.pendingTransactions, prevHash, nonce, merkleRoot, hash);

        this.pendingTransactions = [];
        this.pendingMerkleTree = [];
        this.chain.push(block);

        // Adjust difficulty if needed
        if (this.chain.length % this.difficultyAdjustmentInterval === 0) {
            this.adjustDifficulty();
        }
    }

    /**
     * Gets the hash of a block.
     */
    getHash(prevHash, merkleRoot, nonce) {
        let encrypt = prevHash + nonce + merkleRoot;
        let hash = crypto.createHmac('sha256', "secret").update(encrypt).digest('hex');
        return hash;
    }

    /**
     * Finds nonce that satisfies the proof of work.
     */
    proofOfWork(prevHash, merkleRoot) {
        let nonce = 0;
        let hash = '';
        const target = '0'.repeat(this.difficulty);

        while (true) {
            hash = this.getHash(prevHash, merkleRoot, nonce);
            if (hash.substring(0, this.difficulty) === target) {
                break;
            }
            nonce++;
        }

        return nonce;
    }

    /**
     * Mines a block and adds it to the chain.
     */
    mine() {
        let prevHash = this.chain.length !== 0 ? this.chain[this.chain.length - 1].hash : '0';
        const start = Date.now();
        let nonce = this.proofOfWork(prevHash, this.generateMerkleRoot(this.pendingTransactions));
        const end = Date.now();
        this.addBlock(nonce);

        const timeTaken = (end - start) / 1000;
        console.log(`Block mined with nonce ${nonce} in ${timeTaken} seconds`);
    }

    /**
     * Adjusts the difficulty based on the average block generation time.
     */
    adjustDifficulty() {
        const totalTime = this.chain.slice(-this.difficultyAdjustmentInterval).reduce((total, block, index, array) => {
            if (index === 0) return 0;
            return total + (block.timestamp - array[index - 1].timestamp);
        }, 0);
        
        const averageTime = totalTime / (this.difficultyAdjustmentInterval - 1);
        console.log(`Average block generation time: ${averageTime} seconds`);

        if (averageTime > this.blockGenerationInterval) {
            this.difficulty--;
            console.log('Decreasing difficulty to', this.difficulty);
        } else if (averageTime < this.blockGenerationInterval) {
            this.difficulty++;
            console.log('Increasing difficulty to', this.difficulty);
        }
    }

    /**
     * Checks if the chain is valid by going through all blocks and comparing their stored
     * hash with the computed hash.
     */
    chainIsValid() {
        for (let i = 0; i < this.chain.length; i++) {
            let block = this.chain[i];
            let merkleRoot = this.generateMerkleRoot(block.transactions);

            if (block.hash !== this.getHash(block.prevHash, merkleRoot, block.nonce)) {
                return false;
            }

            if (i > 0 && block.prevHash !== this.chain[i - 1].hash) {
                return false;
            }
        }

        return true;
    }
}

/**
 * Simulates a blockchain with a specified number of transactions per block
 * over a number of blocks.
 */
function simulateChain(blockchain, numTxs, numBlocks) {
    for (let i = 0; i < numBlocks; i++) {
        let numTxsRand = Math.floor(Math.random() * Math.floor(numTxs));
        for (let j = 0; j < numTxsRand; j++){
            // Continued from previous code

        let sender = uuid.v4().substr(0, 5);
        let receiver = uuid.v4().substr(0, 5);
        blockchain.createTransaction(Math.floor(Math.random() * Math.floor(1000)), sender, receiver);
    }
    blockchain.mine();
}
}


const BChain = new Blockchain();
simulateChain(BChain, 5, 10);

console.dir(BChain, { depth: null });
console.log("**** Validity of this blockchain: ", BChain.chainIsValid());

module.exports = Blockchain;