from time import time
import hashlib
import json
from uuid import uuid4
from flask import Flask, jsonify, request
import requests
from urllib.parse import urlparse
from wallet import make_address, get_public_private_keys, match_sender_pub_priv_keys
import sys

class Blockchain:

    # For every blockchain created, there will be wallet embedded. 
    # It will have initial balance, which will get distributed over its lifetime
    def __init__(self):
        self.current_transactions = []    
        self.chain = []
        self.nodes = set()
        self.keys = {}
        self.keys['public_key'], self.keys['private_key'] = make_address()
        # genesis block
        self.add_block(previous_hash='1', proof=100, is_genisis=True)
    
    # For new registering node to blockchain
    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError("URL Invalid")

    # To ensure validity of "block chains"
    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False
            
            if not self.validate(last_block['proof'],
                        block['proof'], last_block_hash):
                return False
            last_block = block
            current_index += 1
        return True
    
    # Resolving conflicts between different nodes
    def resolve_conflicts(self):
        neighbors = self.nodes
        new_chain = None

        max_length = len(self.chain)

        for node in neighbors:
            url = f'http://{node}/chain'
            response = requests.get(url)

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain  = chain
        
        if new_chain:
            self.chain = new_chain
            return True
        return False

    # Helper method to hash a block
    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]
    
    # Makes new transaction from sender public and private key, recipent public key and amount
    # It also verifies if sender has enough balance
    # If is_genisis is True, then current block number is set to 1 as genisis block
    def new_transaction(self, sender_pub, sender_priv, recipient, amount, is_genisis=False):
        balance = 0
        if not is_genisis:
            balance = self.get_balance(sender_pub)
        if is_genisis or balance > int(amount):
            ts = {
                "sender_pub": sender_pub,
                "sender_priv": sender_priv,
                "recipient": recipient,
                "amount": amount
            }
            self.current_transactions.append(ts)
        else:
            return -1
        if is_genisis:
            return 1
        return self.last_block["index"] + 1
    
    # Create new block using previous block hash and proof of work nonce
    # If genisis block is True, then Intial currency is offered to blockchain's own wallet
    # Returns block
    def add_block(self, proof, previous_hash, is_genisis=False):
        if is_genisis:
            self.new_transaction("By Sun's grace", "By Moon's grace", self.keys['public_key'], "100000", is_genisis=is_genisis)
        block = {
            "index": len(self.chain) + 1,
            "timestamp": time(),
            "transactions": self.current_transactions,
            "proof": proof,
            "previous_hash": previous_hash or self.hash(self.chain[-1])
        }
        
        self.current_transactions = []
        self.chain.append(block)
        return block
    
    @staticmethod
    def validate(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    # Finding nonce of given difficulty
    def proof_of_work(self, last_block):
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.validate(last_proof, proof, last_hash) is False:
            proof += 1
        
        return proof
    
    # Tracks given public key from genisis block.
    # For every transaction, add money if is recipent or deduce if is sender 
    # Returns balance of public key
    def get_balance(self, public_key):
        url = f'http://127.0.0.1:5000/chain'
        response = requests.get(url)
        chain = ""
        if response.status_code == 200:
            chain = response.json()['chain']
        if chain == "" or public_key == "":
            raise ValueError("Blockchain not initiated or public key invalid")

        current_balance = 0

        for block in chain:
            transactions = block['transactions']
            for transaction in transactions:
                if transaction['recipient'] == public_key:
                    current_balance += int(transaction['amount'])
                if transaction['sender_pub'] == public_key:
                    current_balance -= int(transaction['amount'])

        
        return current_balance


app = Flask(__name__)

node_identifier = str(uuid4()).replace('-','')

blockchain = Blockchain()

# This function will mine the block, along with it will give 1000 tokens to last user registered from the wallet registered to node
@app.route('/mine', methods=['GET'])
def mine():
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)
    pub_s, priv_s = blockchain.keys['public_key'], blockchain.keys['private_key']
    pub_r, priv_r = get_public_private_keys(-1)

    blockchain.new_transaction(
        sender_pub=pub_s,
        sender_priv=priv_s,
        recipient=pub_r,
        amount="1000"
        )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.add_block(proof, 
                        previous_hash)
    
    response = {
        "message": "Block is created",
        "index": block['index'],
        "transactions": block['transactions'],
        "proof": block['proof'],
        "previous_hash" : block['previous_hash']
    }

    return jsonify(response), 200

# For creating new transactions, user should post public and private address of sender and public key of recipient and amount
# Its public key and private key are validated
# If transaction is verified, then only transaction is accepted
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    required = ['sender_pub', 'sender_priv', 'recipient', 'amount']

    if not all(k in values for k in required):
        return 'Missing Values', 400
    
    sender_pub = values['sender_pub']
    sender_priv = values['sender_priv']
    recipient = values['recipient']
    amount = values['amount']

    flag, message = match_sender_pub_priv_keys(sender_pub, sender_priv)
    print(message, file=sys.stderr)
    if not flag or int(amount) < 0 :
        return 'Invalid credentials :'+message, 400

    index = blockchain.new_transaction(sender_pub,sender_priv,
                        recipient,amount)
    if index == -1:
        response = {
        'message': f'Insufficient balance in {sender_pub}'
        }
        print("Insufficient balance in "+sender_pub, file=sys.stderr)
    else:
        response = {
            'message': f'Block #{index}'
            }
    return jsonify(response), 201

# Returns all blocks of chain
@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        "chain": blockchain.chain,
        "length": len(blockchain.chain)
    }
    return jsonify(response), 200

# Registers node to blockchain
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = json.loads(request.data)
    nodes = values.get('nodes')

    if nodes is None:
        return 'Error', 400
    
    for node in nodes:
        blockchain.register_node(
            "http://127.0.0.1:" + str(node)
        )
    
    response = {
        'message': "Added new nodes",
        'total_nodes': list(blockchain.nodes)
    }

    return jsonify(response), 201

# Resolve nodes of blockchain
@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': "replaced",
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': "no change"
        }
    
    return jsonify(response), 200

# Use this api to add generate new wallet address
@app.route('/wallet/new', methods=['GET'])
def new_wallet():
  public_key, private_key = make_address()
  response = {
    'private_key': private_key,
    'public_key': public_key
  }

  return jsonify(response), 200

# After balance, enter public key for some account and this will return balance of that account
@app.route('/balance/<public_key>', methods=['GET'])
def get_balance(public_key):

    balance = blockchain.get_balance(public_key)
    response = {
        'public_key' : public_key,
        'balance' : balance
    }
    print(public_key+" your balance is "+str(balance), file=sys.stderr)
    return jsonify(response), 200

# Runnable instance
if __name__ == "__main__":
    from argparse import ArgumentParser
    print(node_identifier)
    parser = ArgumentParser()

    parser.add_argument('-p', '--port',
                        default=5000,
                        type=int,
                        help="port num")
    
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port, 
            debug=True)