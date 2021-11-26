import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4

from argparse import ArgumentParser

import requests
from flask import Flask, jsonify, request, render_template

import rsa
from copy import deepcopy

from rsa.pkcs1 import VerificationError


class User:
    """
    Classe utilisateur, qui contient un pseudo et un jeu de clé RSA
    """

    def __init__(self, name: str) -> None:
        self.public, self.private = rsa.newkeys(1024)
        self.name = name

    def sign(self, transaction: dict) -> bytes:
        """
        :param transaction: transaction à signer
        :return: signature en bytes
        """
        # On transforme la transction en string
        message = json.dumps(transaction)
        # La librairie RSA permet de hasher/signer un string à partir d'une private key
        signature = rsa.sign(message.encode(), self.private, "SHA-256")
        return signature


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.current_offer = []
        self.current_contract = []
        # On rajoute une liste pour les signatures, len(self.current_transactions) == len(self.current_signatures)
        self.current_signatures_transactions = []
        self.current_signatures_offer = []
        self.current_signatures_contract = []
        self.chain = []

        # On génère 2 utilisateurs : le coinbase et le premier mineur
        a = User('miner')
        coinbase = User('coinbase')
        # On les insère dans un dictionnaire qui sert à garder en mémoire les User qui peuvent intéragir avec la blockchain
        self.ppl = {coinbase.name: coinbase, a.name: a}

        self.nodes = set()

        # On crée un dicctionnaire contenant une entrée par utilisateur recevant une transaction
        # Chaque entrée contient la liste des quantités reçues par l'utilisateur, avec l'index du bloc et de la transaction
        self.users = {'coinbase': [
            {'block_idx': 0, 'tx_idx': 0, 'amount': 1000}]}
        # On crée une copie de cet annuaire pour les transactions du bloc en cours
        self.future_users = deepcopy(self.users)

        # Create the genesis block
        self.padlock = {}
        self.new_block(previous_hash='1', proof=100)

        # Si ce booléen est True, on génère des fausses clés pour simuler une tentative d'attaque
        self.fake_keys = False

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """

        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            # Check that the hash of the block is correct
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        """
        This is our consensus algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.

        :return: True if our chain was replaced, False if not
        """

        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                # On copie aussi l'annuaire en cas de consensus
                users = response.json()['users']
                padlocks = response.json()['padlock']

                # Check if the length is longer and the chain is valid
                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain
                    new_users = users
                    new_padlock = padlocks

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            self.users = new_users
            self.padlock = new_padlock
            return True

        return False

    def new_block(self, proof, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = {
            'index': len(self.chain),
            'timestamp': time(),
            'transactions': self.current_transactions,
            'signatures_transactions': self.current_signatures_transactions,
            'offer': self.current_offer,
            'signatures_offer': self.current_signatures_offer,
            'contract': self.current_contract,
            'signatures_contract': self.current_signatures_contract,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of transactions
        self.current_transactions = []
        self.current_offer = []
        self.current_contract = []
        self.current_signatures_transactions = []
        self.current_signatures_offer = []
        self.current_signatures_contract = []

        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, coinbase=False):
        """
        Creates a new transaction to go into the next mined Block

        :param sender: Address of the Sender
        :param recipient: Address of the Recipient
        :param amount: Amount

        :param coinbase: si la transaction est coinbased, il faut refund l'utilisateur 'coinbase'

        :return: The index of the Block that will hold this transaction
        """

        # Si le sender et le recipient n'ont pas de compte dans le node, ils ne peuvent pas faire de transaction
        if sender not in self.ppl.keys() or recipient not in self.ppl.keys():
            return None

        # On indexe les transactions
        if len(self.current_transactions) == 0:
            index = 0
        else:
            index = 1 + self.current_transactions[-1]['index']

        transaction = {
            'index': index,
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        }

        # Avant d'ajouter la transaction, on vérifie que le sender a assez, et les anciennes transactions qui lui permettent de faire cette transaction
        available, idx_tx = self.verif_transaction(transaction)

        if not (available is None):
            # Si on a assez, on ajoute la transaction au bloc
            self.current_transactions.append(transaction)
            # On ajoute la somme envoyée au recipient dans l'annuaire temporaire self.future_users
            try:
                self.future_users[recipient].append(
                    {'block_idx': self.last_block['index'] + 1, 'tx_idx': index, 'amount': amount})
            except KeyError:
                self.future_users[recipient] = [
                    {'block_idx': self.last_block['index'] + 1, 'tx_idx': index, 'amount': amount}]
            # On retire les transactions utilisées et on ajoute la somme restante au sender dans l'annuaire
            rest = available - amount
            for i in idx_tx:
                self.future_users[sender].pop(i)

            self.future_users[sender].append(
                {'block_idx': self.last_block['index'] + 1, 'tx_idx': index, 'amount': rest})
        # Si on a pas assez, on annule la transaction
        else:
            return None

        # Refund du coinbase
        if coinbase:
            self.future_users[sender][0]['amount'] = 10000

        # On envoie la transaction au sender pour signature
        self.new_signature_transaction(sender, transaction)

        return self.last_block['index'] + 1

    def verif_transaction(self, transaction):
        """
        Verifie si la transaction est possible (si le sender a assez dans son compte)
        :param transaction: la transaction a valider
        :return: (None, None) si la transaction n'est pas valide (sender n'a jamais reçu d'argent, n'a pas assez d'argent)
                 (available, idx_tx) si la transaction est valide
        """

        sender = transaction['sender']
        amount = transaction['amount']

        # On récupère les transactions de sender
        try:
            list_tx = deepcopy(self.future_users[sender])
        except KeyError:
            return None, None

        # On remonte le long des transactions, et on additionne les montants reçus en gardant en mémoire les transactions
        available = 0
        idx_tx = []
        for i in range(len(list_tx)-1, -1, -1):
            available += list_tx[i]['amount']
            idx_tx.append(i)

            # Si la somme disponible dépasse la quantité de la transaction, on renvoie la somme dispo et les transactions nécessaires
            if available >= amount:
                return available, idx_tx
        return None, None

    def new_signature_transaction(self, sender, transaction):
        """
        Envoie la transaction au sender, pour qu'il la valide en la signant
        """
        signature = self.ppl[sender].sign(transaction)
        # On la rajoute sur la liste des signatures
        self.current_signatures_transactions.append(str(list(signature)))

    def new_offer(self, owner, max_duration, caution, price, padlock_id):

        if owner not in self.ppl.keys() or padlock_id not in self.ppl.keys():
            return None

        if len(self.current_offer) == 0:
            index = 0
        else:
            index = 1 + self.current_offer[-1]['index']

        if self.verif_offer(padlock_id):
            offer = {
                'index': index,
                'owner': owner,
                'max_duration': max_duration,
                'caution': caution,
                'price': price,
                'padlock_id': padlock_id,
            }
            self.current_offer.append(offer)
            self.padlock[padlock_id] = "available"
            self.new_signature_offer(padlock_id, offer)
            return self.last_block['index']+1, len(self.current_offer)-1
        else:
            return None

    def verif_offer(self, padlock):
        return(not (padlock in self.padlock))

    def new_signature_offer(self, padlock, offer):
        """
        Envoie l'offer au cadenas, pour qu'il la valide en la signant
        """
        signature = self.ppl[padlock].sign(offer)
        # On la rajoute sur la liste des signatures
        self.current_signatures_offer.append(str(list(signature)))

    def new_contract(self, offer_id, user, padlock_id, caution):
        if user not in self.ppl.keys() or padlock_id not in self.ppl.keys():
            return None, "Id not recognised"

        if len(self.chain[offer_id[0]]['offer'])-1 < offer_id[1]:
            return None, "Offer not found at this index"

        if len(self.current_contract) == 0:
            index = 0
        else:
            index = 1 + self.current_contract[-1]['index']

        if len(self.current_transactions) == 0:
            index_t = 0
        else:
            index_t = 1 + self.current_transactions[-1]['index']
        transaction = {
            'index': index_t,
            'sender': user,
            'recipient': padlock_id,
            'amount': caution,
        }

        if self.verif_contract(padlock_id):
            available, idx_tx = self.verif_transaction(transaction)
            if not (available is None):
                self.new_transaction(user, padlock_id, caution)
                contract = {
                    'index': index,
                    'offer_id': offer_id,
                    'user': user,
                    'sender': user,
                    'recipient': padlock_id,
                    'amount': caution,
                }
                self.current_contract.append(contract)
                self.padlock[padlock_id] = "not available"
                self.new_signature_contract(user, contract)
                return self.last_block['index']+1, len(self.current_contract)-1
            else:
                return None, "Transaction is not possible, not enough money"
        else:
            return None, "Offer not available"

    def verif_contract(self, padlock):
        return(self.padlock[padlock] == "available")

    def new_signature_contract(self, user, contract):
        """
        Envoie l'offer au cadenas, pour qu'il la valide en la signant
        """
        signature = self.ppl[user].sign(contract)
        # On la rajoute sur la liste des signatures
        self.current_signatures_contract.append(str(list(signature)))

    def check_signatures(self):
        """
        Vérification de la validité des signatures
        """
        # On regarde toutes les transactions dans le bloc
        for tx, signature in zip(self.current_transactions, self.current_signatures_transactions):
            # On génère des fausses paires de clés pour tester la réaction de la chaine aux tentatives de fraude
            if self.fake_keys:
                try:
                    pk, sk = rsa.newkeys(1024)
                    sign = [int(i[:-1]) for i in signature[1:].split()]
                    rsa.verify(json.dumps(tx).encode(), bytes(sign), pk)
                except VerificationError:
                    return {"message": "Some transactions are invalid"}
            # On utilise le module rsa pour vérifier nos signatures, en cas d'erreur on envoie un message d'erreur
            try:
                sign = [int(i[:-1]) for i in signature[1:].split()]
                rsa.verify(json.dumps(tx).encode(), bytes(
                    sign), self.ppl[tx['sender']].public)
            except VerificationError:
                return {"message": "Some transactions are invalid"}

        for tx, signature in zip(self.current_offer, self.current_signatures_offer):
            # On génère des fausses paires de clés pour tester la réaction de la chaine aux tentatives de fraude
            if self.fake_keys:
                try:
                    pk, sk = rsa.newkeys(1024)
                    sign = [int(i[:-1]) for i in signature[1:].split()]
                    rsa.verify(json.dumps(tx).encode(), bytes(sign), pk)
                except VerificationError:
                    return {"message": "Some offers are invalid"}
            # On utilise le module rsa pour vérifier nos signatures, en cas d'erreur on envoie un message d'erreur
            try:
                sign = [int(i[:-1]) for i in signature[1:].split()]
                rsa.verify(json.dumps(tx).encode(), bytes(
                    sign), self.ppl[tx['padlock_id']].public)
            except VerificationError:
                return {"message": "Some offers are invalid"}

        for tx, signature in zip(self.current_contract, self.current_signatures_contract):
            # On génère des fausses paires de clés pour tester la réaction de la chaine aux tentatives de fraude
            if self.fake_keys:
                try:
                    pk, sk = rsa.newkeys(1024)
                    sign = [int(i[:-1]) for i in signature[1:].split()]
                    rsa.verify(json.dumps(tx).encode(), bytes(sign), pk)
                except VerificationError:
                    return {"message": "Some contracts are invalid"}
            # On utilise le module rsa pour vérifier nos signatures, en cas d'erreur on envoie un message d'erreur
            try:
                sign = [int(i[:-1]) for i in signature[1:].split()]
                rsa.verify(json.dumps(tx).encode(), bytes(
                    sign), self.ppl[tx['user']].public)
            except VerificationError:
                return {"message": "Some contracts are invalid"}
        return None

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """

        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        """
        Simple Proof of Work Algorithm:

         - Find a number p' such that hash(pp') contains leading 4 zeroes
         - Where p is the previous proof, and p' is the new proof

        :param last_block: <dict> last Block
        :return: <int>
        """

        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        """
        Validates the Proof

        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param last_hash: <str> The hash of the Previous Block
        :return: <bool> True if correct, False if not.

        """

        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:3] == "000"

    def new_user(self, name: str, padlock=False) -> None:
        """
        On crée un nouvel utilisateur avec le pseudo 'name', qui pourra interagir avec la chaine
        """
        user = User(name)
        self.ppl[user.name] = user
        if padlock:
            self.padlock[user.name] = "available"


# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')
node_identifier = 'miner'

# Instantiate the Blockchain
blockchain = Blockchain()

parser = ArgumentParser()
parser.add_argument('-p', '--port', default=5000,
                    type=int, help='port to listen on')
parser.add_argument('-nn', '--node_name', default="miner",
                    type=str, help='name of the node')
args = parser.parse_args()
port = args.port
node_identifier = args.node_name
blockchain.new_user(node_identifier)
node_address = f"http://localhost:{port}"


@app.route('/set_fake', methods=['GET'])
def set_fake():
    blockchain.fake_keys = not blockchain.fake_keys
    response = {
        'message': f"Changed fake_keys to {blockchain.fake_keys}",
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # We must receive a reward for finding the proof.
    # The sender is "0" to signify that this node has mined a new coin.
    blockchain.new_transaction(
        sender="coinbase",
        recipient=node_identifier,
        amount=100,
        coinbase=True
    )

    verif = blockchain.check_signatures()

    if verif is not None:
        blockchain.current_transactions = []
        blockchain.current_offer = []
        blockchain.current_contract = []
        blockchain.current_signatures_transactions = []
        blockchain.current_signatures_offer = []
        blockchain.current_signatures_contract = []
        blockchain.users = deepcopy(blockchain.future_users)
        return jsonify(verif), 777

    blockchain.users = deepcopy(blockchain.future_users)

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    # blockchain.future_users = blockchain.users.copy()

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'offer': block['offer'],
        'contract': block['contract'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    index = blockchain.new_transaction(
        values['sender'], values['recipient'], float(values['amount']))

    if not(index is None):
        sender = values['sender']
        recipient = values['recipient']
        amount = float(values['amount'])
        response = {
            'message': f'{sender} will send {amount} coins to {recipient} in Block {index}'}
    else:
        response = {'message': f'Transaction is not possible, not enough money'}
    return jsonify(response), 201


@app.route('/offer/new', methods=['POST'])
def new_offer():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['owner', 'max_duration', 'caution', 'price', 'padlock_id']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    a = blockchain.new_offer(values['owner'], float(values['max_duration']),
                             float(values['caution']), float(values['price']), values['padlock_id'])
    if a != None:
        index_block, index_offer = a
        response = {
            'message': f'Offer {index_offer} will be added to Block {index_block}'}
    else:
        response = {'message': 'Padlock already used'}

    return jsonify(response), 201


@app.route('/contract/new', methods=['POST'])
def new_contract():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['offer_block', 'offer_index', 'user']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    n_block, n_offer = int(values['offer_block']), int(values['offer_index'])
    padlock_id = blockchain.chain[n_block]['offer'][n_offer]['padlock_id']
    caution = blockchain.chain[n_block]['offer'][n_offer]['caution']

    a, message = blockchain.new_contract(
        (n_block, n_offer), values['user'], padlock_id, caution)
    if a != None:
        index_block, index_contract = a, message
        response = {
            'message': f'Contract {index_contract} will be added to Block {index_block}'}
    else:
        response = {'message': message}

    return jsonify(response), 201


@app.route('/end_contract', methods=['POST'])
def end_contract():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['contract_block', 'contract_index', 'duration']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new Transaction
    n_block_c, n_contract = int(values['contract_block']), int(
        values['contract_index'])
    contract = blockchain.chain[n_block_c]['contract'][n_contract]
    padlock_id = contract['recipient']
    user = contract['sender']
    offer_id = contract['offer_id']

    n_block_o, n_offer = offer_id
    offer = blockchain.chain[n_block_o]['offer'][n_offer]
    max_duration = offer['max_duration']
    caution = offer['caution']
    owner = offer['owner']
    price = offer['price']

    if float(values['duration']) >= max_duration:
        total_price = caution
    else:
        total_price = float(values['duration'])*price

    blockchain.new_transaction(padlock_id, user, caution-total_price)
    blockchain.new_transaction(padlock_id, owner, total_price)

    blockchain.padlock.pop(padlock_id)
    index_block, index_offer = blockchain.new_offer(
        owner, max_duration, caution, price, padlock_id)

    amount_user = caution-total_price
    amount_owner = total_price

    response = {
        'message': f'Offer {index_offer} will be added to Block {index_block}, {user} will receive {amount_user} and {owner} will receive {amount_owner}'}
    return jsonify(response), 201


@app.route('/user/new', methods=['POST'])
def new_user():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['name']
    if not all(k in values for k in required):
        return 'Missing values', 400

    if values['name'] in blockchain.ppl.keys():
        response = {'message': f'Name already taken, plz change'}
        return jsonify(response), 666

    # Create a new user
    blockchain.new_user(values['name'])

    name = values['name']

    response = {'message': f'User {name} succesfully created'}
    return jsonify(response), 201


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'users': blockchain.users,
        'padlock': blockchain.padlock
    }
    return jsonify(response), 200


@app.route('/users', methods=['GET'])
def see_users():
    response = {
        'users': blockchain.users,
        'length': len(blockchain.users),
    }
    return jsonify(response), 200


@app.route('/future', methods=['GET'])
def see_future():
    response = {
        'users': blockchain.future_users,
        'length': len(blockchain.future_users),
    }
    return jsonify(response), 200


def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    # if nodes is None:
    # return "Error: Please supply a valid list of nodes", 400
    if nodes != None:
        for node in nodes:
            if urlparse(node).netloc not in blockchain.nodes:
                blockchain.register_node(node)
                data = ["http://"+i for i in blockchain.nodes]
                data.append(node_address)
                data.remove(node)
                requests.post(f"{node}/nodes/register", json={"nodes": data})
    response = {
        'message': f'New nodes have been added to {node_identifier}',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


@ app.route('/padlock/app', methods=['GET'])
def padlock_app():
    return render_template('padlock_app.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)
