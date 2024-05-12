# Token exchange between BTC and ETH on the network.

### 1. Multi-signatures
    In the BTC network, an ETH - ECDSA subscription is used to subscribe to a foreign resource.
    Because of this, you can share multi-signatures with others(https://github.com/taurusgroup/multi-party-sig ).
    That is, 2 participants can form 1 common address with 2 private parts with a threshold of 2.
    That is, to send transactions, one private part from each participant is needed.

### 2. ESCROW

1. (key creation stage)
    Alice and someone else can program 2. Escrow contains BTC and ETH.
    In ETH and BTC, you can synchronize one pair of key ECDSA and use
    it as you deposit money in ETH and BTC. At the moment, the participants form
    a pair of key ECDSA(for ETH) and Shcnorr(for BTC), so that you can further use
    them as 3 accounts that are controlled by both parties.

2. (Verification stage)
    Alice and Bob send tokens to a shared account and send them to replenish the required amount.
    Strings are not starting to be implemented, but the required number of tokens does not come to mind.

3. (Hash code of the withdrawal stage, exchange_wishes scheme.png)
    The parties send transaction hashes with their incomplete signature on the withdrawal of tokens from the network they need.
    I.e., each participant has a transaction signature that outputs each other's tokens. Next, they will need
    to exchange these signatures, making sure that the signature has been sent and that it is correct.

    Alice and Bob have saved their withdrawal hashes (their own hashes)
    Alice (hash code for withdrawal of funds with part of the signature) <-> Bob (hash code for withdrawal of funds with part of the signature)

4. (Escrow stage, escrwo_agent_works.png)
    Next, the participants send the agent a public key and a hash of the transaction on the withdrawal of their tokens to verify the signature, which will be sent by another participant. It also provides full information about the withdrawal of funds from another participant's deposit account.
    The agent, having signatures and transaction hashes, as well as public keys of escrow accounts,
    cross-checks the signatures of participants using the pub key and hash of the transaction for withdrawal of funds and, if they are correct, sends signatures to the parties.

    Alice (sends her own tx hash and Bob's signature) -> agent
    Bob (sends his own tx hash and Alice's signature) -> agent

```
Escrow Public Key 1
Alice's signature (Bob tokens) <-> Bob hash(Bob tokens)
Escrow Public Key 2
Alice's hash (Alice tokens) <-> Bob's signature (Alice's tokens)
``