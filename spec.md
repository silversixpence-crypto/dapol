# Spec for dapol codebase

DAPOL+ protocol introduced in the "Generalized Proof of Liabilities" by Yan Ji and Konstantinos Chalkias ACM CCS 2021 paper, available [here](https://eprint.iacr.org/2021/1350).

The implementation is written in Rust due to a) the readily available libraries for Bulletproofs & other ZK crypto, and b) the performance benefits, as building the tree is an expensive computation for real-world input sizes.

**Key:**
- Entity (aka user) - Represents a single unit of the external data that is to be modeled by the PoL. Each entity has an ID ($\text{id}_u$) and a liability ($l_u$).
- $\mathcal{P}$ - constructor of the tree (aka prover)
- PBB - (public bulletin board)

## PoL data, functions & parameters

### Public parameters

DAPOL+ requires the following public parameters to be set before generating any trees:

$$\left( ( \mathbb{G}, g_1, g_2 ), \mathcal{R}, N, \text{MaxL}, H, S_{\text{com}}, S_{\text{hash}} \right)$$

where
- $\mathbb{G}$ is a group of prime order, with generators $g_1$ & $g_2$ s.t. their relative logarithm is unknown
- $N$ is the upper bound on the number of entities i.e. if $n$ is the number of entities to be modeled by the tree, then $n < N$ (note that we must have $N \le 2^H$ since that is the maximum number of bottom layer leaf node for entities)
- $\text{MaxL}$ is the maximum liability of any single entity, and is used to determine the upper bound for the range proof: $N \text{MaxL}$
- $H$ is the height of the tree
- $S_{\text{com}}$ is the salt used to calculate a leaf/padding node's Pedersen commitment
- $S_{\text{hash}}$ is the salt used to calculate a leaf/padding node's hash
- $\mathcal{R}$ is the range proof protocol

The following values are set automatically by the codebase:
- $\mathbb{G}$ is the Ristretto Group for Curve25519 with the following generator elements
  - $g_1=$ [ED25519_BASEPOINT](https://github.com/zkcrypto/curve25519-dalek-ng/blob/ae4bf40e28bddee0f3a6a6b3d7492874c24c2e54/src/backend/serial/u64/constants.rs#L129)
  - $g_2=\text{pointFromHash}(\text{hash}(g_1))$ (SHA3 is used as the hash function, and the Elligator map is used to turn the digest into an elliptic curve point, see [here](https://github.com/zkcrypto/curve25519-dalek-ng/blob/ae4bf40e28bddee0f3a6a6b3d7492874c24c2e54/src/ristretto.rs#L688) for more details, also [Ristretto group section](#Ristretto))
- $\mathcal{R}$ is the Bulletproofs protocol
- $N=2^H$ because this sets the highest possible upper bound

These values can be set by $\mathcal{P}$:
- $\text{MaxL}$ (default is $2^{32}$)
- Both the salts (default to being randomly generated using a CSPRNG)

#### Note on the salts

Both the salts should be changed for each PoL generated. If this is not done then blinding factors & hashes for leaf nodes do not change across PoLs, so there are 2 possible ways of gaining some information:
1. An attacker can detect which leaf node belongs to the same entity across 2 PoLs by matching up leaf node hashes. Of course they would need access to the leaf nodes of tree to be able to do this, so the attack can be minimized by sharing parts of the tree only with registered entities.
2. If an entity's balance has changed from 1st to 2nd PoL then an attacker can guess the balance by dividing the commitments. Since the entity's balance is not an input to the hash function the attacker can first perform the above attack to locate leaf nodes that match to the same user, then do the division. The division attack goes like this:
    1. Entity's 2 leaf node commitments are $c_u=g^{l_u}_1 g^{b_u}_2$ & $c'_u=g^{l'_u}_1 g^{b_u}_2$
    2. Attacker divides the 2 to get $c=g^{l_u-l'_u}_1$
    3. The liabilities generally have less than 64 bits of entropy so the attacker can guess the value of $l_u-l'_u$, which gives the attacker insight into the trading actions taken by the entity

### Public data (PD)

Each tree in DAPOL+ has a PD tuple which needs to be posted on a PBB for the PoL protocol to function properly. The PD tuple consists of the hash & Pedersen commitment of the root node: $PD = (C_{\text{root}}, H_{\text{root}})$.

### Secret data (SD)

As with PD there is an SD tuple for each tree: $SD = (M, \epsilon)$ where $M$ is the master secret and $\epsilon$ is a map from entity to leaf node.

#### Master secret $M$

$M$ must be seen only by $\mathcal{P}$ because exposing this value would mean an attacker could guess an entity's ID from the leaf node hash (assuming the ID has low entropy) using the below steps. Once an attacker has the ID they can guess the entity's liability from the leaf node's commitment value.
1. An adversary ($\mathcal{A}$) gains access to a leaf node's data (hash & Pedersen commitment)
2. $\mathcal{A}$ guesses $\text{id}_u$ and calculates $w_u = \text{KDF}(M, \text{id}_u)$
3. $\mathcal{A}$ calculates $s_u = \text{KDF}(w_u, S_{\text{hash}})$
4. $\mathcal{A}$ calculates $h_u = \text{hash}(\text{"leaf"} | \text{id}_u | s_u)$
5. If $h_u$ is equal to the hash of the leaf node then $\mathcal{A}$ has guessed $\text{id}_u$ correctly, otherwise go back to #1

The paper advises to keep $M$ the same across PoLs so that entities only need to request their verification key $w_u = \text{KDF}(M, \text{id}_u)$ from the exchange once, and then reuse it to do verification on all PoLs. Having the same master secret does not pose a security risk for $\mathcal{P}$ because it is only used to generate the verification keys for the entity, and it is passed through a key derivation function for this so that simply having the verification key does not allow one to guess the master secret in reasonable time. In order for this security to hold, however, it is important to have a master secret with high entropy ($>256$ bits).

#### Entity mapping $\epsilon$

The user mapping must be known only by $\mathcal{P}$ because exposing this will leak user IDs and where they are mapped to on the tree. The entity map is not required for the DM-SMT accumulator variant since the mapping is deterministically generated from the master secret.

In the code $\epsilon$ is a hashmap from entity ID to x-coordinate on the bottom layer of the tree.

### Tree

The security & privacy proofs in the paper assume the tree is held by $\mathcal{P}$ and so it is recommended that the tree be kept secret and inclusion proofs only given out to authenticated entities.

### Functions

Functions from the paper and their equivalents in the code:

| Function in paper | Description                                            | Equivalents in code                                                                                                                                  |
|:------------------|:-------------------------------------------------------|:-----------------------------------------------------------------------------------------------------------------------------------------------------|
| Setup             | Produces the PD & SD tuples                            | `DapolTree::public_root_data`<br>`DapolTree::root_hash`<br>`DapolTree::root_commitment`<br>`DapolTree::master_secret`<br>`DapolTree::entity_mapping` |
| ProveTot          | Reveals the blinding factor and the liability sum      | `DapolTree::secret_root_data`<br>`DapolTree::root_liability`<br>`DapolTree::root_blinding_factor`                                                    |
| VerifyTot         | Checks that Public Data corresponds to the Secret Data | `DapolTree::verify_root_commitment`                                                                                                                  |
| Prove             | Inclusion proof generation for an entity               | `DapolTree::generate_inclusion_proof`                                                                                                                |
| Verify            | Verify inclusion proof                                 |  `InclusionProof::verify`                                                                                                                                                    |


## Dependencies

The KDF protocol used is [HKDF-SHA256](https://datatracker.ietf.org/doc/html/rfc5869) with [this implementation](https://docs.rs/hkdf/latest/hkdf/). The implementation requires a hash function; [SHA256](https://docs.rs/sha2/latest/sha2/) is used.

[blake3](https://docs.rs/blake3/latest/blake3/) is used as the hash function to construct the Merkle tree.

[`thread_rng` from rand](https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html) is used as the CSPRNG for the shuffle algorithm for the NDM-SMT.

### Bulletproofs

Bulletproofs is chosen as the range proof protocol because it is efficient, allows aggregation, and has no trusted setup. This is the range proof protocol suggested by the paper.

The following codebase is used as the implementation: [zkcrypto/bulletproofs](https://github.com/zkcrypto/bulletproofs). There is another codebase available but it has weaker performance than the one currently being used. There is some funny business with the cargo crate versions, which is detailed [here](https://github.com/zkcrypto/bulletproofs/issues/15).

When calculating a range proof the upper bound parameter is a bit length, which means only powers of 2 are supported. More than that, the upper bound bit length can only be one of: 8 16 32 64, otherwise the library will throw an error.

The Bulletproofs code is also used for calculating Pedersen commitments, and the following section provides details.

### Ristretto

The [Ristretto Group](https://ristretto.group) for Curve25519 is used as the elliptic curve group for the Pedersen commitments. [curve25519-dalek-ng](https://github.com/zkcrypto/curve25519-dalek-ng) is the rust implementation used, which is a fork of [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/) (see [this gh issue](https://github.com/zkcrypto/bulletproofs/issues/15) for details on the fork).

The paper requires 2 generators of $G$, $g_1$ & $g_2$, such that their relative discrete logarithm is unknown.

$g_1$ is set to the point defined [here](https://github.com/zkcrypto/curve25519-dalek-ng/blob/763a0faaf54752b06702b39e2296173ab76c2204/src/backend/serial/u64/constants.rs#L129), which is exactly the same as the point used in the Bulletproofs implementation. The point is said to be the 'Ed25519 basepoint' but it is not clear if the point is equal to the one defined in [the RFC for Ed25519](https://datatracker.ietf.org/doc/html/rfc8032) or the base point for Curve25519 given by [SafeCurves](https://safecurves.cr.yp.to/base.html). The differences may be due to different encoding methods (dalek encoding of field elements is explained [here](https://doc-internal.dalek.rs/curve25519_dalek/backend/serial/u64/field/struct.FieldElement51.html)). The order of the base point [is said to be](https://github.com/zkcrypto/curve25519-dalek-ng/blob/763a0faaf54752b06702b39e2296173ab76c2204/src/backend/serial/u64/constants.rs#L95) the prime $2^{252} + 27742317777372353535851937790883648493$, which is the same as the order of the other 2 base points in the literature, and will produce a subgroup of co-factor 8 (which is what we what, essentially).

$g_2$ is formed from the SHA3-512 hash of $g_1$ using [this function](https://github.com/zkcrypto/curve25519-dalek-ng/blob/763a0faaf54752b06702b39e2296173ab76c2204/src/ristretto.rs#L688), which claims that the that "the discrete log of the output point with respect to any other point should be unknown".

## NDM-SMT shuffle algorithm

"Durstenfeld’s shuffle algorithm optimized by HashMap" is explained in the paper, but contains a minor error. The error is fixed in the implementation. More details can be found [here](https://hackmd.io/@JI2FtqawSzO-olUw-r48DQ/Hka8tkdNT).

## Code details

TODO

A hash map is used to store the nodes when building the tree

panic if there is a bug in the code. if the input is incorrect then return an error result, so that calling code can take action.

### Limits & types

For the tree height:
- max height: 64 (64 was chosen as the max height because with the NDM-SMT we can have $2^36$ ($~70\text{B}$) entities and still have only $10^-9$ of the bottom layer spaces filled. With DM SMT we may need to increase this max.)
- min height: 2
- type: u8 (2^8 = 256 is more than big enough as the maximum possible height)

TODO more

### Naming & orientation

TODO

paper uses term idx but code uses coordinate

y-coord is 0 where the bottom leaves are and height-1 where the root node is
x-coord is 0 at the left of the tree (imagine the tree squashed to the left making it seem slanted on the right)

### Knobs $\mathcal{P}$ can use to adjust efficiency trade-offs

Store depth TODO

