# Spec for dapol codebase

DAPOL+ protocol introduced in the "Generalized Proof of Liabilities" by Yan Ji and Konstantinos Chalkias ACM CCS 2021 paper, available [here](https://eprint.iacr.org/2021/1350).

The implementation is written in Rust due to a) the readily available libraries for Bulletproofs & other ZK crypto, and b) the performance benefits, as building the tree is an expensive computation for real-world input sizes.

**Key:**
- Entity (aka user) - Represents a single unit of the external data that is to be modeled by the PoL. Each entity has an ID ($\text{id}_u$) and a liability ($l_u$).
- $\mathcal{P}$ - constructor of the tree (aka prover)
- PBB - (public bulletin board)

## PoL data, functions & parameters

### Functions

Functions from paper and their equivalents in the code:

#### Setup

**Output**: produces the Public Data (root hash, root commitment) & Secret Data (master secret, leaf node mapping** tuples

**Code equivalents**:
- `DapolTree::public_root_data`, which is made up of these 2:
  - `DapolTree::root_hash`
  - `DapolTree::root_commitment`
- `DapolTree::master_secret`
- `DapolTree::entity_mapping`

#### ProveTot

**Output**: reveals the blinding factor and the liability sum

**Code equivalents**:
- `DapolTree::secret_root_data`, which is made up of these 2:
  - `DapolTree::root_liability`
  - `DapolTree::root_blinding_factor**

#### VerifyTot

**Output**: checks that Public Data corresponds to the Secret Data

**Code equivalent**: `DapolTree::verify_root_commitment`

#### Prove

**Output**: inclusion proof generation for an entity

**Code equivalent**: `DapolTree::generate_inclusion_proof`

#### Verify

**Output**: verify inclusion proof

**Code equivalent**: `InclusionProof::verify`

### Public parameters

DAPOL+ requires the following public parameters to be set before generating any trees:

$$\left( ( \mathbb{G}, g, h ), \mathcal{R}, N, \text{MaxL}, H, S_{\text{com}}, S_{\text{hash}} \right)$$

where
- $\mathbb{G}$ is a group of prime order, with generators $g$ & $h$ s.t. their relative logarithm is unknown
- $N$ is the upper bound on the number of entities i.e. if $n$ is the number of entities to be modeled by the tree, then $n < N$ (note that we must have $N \le 2^H$ since that is the maximum number of bottom layer leaf node for entities)
- $\text{MaxL}$ is the maximum liability of any single entity, and is used to determine the upper bound for the range proof: $N \text{MaxL}$
- $H$ is the height of the tree
- $S_{\text{com}}$ is the salt used to calculate a leaf/padding node's Pedersen commitment
- $S_{\text{hash}}$ is the salt used to calculate a leaf/padding node's hash
- $\mathcal{R}$ is the range proof protocol

The following values are set automatically by the codebase:
- $\mathbb{G}$ is the Ristretto group, TODO what are the generators?
- $\mathcal{R}$ is the Bulletproofs protocol
- $N=2^H$ because why would anyone want to publicly lower the upper bound?
- $\text{MaxL}=2^{B-H}$ so that the upper bound is $2^B$ where $B$ is set by $\mathcal{P}$ (the Bulletproofs library requires a power of 2 as the upper bound)

These values can be set by $\mathcal{P}$
- $B$ which is the bit length of the range proof upper bound (defaults to 64)
- Both the salts (randomly generated if not set)

Both the salts should be changed for each PoL generated TODO say why (involves brute force attacks and master secret)

### Public data (PD)

Each tree in DAPOL+ has a PD tuple which needs to be posted on a PBB for the PoL protocol to function properly.

$$PD = (C_{\text{root}}, H_{\text{root}})$$PD

The hash & Pedersen commitment of the root node.

This data is available in the API via TODO

### Secret data (SD)

As with PD there is an SD tuple for each tree:

$$SD = (M, \epsilon)$$

where $M$ is the master secret and $\epsilon$ is a map from entity to leaf node (only required for the NDM SMT).

#### $M$

$M$ must be kept seen only by $\mathcal{P}$ because exposing this would mean $\text{id}_u$'s & $l_i$'s could be guessed by brute-force method (if the ID space used is small enough and IDs have low entropy):
1. An adversary ($\mathcal{A}$) gains access to a leaf node's data (hash & Pedersen commitment)
1. $athcal{A}$ guesses $\text{id}_u$ and calculates $w_u = \text{KDF}(M, \text{id}_u)$
2. $athcal{A}$ calculates $s_u = \text{KDF}(w_u, S_{\text{hash}})$
3. $athcal{A}$ calculates $h_u = \text{hash}(\text{"leaf"} | \text{id}_u | s_u)
4. If $h_u$ is equal to the hash of the leaf node then $\mathcal{A}$ has guessed $\text{id}_u$ correctly, otherwise go back to #1

TODO what if you have multiple $w_u$'s and id_u's? can you try find the master secret?

The paper advises to keep $M$ the same across PoLs so that users only need to request $w_u = \text{KDF}(M, \text{id}_u)$ from the exchange once. TODO say more TODO say why having the same master secret is not a security concern

#### $\epsilon$

The user mapping (if using an NDM SMT) must be known only by $\mathcal{P}$ because exposing this will leak user IDs and where they are mapped to on the tree.

In the code $\epsilon$ is a hashmap from entity ID to x-coordinate on the bottom layer of the tree.

### Tree

The security & privacy proofs in the paper assume the tree is held by $\mathcal{P}$ and so it is recommended that the tree be kept secret and inclusion proofs only given out to authenticated entities.

## Dependencies

The KDF protocol used is [HKDF-SHA256](https://datatracker.ietf.org/doc/html/rfc5869) with [this implementation](https://docs.rs/hkdf/latest/hkdf/). The implementation requires a hash function; [SHA256](https://docs.rs/sha2/latest/sha2/) is used.

[blake3](https://docs.rs/blake3/latest/blake3/) is used as the hash function to construct the Merkle tree.

[`thread_rng` from rand](https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html) is used as the CSPRNG for the shuffle algorithm for the NDM SMT.

### Bulletproofs

Bulletproofs is chosen as the range proof protocol because it is efficient, allows aggregation, and has no trusted setup. This is the range proof protocol suggested by the paper.

The following codebase is used as the implementation: [zkcrypto/bulletproofs](https://github.com/zkcrypto/bulletproofs). There is another codebase available but it has weaker performance than the one currently being used. There is some funny business with the cargo crate versions, which is detailed [here](https://github.com/zkcrypto/bulletproofs/issues/15).

When calculating a range proof the upper bound parameter is a bit length, which means only powers of 2 are supported. More than that, the upper bound bit length can only be one of: 8 16 32 64, otherwise the library will throw an error.

The Bulletproofs code is also used for calculating Pedersen commitments, and the following section provides details.

### Ristretto

The [Ristretto Group](https://ristretto.group) for Curve25519 as the elliptic curve group for the Pedersen commitments. [curve25519-dalek-ng](https://github.com/zkcrypto/curve25519-dalek-ng) is the rust implementation used, which is a fork of [curve25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek/) (see [this gh issue](https://github.com/zkcrypto/bulletproofs/issues/15) for details on the fork).

The paper requires 2 generators of $G$, $g_1$ & $g_2$, such that their relative discrete logarithm is unknown.

$g_1$ is set to the point defined [here](https://github.com/zkcrypto/curve25519-dalek-ng/blob/763a0faaf54752b06702b39e2296173ab76c2204/src/backend/serial/u64/constants.rs#L129), which is exactly the same as the point used in the Bulletproofs implementation. The point is said to be the 'Ed25519 basepoint' but it is not clear if the point is equal to the one defined in [the RFC for Ed25519](https://datatracker.ietf.org/doc/html/rfc8032) or the base point for Curve25519 given by [SafeCurves](https://safecurves.cr.yp.to/base.html). The differences may be due to different encoding methods (dalek encoding of field elements is explained [here](https://doc-internal.dalek.rs/curve25519_dalek/backend/serial/u64/field/struct.FieldElement51.html)). The order of the base point [is said to be](https://github.com/zkcrypto/curve25519-dalek-ng/blob/763a0faaf54752b06702b39e2296173ab76c2204/src/backend/serial/u64/constants.rs#L95) the prime $2^252 + 27742317777372353535851937790883648493$, which is the same as the order of the other 2 base points in the literature, and will produce a subgroup of co-factor 8 (which is what we what, essentially).

$g_2$ is formed from the SHA3-512 hash of $g_1$ using [this function](https://github.com/zkcrypto/curve25519-dalek-ng/blob/763a0faaf54752b06702b39e2296173ab76c2204/src/ristretto.rs#L688), which claims that the that "the discrete log of the output point with respect to any other point should be unknown".

## NDM-SMT shuffle algorithm

"Durstenfeld’s shuffle algorithm optimized by HashMap" is explained in the paper, but contains a minor error. The error is fixed in the implementation. More details can be found [here](https://hackmd.io/@JI2FtqawSzO-olUw-r48DQ/Hka8tkdNT).

## Code details

TODO

A hash map is used to store the nodes when building the tree

panic if there is a bug in the code. if the input is incorrect then return an error result, so that calling code can take action.

### Limits & types

For the tree height:
- max height: 64 (64 was chosen as the max height because with the NDM SMT we can have $2^36$ ($~70\text{B}$) entities and still have only $10^-9$ of the bottom layer spaces filled. With DM SMT we may need to increase this max.)
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

