# Spec for [dapol](https://github.com/silversixpence-crypto/dapol) codebase

## Intro

This repo is a Rust implementation of the DAPOL+ protocol, which was introduced in the "Generalized Proof of Liabilities" ACM CCS 2021 paper, by Yan Ji and Konstantinos Chalkias (available [here](https://eprint.iacr.org/2021/1350)).

DAPOL+ (Distributed Auditing Proof of Liabilities) is a protocol around a Merkle Sum Tree that allows an entity to cryptographically commit to it's liabilities in a way that maintains data privacy and verifiability. Some examples of where this protocol is useful:
- Centralized cryptocurrency exchange uses DAPOL+ to commit to the digital asset balances it owes it's users, and the users can verify that their balances are correctly represented in the tree
- Hospitals commit to their COVID case count, and their patients can check that their case was correctly recorded

This repo is part of a larger Proof of Reserves project, and more information on that you can check out this [top-level doc for the project](https://hackmd.io/p0dy3R0RS5qpm3sX-_zreA).

The implementation is written in Rust due to a) the readily available libraries for Bulletproofs & other ZK crypto, and b) the performance benefits, as building the tree is an expensive computation for real-world input sizes.

## How Proof of Liabilities (PoL) works

This is a brief explanation of PoL. For a deeper dive on Proof of Liabilities you can check out [this blog](https://reservex.io/blogs/1). For a full formulation of DAPOL+ see the original paper.

**KEY:**
- Entity (aka user) - Represents a single unit of the external data that is to be modeled by the protocol. Each entity has an ID ($\text{id}_u$) and a liability ($l_u$).
- $\mathcal{P}$ - constructor of the tree (aka prover)
- PBB - (public bulletin board)

Let's explain with the example of the cryptocurrency exchange mentioned above: $\mathcal{P}$ is an exchange that has some users. The users send the exchange fiat currency in exchange for cryptocurrency. The exchange custodies the cryptocurrency on behalf of its users (meaning that the users do not have control of the funds, the exchange does). We say the exchange has a **liability** to each of its users. The liability is a positive integer representing the exact amount of cryptocurrency that the exchange is holding for them. The liability should only change when the user takes action, but since the exchange owns the data they could maliciously change the data to their advantage. The users thus request that the exchange cryptographically commit to its liabilities such that:
- the commitment can be posted on a PBB
- the exchange cannot change any liability after the commitment is posted on the PBB
- the total liability sum is calculated as part of the commitment
- users can check what their liability is in the commitment
- user data stays hidden throughout the whole process

Here is a simplified version of the Proof of Liabilities function (see the paper for a more detailed formulation):
$$
P(\{\text{users' liabilities}\}) = \text{commitment}
$$

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
- $\mathcal{R}$ is the Bulletproofs protocol, also using the Ristretto Group for Curve25519
- $N=2^H$ because this sets the highest possible upper bound

These values can be set by $\mathcal{P}$:
- $\text{MaxL}$ (default is $2^{32}$)
- $H$ (default is $32$)
- Both the salts (default to being randomly generated using a CSPRNG)

#### Note on the salts

Both the salts should be changed for each PoL generated. If this is not done then blinding factors & hashes for leaf nodes do not change across PoLs, so there are 2 possible ways an attacker can gain some information:
1. An attacker can detect which leaf node belongs to the same entity across 2 PoLs by matching up leaf node hashes. Of course they would need access to the leaf nodes of the tree to be able to do this, so the attack can be minimized by sharing parts of the tree only with registered entities.
2. If an entity's balance has changed from 1st to 2nd PoL then an attacker can guess the balance by dividing the commitments. Since the entity's balance is not an input to the hash function the attacker can first perform the above attack to locate leaf nodes that match to the same user, then do the division. The division attack goes like this:
    1. Entity's 2 leaf node commitments are $c_u=g^{l_u}_1 g^{b_u}_2$ & $c'_u=g^{l'_u}_1 g^{b_u}_2$
    2. Attacker divides the 2 to get $c=g^{l_u-l'_u}_1$
    3. The liabilities generally have less than 64 bits of entropy so the attacker can guess the value of $l_u-l'_u$, which gives the attacker insight into the trading actions taken by the entity

### Public data (PD)

Each tree in DAPOL+ has a PD tuple which needs to be posted on a PBB for the PoL protocol to function properly. The PD tuple consists of the hash & Pedersen commitment of the root node: $PD = (h_{\text{root}}, c_{\text{root}})$.

### Secret data (SD)

As with PD there is an SD tuple for each tree: $SD = (M, \epsilon)$ where $M$ is the master secret and $\epsilon$ is a map from entity to leaf node.

#### Master secret $M$

$M$ must be seen only by $\mathcal{P}$ because exposing this value would mean an attacker could guess an entity's ID from the leaf node hash (assuming the ID has low entropy) using the below steps. Once an attacker has the ID they can guess the entity's liability from the leaf node's commitment value (assuming the liability has low entropy).
1. An adversary ($\mathcal{A}$) gains access to a leaf node's data (hash & Pedersen commitment)
2. $\mathcal{A}$ guesses $\text{id}_u$ and calculates $w_u = \text{KDF}(M, \text{id}_u)$
3. $\mathcal{A}$ calculates $s_u = \text{KDF}(w_u, S_{\text{hash}})$
4. $\mathcal{A}$ calculates $h_u = \text{hash}(\text{"leaf"} | \text{id}_u | s_u)$
5. If $h_u$ is equal to the hash of the leaf node then $\mathcal{A}$ has guessed $\text{id}_u$ correctly, otherwise go back to #1
6. $\mathcal{A}$ uses the ID to calculate $w_u$, and then $b_u = \text{KDF}(w_u, S_{\text{com}})$
7. $\mathcal{A}$ guesses $l_u$ and calculates $c_u=g^{l_u}_1 g^{b_u}_2$
8. If $c_u$ is equal to the commitment of the leaf node then $\mathcal{A}$ has guessed $l_u$ correctly, otherwise go back to the previous step

The paper advises to keep $M$ the same across PoLs so that entities only need to request their verification key $w_u = \text{KDF}(M, \text{id}_u)$ from the exchange once, and then reuse it to do verification on all PoLs. Having the same master secret does not pose a security risk for $\mathcal{P}$ because it is only used to generate the verification keys for the entity, and it is passed through a key derivation function for this so that simply having the verification key does not allow one to guess the master secret in reasonable time. In order for this security to hold, however, it is important to have a master secret with high entropy ($>128$ bits, max supported is $256$ bits).

#### Entity mapping $\epsilon$

The user mapping must be known only by $\mathcal{P}$ because exposing this will leak user IDs and where they are mapped to on the tree. The entity map is not required for the DM-SMT accumulator variant since the mapping is deterministically generated from the master secret.

In the code $\epsilon$ is a hashmap from entity ID to x-coordinate on the bottom layer of the tree.

### Tree

The security & privacy proofs in the paper assume the tree is held by $\mathcal{P}$ and so it is recommended that the tree be kept secret and inclusion proofs only given out to authenticated entities.

### Functions

Functions from the paper and their equivalents in the code:

| Function in paper | Description                                            | Equivalents in code                                                                                                                                                                                                              |
|:------------------|:-------------------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Setup             | Produces the PD & SD tuples                            | `DapolTree::new(...) -> DapolTree`<br>`DapolTree::public_root_data(DapolTree) -> (Hash, RistrettoPoint)`<br>`DapolTree::master_secret(DapolTree) -> Secret`<br>`DapolTree::entity_mapping(DapolTree) -> HashMap<EntityId, u64>>` |
| ProveTot          | Reveals the blinding factor and the liability sum      | `DapolTree::secret_root_data(DapolTree) -> (u64, curve25519::Scalar)`                                                                                                                                                            |
| VerifyTot         | Checks that Public Data corresponds to the Secret Data | `DapolTree::verify_root_commitment(RootCommitment, RootBlindingFactor, RootLiability) -> bool`                                                                                                                                                                                              |
| Prove             | Inclusion proof generation for an entity               | `DapolTree::generate_inclusion_proof(DapolTree) -> InclusionProof`                                                                                                                                                                                            |
| Verify            | Verify inclusion proof                                 | `InclusionProof::verify(InclusionProof) -> bool`                                                                                                                                                                                                         |


## Dependencies

The KDF protocol used is [HKDF-SHA256](https://datatracker.ietf.org/doc/html/rfc5869) with [this implementation](https://docs.rs/hkdf/latest/hkdf/). The implementation requires a hash function; [SHA256](https://docs.rs/sha2/latest/sha2/) is used.

[blake3](https://docs.rs/blake3/latest/blake3/) is used as the hash function to construct the Merkle tree.

[`thread_rng` from rand](https://docs.rs/rand/latest/rand/rngs/struct.ThreadRng.html) is used as the CSPRNG for the shuffle algorithm for the NDM-SMT as well as generating random salts if $\mathcal{P}$ does not provide them.

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

### General practices followed

When it comes to error handling this is the convention followed:
- If a bug is found in the code then it will `panic!`. Example of bug detection: there are invariant checks done to make sure that the code is in an expected state; if one of these fails then it is assumed a bug was found.
- Malformed parameters result in an `Err` being returned.
- `Err` values returned from libraries are propagated up as such.

### Node storage

As the tree is being build the nodes are stored in a hash map (specifically the concurrent hashmap: [Dashmap](https://docs.rs/dashmap/latest/dashmap/)). This data structure allows threads to easily just throw nodes into storage without worrying about which index they would live at (which is a rather expensive thing to calculate ahead of time), and offers the best read performance when the tree is to be used post-build for generating inclusion proofs.

The code offers variability in the number of nodes stored. If the height of the tree is large (~32) & the number of users is many (~100M) then the total memory usage is going to be large (~300GB). If less nodes are stored then this value can be lowered. Storing less nodes means that inclusion proofs will take longer to be generated because the nodes not stored will have to be constructed again, but this is this the trade-off.

The problem with node storage is that it is not permanent. If the machine or the process is shut down then the tree data is cleared. After building the tree it needs to be used to generate inclusion proofs on demand, and there cannot be a long wait time for requests. One option is to serialize the tree after building it, and then deserialize it on-demand when an inclusion proof is needed. There is functionality in the code for serde, but for large trees the time to deserialize is longer than the time to build the tree from scratch (due to the sequential nature of the deserialization library), so this is not a realistic option at all. Currently the only viable option is to keep the process running so that the tree lives in memory, ready to receive inclusion proof requests. There are some ways around this:
1. Serialize to a file that allows concurrent read/write. This option would not affect the tree build & inclusion proof generation performance, but this adds overhead it's not clear how fast the (de)serialization process would be.
2. Use a database to store the nodes, whether that be a database on the machine or one in the cloud. This would negatively affect tree build & inclusion performance, but once the database has been created there is no more overhead required so inclusion proofs can be generated on-demand in reasonable time.

### Limits & types

For the tree height $H$:
- Max value: $64$. This was chosen as the max because with the NDM-SMT we can have $2^{36}$ ($~70\text{B}$) entities and still have only $10^{-9}%%$ of the bottom layer spaces filled. With DM SMT we may need to increase this value, which can be easily done.
- Min value: $2$
- Type: `u8` (2^8 = 256 is more than big enough as the maximum possible height)
- Default: $32$

For the max liability $\text{MaxL}$:
- Max value: $2^{64}$. This value was chosen because $64$-bit numbers are the largest natively supported by Rust. This value can be increased if need be.
- Type: `u64`
- Default: $2^{32}$

Master secret $M$:
- Type: `u8` array of length $32$, giving a total of $256$ bits.
- No default supported. This is to ensure that security is determined by $\mathcal{P}$ explicitly.

The salts $S_{\text{hash}}$ & $S_{\text{com}}$:
- Type: `u8` array of length $32$, giving a total of $256$ bits.
- Default: random value chosen uniformly using `thread_rng`.

### Tree coordinates

The paper uses term "idx" but code uses a Cartesian plane coordinate system. Picture a full binary tree with it's bottom layer nodes on the x-axis, the left-most node occupying the origin at coordinate $(0,0)$. The typical image of a binary tree has each of the parent nodes situated vertically above its children, and horizontally halfway between them. The tree in the Cartesian plane is slightly different: each parent node sits vertically 1 unit above its children nodes (similar to the typical image), but horizontally it is situated at the x-coord that is half of its left child's x-coord. This has the visual effect of making the tree look squashed up against the y-axis. We have the following specific coordinates for more information:
- The y-coord for all bottom layer nodes is $0$
- The x-coord for the left-most node on the bottom layer of the tree is $0$
- The x-coord for the right-most node on the bottom layer of the tree is $2^H-1$
- The y-coord for the root node is $H-1$
- The x-coord for the root node is $0$
For trees that are not **full** (i.e. only **complete**) there will be gaps along the horizontal lines where there are no nodes i.e. for each y-coord in the integer range $y_0 \in [0,H-1]$ there will be at least 1 node with coord $(x,y_0)$, but, for some $y_0 \in [0,H-1]$, not every x-coord in the integer range $x_0 \in [0,2^{y_0}]$ will yield a node with coord $(x_0,y_0)$.

