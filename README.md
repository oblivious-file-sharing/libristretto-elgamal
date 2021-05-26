# The ElGamal Encryption Library from Ristretto
This library implements ElGamal encryption in the [Ristretto](https://ristretto.group/) group with the following properties:
 - constant-time message encoding and decoding
 - ciphertext compaction
 - point sanitization
 - eager fixed-base precomputation

This library is based on `Ristretto/libristretto255`: https://github.com/Ristretto/libristretto255. The original repository's and this repository's [AUTHORS.md](https://github.com/oblivious-app/libristretto-elgamal/blob/master/AUTHORS.md) list its contributors and its commit history. Our library is also under the MIT license.

This library is a research prototype; that is, the implementation may have a few bugs. Thus, it is not recommended to use this project for production. If you spot a bug, please let us know. In addition, we welcome you to contribute to the source code.

If you want a quick tutorial of how to use the library, this is a good start:
[src/file_test.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/file_test.c)

## Requirements

OpenSSL library. You can install it in Ubuntu by entering `sudo apt-get install libssl-dev`.

## Constant-time message encoding and decoding

This library provides a secure and constant-time solution to encode binary strings into points.

### ◆ Problem and prior work ###
This task is challenging. Previously, we know a folklore approach based on random search. This approach searches legit points that embed the string and has been used in [`dedis/kyper`](https://github.com/dedis/kyber/) and other popular libraries.

However, this approach is not constant-time because of random searching. Padding the search is insufficient because the searching algorithm terminates in *expected* polynomial time, and therefore, a small bound cannot guarantee that each message will be successfully mapped. It helps to make a large bound, but the overall time will be unpleasantly long.

### ◆ Our solution ###

Our solution is to get rid of random searching and base on deterministic methods. We build inversible encoding using the elligator in Ristretto, which maps strings to points. The challenge is that the Ristretto elligator does not provide one-one mapping. In fact, the Ristretto elligator maps eight strings to the same point. The inverse mapping, therefore, has eight candidate preimages, which makes decoding difficult.

We identify two methods to distinguish the original message among these eight preimages. We call them Embed-direct and Embed-aux, respectively, as follows.

- **Embed-direct.** Instead of encoding the message directly, we encode the message concatenated with its hash value. Here, the hash function is collision-resistant (like, the first 80 bits of SHA-256 in the random oracle model). This preprocessing allows us to identify the original message among the eight preimages, having a computational guarantee from the collision resistance. The space utilization of this approach is about 68%.

- **Embed-aux.** Another solution is to externally store auxiliary information about which one out of the eight preimages the original message is, where the auxiliary information for a single message will be of three bits. The problem with this solution is that we cannot construct rerandomizable encryption directly because the auxiliary information is now homeless. However, if the auxiliary information is stored, the space utilization can reach 98%.

Our solution is to combine Embed-direct and Embed-aux. We encode 58 original messages into 58 points in Embed-aux and then encode the auxiliary information of these 58 points into one point in Embed-direct. The resultant sequence of 59 points now can be uniquely decoded and does not require auxiliary information to be stored elsewhere.

### ◆ Related files ###

Embed-direct's code is in these files:

- [src/encode_single_message_hintless_hashonly.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/encode_single_message_hintless_hashonly.c)
- [src/decode_single_message_hintless_hashonly.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/decode_single_message_hintless_hashonly.c)
- [src/hintless_test.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/hintless_test.c)

Embed-aux's code is in these two files:

- [src/encode_single_message.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/encode_single_message.c)
- [src/decode_single_message.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/decode_single_message.c)

The combination of Embed-direct and Embed-aux is here:

- [src/encode_file.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/encode_file.c)
- [src/decode_file.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/decode_file.c)
- [src/file_test.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/file_test.c)

## Ciphertext compaction

The library adopts Kaoru Kurosawa's multi-recipient public-key encryption with shortened ciphertext to construct a compact encryption scheme with small ciphertext expansion.

### ◆ Problem ###

Recall that ElGamal encryption's ciphertext consists of two group elements. Concretely, one is `M + rQ` where Q is the public key, and another one is `rG` where G is the base point. That is, the ciphertext expansion is at least 2x.

This library provides a compact way to encrypt long messages with ~1x expansion, which we now describe.

### ◆ Background: Kurosawa encryption ###

We first revisit Kurosawa encryption, which is designed for the multi-recipient setting, as follows.

Consider that a sender wants to send `M_1`, `M_2`, ..., `M_n` to receivers `U_1`, `U_2`, ..., `U_n`, respectively, where `Q_1`, `Q_2`, ..., `Q_n` are the receivers' public keys, respectively. The sender can generate one big ciphertext:

    M_1 + rQ_1, M_2 + rQ_2, ..., M_n + rQ_n, rG

Each receive can only obtain the message that the receiver has the private key to, although the randomness r is reused among all the n encryption operations above.

### ◆ Our solution ###

We can adopt Kurosawa encryption to construct a compact encryption for long messages. In our solution, the public key is no longer one point Q, but a sequence of points `Q_1`, `Q_2`, ..., `Q_n`, sampled independently; the private key is also now a sequence of scalar values.

Now, suppose that we have a long message, the encoding of which comprises n points. We can sample one random value r and encrypt the message in the Kurosawa's manner, as if each point of the public key is for an independent receiver.

The resultant encryption scheme has `1 + 1/n` ciphertext expansion, a roughly reduction by half. By setting `n = 59`, we have a ciphertext of 60 points, not 118 points in the traditional ElGamal encryption.

### ◆ Security proof ###

Our solution is a direct result of Kurosawa encryption, so the security proof of Kurosawa encryption applies to our method.

In addition, Bellare, Boldyreva, and Staddon have a generalized analysis of randomness re-use. ElGamal encryption, which Kurosawa encryption is constructed from, is one of the encryption schemes that remain secure in the randomness re-using setting.

We still provide a game-based security proof for reference, which is available here: [link](https://github.com/oblivious-file-sharing/compact_elgamal_security_proof).

The security proof invokes the hybrid arguments and shows that if an attacker can break the security of our solution, the attacker also has the ability to win the decisional Diffie-Hellman game, a contradiction.

### ◆ Related files ###

This library implements the compact encryption and decryption algorithm in these files:

- [src/elgamal.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/elgamal.c)
- [src/elgamal_gen.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/elgamal_gen.c)
- [src/elgamal_test.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/elgamal_test.c)

## Point sanitization

This library provides two point sanitization algorithms for serialization. The first one, batched normalization of extended coordinates using Montgomery's trick, is for a semi-honest serializer. The second one directly uses Ristretto's encoding algorithm, which is for an untrusted serializer.

### ◆ Problem ###

To compute on elliptic curves efficiently, we often represent a point in extended coordinates. That is, each point (x, y) is now represented as (X, Y, Z, T) where `X=Zx`, `Y=Zy`, and `T=Zxy`; `Z` is a free value. However, extended coordinates can reveal -- from Z -- some information about what computation has been done so far. This leakage has been analyzed by David Naccache, Nigel P. Smart, and Jacques Stern in 2004.

We also want to ensure that our deserialization algorithm outputs a point that is indeed in the Ristretto group.

### ◆ Method I: Batched normalization of extended coordinates ###

If we assume that the serializer is semi-honest, we don't need to worry that the deserialization results in out-of-scope points, and therefore we can have a simple algorithm: converting (X, Y, Z, T) back to (x, y), the main step of which is to compute the inverse of Z.

The challenge is that inversion is slow, much slower than multiplication. But, inversions can be batched efficiently using Peter L. Montgomery's trick, and therefore it enables us to compute inverse of Z of many points efficiently.

This batched normalization clears out the leakage and uses two scalar values per point.

### ◆ Method II: Ristretto's point encoding algorithm ###

If the serializer could be malicious, i.e., encoding invalid points, we as the deserializer need to check whether the deserialization results are in the Ristretto group. Ristretto's point encoding algorithm (not our constant-time message encoding) is the solution that offers such guarantee.

In Ristretto's point encoding algorithm, a point (X, Y, Z, T) is converted into one scalar value `s`. The decoding algorithm can convert `s` back to a point (X, Y, Z, T). This solution not only clears out the leakage, but also requires only one scalar value to store a point.

Compared with other candidates like storing (x, sgn y), Ristretto's point encoding algorithm does not require additional point membership checks. Mike Hamburg's paper provides a detailed comparison, which shows that Ristretto's point encoding algorithm is a top choice.

The shortcoming is that Ristretto's point encoding uses inverse square root, which is not batchable. As a result, if we know the serializer is semi-honest, we will incline to Method I if the increased network cost is worthwhile.

### ◆ Related files ###

The two methods are implemented in [src/elgamal.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/elgamal.c).

- Method I: `Serialize_Honest_Size / Serialize_Honest / Deserialize_Honest`.
- Method II: `Serialize_Malicious_Size / Serialize_Malicious / Deserialize_Malicious`.

## Eager fixed-base precomputation

This library strives to speed up fixed-base scalar-point multiplication, used frequently in ElGamal, by using a large look-up tables.

### ◆ Problem ###

ElGamal encryption frequently does fixed-base scalar-point multiplication. For example, to generate a ciphertext for message `M`, the encryption algorithm samples a random scalar `r`, computes `r Q` where `Q` is the public key, and computes `r G` where `G` is the base point.

We can precompute the values used in the double-and-add, but such an idea is merely the beginning.

### ◆ Our approach ###

There have been many prior works in this direction. We use their techniques, but practice in an eagerer way, as follows. We split the binary representation of the scalar value (~256 bits) into 16 segments, each of which is in charge of 16 bits. For each segment, we precompute 2^16 points that represent different values for this segment on a specific base (i.e., `Q` or `G`). Then, a scalar-point multiplication becomes 15 point additions, much faster.

The fast speed comes at a cost of memory consumption. Each look-up table, for a specific base, takes ~250MB.

In addition, after each access to the look-up table, the program flushes the cache (at a noticeable overhead) to avoid timing leakage due to cache.

### ◆ Related files ###

The following file provides a few functions to operate the lookup table. Ideally, one should store the lookup table locally on the disk and load the table when necessary.

- [src/fastexp.c](https://github.com/oblivious-app/libristretto-elgamal/blob/master/src/fastexp.c)

The `ADJUST_WINDOW` refers to the size of a segment (not the number of segments).

The test file assumes that the tables have been generated in `/table/`. It is recommended to use even a small lookup table for a device with small storage because a small table can already speed up a lot.

## Frequently asked questions ##

**Q:** The key generation fails during the creation of the precomputation tables. Any idea?

**A:** The precomputation tables -- by default -- are stored in `/table`. It may require a pretty large space (~45GiB). If your disk space is insufficient, you may want to mount another storage device to `/table`. A common approach for users in AWS is to dedicate a large EBS volume for the tables.

**Q:** The creation of dummy ciphertexts fails for the case for 1MB file due to segment fault. Any idea?

**A:** The current creation requires a larger stack size, which can be turned on by entering `ulimit -S -s 131072` in the current terminal's session.

## Regulatory issue

This repository is not subject to the U.S. Export Administration Regulation (EAR) because it is publicly available; notifications to U.S. Bureau of Industry and Security (BIS) and National Security Agency (NSA) have been sent. 

For more information about this regulatory issue, see [this post](https://www.eff.org/deeplinks/2019/08/us-export-controls-and-published-encryption-source-code-explained) by Electronic Frontier Foundation (EFF).

## References

[deR94]: Peter de Rooij, "Efficient exponentiation using precomputation and vector addition chains," in EUROCRYPT'94.

[BBS03]: Mihir Bellare, Alexandra Boldyreva, and Jessica Staddon, "Randomness re-use in multi-recipient encryption schemeas", in PKC'03.

[Ber06]: Daniel J. Bernstein, "Curve25519: New Diffie-Hellman speed records," in PKC'06.

[BHKL13]: Daniel J. Bernstein, Mike Hamburg, Anna Krasnova, and Tanja Lange, "Elligator: Elliptic-curve points indistinguishable from uniform random strings," in CCS'13.

[Bon98]: Dan Boneh, "The decision Diffie-Hellman problem," in ANTS'98.

[BGMW92]: Ernest F. Brickell, Daniel M. Gordon, Kevin S. McCurley, and David B. Wilson, "Fast exponentiation with precomputation," in EUROCRYPT'92.

[FJT13]: Pierre-Alain Fouque, Antoine Joux, and Mehdi Tibouchi. "Injective encodings to
elliptic curves," in ACISP'13.

[Ham15]: Mike Hamburg, "Decaf: Eliminating cofactors through point compression," in CRYPTO'15.

[Kur02]: Kaoru Kurosawa, "Multi-recipient public-key encryption with shortened ciphertext," in PKC'02.

[LL94]: Chae Hoon Lim and Pil Joong Lee, "More flexible exponentiation with precomputation," in CRYPTO'94.

[Mon87]: Peter L. Montgomery, "Speeding the Pollard and Elliptic Curve Methods of Factorization," in Mathematics of Computation'87.

[NSS04]: David Naccache, Nigel P. Smart, and Jacques Stern, "Projective Coordinates Leak", in EUROCRYPT'04.
