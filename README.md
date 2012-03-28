# Zhang-Kim ID-based blind signature scheme

This is an implementation of the signature scheme described in the paper
"Efficient ID-Based Blind Signature and Proxy Signature from Bilinear Pairings",
by Zhang and Kim.

As suggested by the title, this signature scheme is implemented using a bilinear
pairing over an elliptic curve group. The PBC library (http://crypto.stanford.edu/pbc/)
is used for this purpose, and any pairing that is supported by this library can be used.
The GNU MP library is also necessary, since it is used by PBC.

## ID-based signature

An ID-based signature consists of four procedures:
1. *KeyGen*: creates a master key and master public key.
2. *Extract*: creates a private key given the master (private) key and a string identifier ID.
3. *Sign*: signs a string using a private key for a particular ID.
4. *Verify*: verifies a signature on a string using the master public key and the string identifier ID.

The entity having the master public key is often referred to as the Key Generation Centre (KGC).
One might suppose that this primitive is used to issue keys to people by a string identifier (such
as their name).

## Blind signature

A blind signature scheme consists of three procedures:
1. *KeyGen*: creates a private key and public key.
2. *Sign*: A protocol undertaken between someone possessing a piece of information to be signed and
   someone possessing the private key to sign it. The former obtains exactly one signature from the
   protocol, and the signer does not learn anything about the information which is signed, nor can
   they later link the signature to their interaction.

## ID-based blind signature

An ID-based blind signature is just an ID-based signature in which the *Sign* procedure is
replaced by a blind signature protocol.
