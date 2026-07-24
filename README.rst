gomatrixcrypto
==============

Small Go library for Matrix-adjacent cryptographic primitives.

.. Substitutions for Badges

.. |coverage| image:: https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FWombat-Foundation%2Fgomatrixcrypto%2F_metadata%2Fbadges%2Fcoverage-main.json
   :target: https://github.com/Wombat-Foundation/gomatrixcrypto/actions/workflows/test.yml?query=branch%3Amain
   :alt: Coverage

.. |tests| image:: https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2FWombat-Foundation%2Fgomatrixcrypto%2F_metadata%2Fbadges%2Ftests-main.json
   :target: https://github.com/Wombat-Foundation/gomatrixcrypto/actions/workflows/test.yml?query=branch%3Amain
   :alt: Tests (pass/skip/fail)

|coverage| |tests|

This repository currently provides:

* ``lthash``: LtHash16-style homomorphic state hashing for Matrix state sets
* ``fndsa512``: a thin Go wrapper for Falcon ``fn-dsa-512``
* ``keyid``: canonical ``fn-dsa-512`` key-ID fingerprint and short-ID helper
* ``matrixjson``: Matrix Canonical JSON encoding for signed objects
* ``merkle``: MSC4511 SHA3-256 root derivation and event ID primitives
* ``serverkey``: FN-DSA server-key object construction and self-signing
* ``cuckoo``: Cuckoo Cycle proof generation and verification helpers
* ``cmd/merkle-vectors``: draft MSC4511 Merkle metadata vector generator
* ``cmd/cuckoo-scan``: helper command that scans graph nonces until the
  reference mean-miner finds a proof

Status
------

Early library code, not a finished application or protocol implementation.

The ``fn-dsa-512`` package currently wraps ``github.com/pornin/go-fn-dsa``.
That upstream implementation explicitly tracks a pre-final FN-DSA standard, so
wire compatibility may need adjustment when NIST finalizes the specification.

Requirements
------------

* Go 1.25+

Project Layout
--------------

* ``lthash/``: reference lattice hash and ``BLAKE`` checksum
* ``fndsa512/``: key gen, signing, and verification helpers
* ``keyid/``: key-ID digest and *pseudo-unique* short-ID derivation
* ``matrixjson/``: canonical JSON encoder
* ``merkle/``: draft MSC4511 field roots, event roots, and event ID helpers
* ``serverkey/``: FN-DSA helpers for ``/_matrix/key/v2/server``
* ``cuckoo/``: PoW edge miner and proof verification
* ``res/``: reference notes and external materials

Package Overview
----------------

LtHash
~~~~~~

The ``lthash`` package implements a 2048-byte lattice state hash. Each state
entry is expanded with ``SHAKE256`` and accumulated with wrapping ``uint16``
addition, so inserts and removals are incremental and order-independent.

Example:

.. code-block:: go

   var h lthash.Hash
   h.Insert("m.room.create", "", "$event0:example.org")
   h.Insert("m.room.member", "@alice:example.org", "$event1:example.org")
   checksum := h.Checksum()

FN-DSA-512
~~~~~~~~~~

The ``fndsa512`` package exposes a narrow API over the underlying Falcon
implementation for:

* key generation
* raw-message signing and verification
* prehashed signing and verification

Example:

.. code-block:: go

   priv, pub, err := fndsa512.GenerateKey(nil)
   if err != nil {
       panic(err)
   }

   msg := []byte("matrix canonical json payload")
   sig, err := fndsa512.Sign(nil, priv, msg)
   if err != nil {
       panic(err)
   }

   ok := fndsa512.Verify(pub, msg, sig)

Server Keys
~~~~~~~~~~~

The ``serverkey`` package builds and self-signs an FN-DSA Matrix server-key
object. The signature covers the Matrix Canonical JSON form of the object after
removing ``signatures`` and ``unsigned``.

Example:

.. code-block:: go

   priv, pub, err := fndsa512.GenerateKey(nil)
   if err != nil {
       panic(err)
   }

   // In production this proof is found by iterating the minting nonce until the
   // SHA3-256-derived graph seed has a valid Cuckoo Cycle solution. The final
   // key_id is derived from that graph seed and the sorted proof solution.
   proof := serverkey.FNDSAMintingProof{
       Algorithm: serverkey.ProductionPoW,
       Nonce:     8137226,
       Solution:  []uint32{ /* 42 sorted edge nonces */ },
   }

   obj, keyName, err := serverkey.NewSignedFNDSA(
       nil,
       "example.com",
       priv,
       pub,
       1798848000000,
       serverkey.FNDSAMetadata{
           FIPS206Revision: serverkey.DefaultFIPSRevision,
           Claims: []string{
               "constant-time-keygen",
               "constant-time-signing",
           },
       },
       proof,
   )
   if err != nil {
       panic(err)
   }

   verifiedKeyName, err := serverkey.VerifyFNDSASelfSignature(obj, "example.com")
   if err != nil || verifiedKeyName != keyName {
       panic("invalid self-signature")
   }

Demo command, including a low-difficulty Cuckoo proof embedded in the generated
FN-DSA verify key object:

.. code-block:: bash

   go run ./cmd/serverkey-demo -server example.com -valid-days 7

To encrypt the generated private key before it is printed, provide the
passphrase through an environment variable or a file:

.. code-block:: bash

   SERVERKEY_PASSPHRASE='replace with a secret phrase' go run ./cmd/serverkey-demo -server example.com -private-key-passphrase-env SERVERKEY_PASSPHRASE

Existing plaintext private-key exports can be encrypted, and encrypted exports
can be re-wrapped with a new passphrase:

.. code-block:: bash

   SERVERKEY_PASSPHRASE='replace with a secret phrase' go run ./cmd/serverkey-keytool -mode encrypt -in private-key.b64 -passphrase-env SERVERKEY_PASSPHRASE

   OLD_SERVERKEY_PASSPHRASE='old secret phrase' NEW_SERVERKEY_PASSPHRASE='new secret phrase' go run ./cmd/serverkey-keytool -mode reencrypt -in encrypted-private-key.json -old-passphrase-env OLD_SERVERKEY_PASSPHRASE -new-passphrase-env NEW_SERVERKEY_PASSPHRASE

Empty passphrases are rejected. Removing encryption from an encrypted private
key is intentionally not provided by this tool.

The demo uses ``-pow-edge-bits 8 -pow-proof-size 4`` and searches ``1<<12``
edge nonces per minting nonce by default, so it is intentionally easy: it looks
for a 4-cycle in a tiny graph. The live production profile described in
``res/`` is ``42-29`` with a SHA3-256 co-generation seed and is intentionally
much more expensive.

PoW profile examples:

.. code-block:: bash

   # Default fast demo profile.
   go run ./cmd/serverkey-demo -server example.com

   # Custom profile and algorithm label.
   go run ./cmd/serverkey-demo -pow-profile custom -pow-algorithm local.cuckoo-cycle-6-12-sha3-256-cogen -pow-edge-bits 12 -pow-proof-size 6 -pow-max-nonce 65536

   # Production-style nutra.tk bundle using the reference mean-miner.
   (cd cuckoo/meanminer/csrc && make)
   go run ./cmd/serverkey-demo -server nutra.tk -valid-days 365 -pow-profile production -pow-max-graph-nonce 1024

   # Production parameter labels. This is expected to be expensive with the Go helper.
   go run ./cmd/serverkey-demo -pow-profile production -pow-max-nonce 536870912 -pow-max-graph-nonce 1024

MSC4511 Merkle Vectors
~~~~~~~~~~~~~~~~~~~~~~

Draft MSC4511 Merkleized metadata vectors can be regenerated with:

.. code-block:: bash

   go run ./cmd/merkle-vectors

These are implementation regression vectors, not official Matrix specification
vectors.

Cuckoo Cycle
~~~~~~~~~~~~

The ``cuckoo`` package provides deterministic edge derivation from a seed,
proof verification, and a bounded search helper suitable for tests or
low-difficulty experiments.

Example:

.. code-block:: go

   cfg := cuckoo.Config{EdgeBits: 8, ProofSize: 4}
   seed := []byte("example-seed")
   proof, err := cuckoo.FindProof(cfg, seed, 1<<12)
   if err != nil {
       panic(err)
   }

   err = cuckoo.Verify(cfg, seed, proof)

Reference mean-miner scan helper:

.. code-block:: bash

   # Build the reference solver first.
   (cd cuckoo/meanminer/csrc && make)

   # Scan graph nonces until the first solvable graph is found.
   go run ./cmd/cuckoo-scan -prefix manual-test -start 0 -limit 200 -threads 6

The helper hashes ``<prefix> + little-endian uint64(graph_nonce)`` with
``SHA-256`` to derive the 32-byte graph seed for each attempt. It is useful
when you want to reproduce the shell loop used during solver testing without
retyping the loop each time.

Testing
-------

Run the full test suite with:

.. code-block:: bash

   make test

Run the main verification path with:

.. code-block:: bash

   make format lint cov
