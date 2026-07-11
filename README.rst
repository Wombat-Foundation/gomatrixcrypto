gomatrixlib
==========

Small Go library for Matrix-adjacent cryptographic primitives.

This repository currently provides:

* ``lthash``: LtHash16-style homomorphic state hashing for Matrix state sets
* ``fndsa512``: a thin Go wrapper for Falcon ``fn-dsa-512``
* ``keyid``: canonical ``fn-dsa-512`` key-ID fingerprint and short-ID helper
* ``cuckoo``: Cuckoo Cycle proof generation and verification helpers

Status
------

This is early library code, not a finished application or protocol implementation.

The ``fn-dsa-512`` package currently wraps ``github.com/pornin/go-fn-dsa``.
That upstream implementation explicitly tracks a pre-final FN-DSA standard, so
wire compatibility may need adjustment when NIST finalizes the specification.

Requirements
------------

* Go 1.25+

Project Layout
--------------

* ``lthash/``: incremental lattice hash and ``BLAKE`` checksum
* ``fndsa512/``: key generation, signing, and verification helpers
* ``keyid/``: key-ID digest and *quasi-unique* short-ID derivation
* ``cuckoo/``: PoW edge derivation, proof verification, and bounded proof search
* ``extlib/``: reference notes and external material used during implementation

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

Testing
-------

Run the full test suite with:

.. code-block:: bash

   make test

Run the main verification path with:

.. code-block:: bash

   make check
