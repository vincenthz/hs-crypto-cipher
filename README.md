crypto-cipher
=============

Documentation: [crypto-cipher-types on hackage](http://hackage.haskell.org/package/crypto-cipher-types)


Writing tests
-------------

Tests for blockciphers are already all included in crypto-cipher-tests.

    import Crypto.Cipher.Tests
    main = defaultMain
        [ testBlockCipher defaultKATs (undefined :: BlockCipherType)
        ]


TODO
----

* cipher-des: slow
* cipher-blowfish: slow
