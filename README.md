crypto-cipher suite
===================

Documentation: [crypto-cipher-types on hackage](http://hackage.haskell.org/package/crypto-cipher-types)

Using ciphers
--------------

Here a simple example on how to encrypt using ECB, with the AES256 cipher:

    import Crypto.Cipher.Types
    import Crypto.Cipher

    -- the bytestring need to have a length of 32 bytes
    -- otherwise the simplified error handling will raise an exception.
    initAES256 :: ByteString -> AES256
    initAES256 = either (error . show) cipherInit . makeKey

    -- real code would not create a new context every time, but
    -- initialize once, and reuse the context.
    cryptKey key msg = encryptECB ctx msg
      where ctx = initAES256 key

And another using CBC mode with Blowfish cipher:

    import Crypto.Cipher.Types
    import Crypto.Cipher

    initBlowfish :: ByteString -> Blowfish
    initBlowfish = either (error . show) cipherInit . makeKey

    cryptKey key iv msg = encryptCBC ctx (makeIV iv) msg
      where ctx = initBlowfish key


Phantom types
-------------

[crypto-cipher-types](http://hackage.haskell.org/package/crypto-cipher-types) use
Phantom types for Keys and IVs, which are all the same underlaying types but allow
to differentiate between valid keys of differents ciphers.

For example a "Key Blowfish" is different than a "Key AES256". This is similar for IV.

One must use makeIV and makeKey to create those types.

    makeKey "\x00\x11\x22\x33\x44\x55\x66" :: Either KeyError (Key MyCipher)

and:

    makeIV "\x00\x11\x22\x33\x44" :: Maybe (IV MyCipher)

In simple context, the haskell compiler cannot infer the cipher that need to be
use, and the user need to add annotation in signatures as to which cipher need
to be chosen.

This only need to be done, either on the initialized Cipher (cipherInit),
the Key or the IV.

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
* cipher-camellia: slow, endianness problem
