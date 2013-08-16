import Crypto.Cipher.Benchmarks
import Crypto.Cipher.Blowfish

main = defaultMain
    [ GBlockCipher (undefined :: Blowfish128)
    ]
