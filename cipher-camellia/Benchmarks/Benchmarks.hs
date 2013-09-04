import Crypto.Cipher.Benchmarks
import Crypto.Cipher.Camellia

main = defaultMain
    [GBlockCipher (undefined :: Camellia128)
    ]
