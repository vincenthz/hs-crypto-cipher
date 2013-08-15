import Crypto.Cipher.Benchmarks
import Crypto.Cipher.DES (DES)
import Crypto.Cipher.TripleDES

main = defaultMain
    [GBlockCipher (undefined :: DES)
    ,GBlockCipher (undefined :: DES_EEE3)
    ,GBlockCipher (undefined :: DES_EDE3)
    ,GBlockCipher (undefined :: DES_EEE2)
    ,GBlockCipher (undefined :: DES_EDE2)
    ]
