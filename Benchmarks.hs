import Criterion
import Criterion.Environment
import Criterion.Config
import Criterion.Monad
import Criterion.Analysis
import Criterion.Measurement

import Text.Printf

import Control.Monad.Trans

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

import qualified Crypto.Cipher.AES as AES
import qualified Crypto.Cipher.RC4 as RC4
import qualified Crypto.Cipher.Camellia as Camellia

(Right key128) = AES.initKey128 $ B.replicate 16 0
aesEncrypt128 = AES.encrypt key128
aesEncrypt128CBC = AES.encryptCBC key128 (B.replicate 16 0)
(Right key192) = AES.initKey192 $ B.replicate 24 0
aesEncrypt192 = AES.encrypt key192
aesEncrypt192CBC = AES.encryptCBC key192 (B.replicate 16 0)
(Right key256) = AES.initKey256 $ B.replicate 32 0
aesEncrypt256 = AES.encrypt key256
aesEncrypt256CBC = AES.encryptCBC key256 (B.replicate 16 0)

(Right camelliaKey128) = Camellia.initKey128 $ B.replicate 16 0
camelliaEncrypt128 = Camellia.encrypt camelliaKey128

rc4Key = RC4.initCtx $ replicate 16 0
rc4Encrypt = snd . RC4.encrypt rc4Key 

b16 f   = whnf f $ B.replicate 16 0
b32 f   = whnf f $ B.replicate 32 0
b128 f  = whnf f $ B.replicate 128 0
b512 f  = whnf f $ B.replicate 512 0
b1024 f = whnf f $ B.replicate 1024 0
b4096 f = whnf f $ B.replicate 4096 0

doCipher env f = do
	mean16   <- runBenchmark env (b16 f)   >>= \sample -> analyseMean sample 100
	mean32   <- runBenchmark env (b32 f)   >>= \sample -> analyseMean sample 100
	mean128  <- runBenchmark env (b128 f)  >>= \sample -> analyseMean sample 100
	mean512  <- runBenchmark env (b512 f)  >>= \sample -> analyseMean sample 100
	mean1024 <- runBenchmark env (b1024 f) >>= \sample -> analyseMean sample 100
	mean4096 <- runBenchmark env (b4096 f) >>= \sample -> analyseMean sample 100
	return (mean16, mean32, mean128, mean512, mean1024, mean4096)

norm :: Int -> Double -> Double
norm n time
	| n < 1024  = 1.0 / (time * (1024 / fromIntegral n))
	| n == 1024 = 1.0 / time
	| n > 1024  = 1.0 / (time / (fromIntegral n / 1024))

pn :: Int -> Double -> String
pn n time = printf "%.1f K/s" (norm n time)

doOne env (cipherName, f) = do
	(mean16, mean32, mean128, mean512, mean1024, mean4096) <- doCipher env f
	let s = printf "%12s: %12s %12s %12s %12s %12s %12s\n                %12s %12s %12s %12s %12s %12s"
	               cipherName
	               (secs mean16) (secs mean32) (secs mean128)
	               (secs mean512) (secs mean1024) (secs mean4096)
	               (pn 16 mean16) (pn 32 mean32) (pn 128 mean128)
	               (pn 512 mean512) (pn 1024 mean1024) (pn 4096 mean4096)
	return s

main = withConfig defaultConfig $ do
	env <- measureEnvironment
	l   <- mapM (doOne env)
		[ ("RC4"        , rc4Encrypt)
		, ("Camellia128", camelliaEncrypt128)
		, ("AES128"     , aesEncrypt128)
		, ("AES128-CBC" , aesEncrypt128CBC)
		, ("AES192"     , aesEncrypt192)
		, ("AES192-CBC" , aesEncrypt192CBC)
		, ("AES256"     , aesEncrypt256)
		, ("AES256-CBC" , aesEncrypt256CBC)
		]
	liftIO $ printf "%12s| %12s %12s %12s %12s %12s %12s\n"
	                "cipher" "16 bytes" "32 bytes" "64 bytes" "512 bytes" "1024 bytes" "4096 bytes"
	liftIO $ printf "=============================================================================================\n"
	mapM_ (liftIO . putStrLn) l
