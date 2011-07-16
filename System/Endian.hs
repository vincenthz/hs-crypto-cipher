{-# LANGUAGE CPP #-}
module System.Endian (littleEndian) where


#ifdef BIG_ENDIAN
littleEndian :: Bool
littleEndian = False
#elif defined(LITTLE_ENDIAN)
littleEndian :: Bool
littleEndian = True
#else

import System.Info (arch)

littleEndian :: Bool
littleEndian = arch /= "sparc" && arch /= "ppc"
#endif
