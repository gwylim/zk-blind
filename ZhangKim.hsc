{-# LANGUAGE CPP, ForeignFunctionInterface #-}
module ZhangKim (
  ZkParam,
  ZkMaster,
  ZkPrivate,
  genKeyPair,
  extractKey,
  signInit,
  blind,
  sign,
  unblind,
  verify
  ) where

#include <pbc/pbc.h>
#include "zk.h"

import Foreign.C
import Foreign.Ptr
import Foreign.ForeignPtr
import Foreign.Marshal.Alloc
import Data.ByteString
import Data.Word
import System.IO.Unsafe
import Data.Serialize

newtype ZkParam = ZkParam (ForeignPtr ZkParam)
newtype ZkMaster = ZkMaster (ForeignPtr ZkMaster)
newtype ZkPrivate = ZkPrivate (ForeignPtr ZkPrivate)
newtype Pairing = Pairing (ForeignPtr Pairing)

foreign import ccall "&pairing_clear" pairing_clear :: FunPtr (Ptr Pairing -> IO ())

foreign import ccall pairing_init_set_str :: Ptr Pairing -> CString -> IO ()
pairingFromString :: String -> Pairing
pairingFromString s = unsafePerformIO $ withCString s $ \s -> do
  pairing <- mallocForeignPtrBytes #size pairing_t
  withForeignPtr pairing $ \pairingPtr -> do
  pairing_init_set_str pairingPtr s
  addForeignPtrFinalizer pairing_clear pairing
  return (Pairing pairing)

pairing = pairingFromString "type d\nq 2094476214847295281570670320144695883131009753607350517892357\nn 2094476214847295281570670320143248652598286201895740019876423\nh 1122591\nr 1865751832009427548920907365321162072917283500309320153\na 9937051644888803031325524114144300859517912378923477935510\nb 6624701096592535354217016076096200573011941585948985290340\nk 6\nnk 84421409121513221644716967251498543569964760150943970280296295496165154657097987617093928595467244393873913569302597521196137376192587250931727762632568620562823714441576400096248911214941742242106512149305076320555351603145285797909942596124862593877499051211952936404822228308154770272833273836975042632765377879565229109013234552083886934379264203243445590336\nhk 24251848326363771171270027814768648115136299306034875585195931346818912374815385257266068811350396365799298585287746735681314613260560203359251331805443378322987677594618057568388400134442772232086258797844238238645130212769322779762522643806720212266304\ncoeff0 362345194706722765382504711221797122584657971082977778415831\ncoeff1 856577648996637037517940613304411075703495574379408261091623\ncoeff2 372728063705230489408480761157081724912117414311754674153886\nnqr 279252656555925299126768437760706333663688384547737180929542\n"
(Pairing pairingPtr) = pairing

-- Length functions

foreign import ccall zk_param_length_in_bytes :: Ptr Pairing -> IO CInt
paramLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_param_length_in_bytes

foreign import ccall zk_master_length_in_bytes :: Ptr Pairing -> IO CInt
masterLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_master_length_in_bytes

foreign import ccall zk_private_length_in_bytes :: Ptr Pairing -> IO CInt
privateLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_private_length_in_bytes

foreign import ccall zk_sign_init_length_in_bytes :: Ptr Pairing -> IO CInt
signInitLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_sign_init_length_in_bytes

foreign import ccall zk_sign_init_factor_length_in_bytes :: Ptr Pairing -> IO CInt
signInitFactorLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_sign_init_factor_length_in_bytes

foreign import ccall zk_blinded_length_in_bytes :: Ptr Pairing -> IO CInt
blindedLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_blinded_length_in_bytes

foreign import ccall zk_blinding_factor_length_in_bytes :: Ptr Pairing -> IO CInt
blindingFactorLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_blinding_factor_length_in_bytes

foreign import ccall zk_blinded_signature_length_in_bytes :: Ptr Pairing -> IO CInt
blindedSignatureLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_blinded_signature_length_in_bytes

foreign import ccall zk_signature_length_in_bytes :: Ptr Pairing -> IO CInt
signatureLength = fromEnum $ unsafePerformIO $ withForeignPtr pairingPtr zk_signature_length_in_bytes

foreign import ccall zk_param_to_bytes :: Ptr CChar -> Ptr ZkParam -> IO ()
foreign import ccall zk_param_from_bytes :: Ptr ZkParam -> Ptr CChar -> IO ()
foreign import ccall "&zk_param_clear" zk_param_clear :: FunPtr (Ptr ZkParam -> IO ())
foreign import ccall zk_param_from_master :: Ptr ZkParam -> Ptr ZkMaster -> IO ()

instance Serialize ZkParam where
  put (ZkParam ptr) =
    let bytes = unsafePerformIO $
          withForeignPtr ptr $ \p -> do
          allocaBytes paramLength $ \bytes -> do
          zk_param_to_bytes bytes p
          packCStringLen (bytes, paramLength)
    in  putByteString bytes
  get =
    do bytes <- getByteString paramLength
       return $ unsafePerformIO $ useAsCString bytes $ \encoded -> do
         param <- mallocForeignPtrBytes #size zk_param_t
         withForeignPtr param $ \paramPtr -> do
         zk_param_from_bytes paramPtr encoded
         addForeignPtrFinalizer zk_param_clear param
         return (ZkParam param)

foreign import ccall zk_gen :: Ptr ZkMaster -> Ptr Pairing -> IO ()
genKeyPair :: IO (ZkParam, ZkMaster)
genKeyPair =
  let (Pairing ptr) = pairing
  in  withForeignPtr ptr $ \pairing -> do
      master <- mallocForeignPtrBytes #size zk_master_t
      withForeignPtr master $ \masterPtr -> do
      zk_gen masterPtr pairing
      param <- mallocForeignPtrBytes #size zk_param_t
      withForeignPtr param $ \paramPtr -> do
      zk_param_from_master paramPtr masterPtr
      addForeignPtrFinalizer zk_param_clear param
      addForeignPtrFinalizer zk_master_clear master
      return (ZkParam param, ZkMaster master)

foreign import ccall zk_master_to_bytes :: Ptr CChar -> Ptr ZkMaster -> IO ()
foreign import ccall zk_master_from_bytes :: Ptr ZkMaster -> Ptr CChar -> IO ()
foreign import ccall "&zk_master_clear" zk_master_clear :: FunPtr (Ptr ZkMaster -> IO ())

instance Serialize ZkMaster where
  put (ZkMaster ptr) =
    let bytes = unsafePerformIO $
          withForeignPtr ptr $ \p -> do
          allocaBytes masterLength $ \bytes -> do
          zk_master_to_bytes bytes p
          packCStringLen (bytes, masterLength)
    in  putByteString bytes
  get =
    do bytes <- getByteString masterLength
       return $ unsafePerformIO $ useAsCStringLen bytes $ \(encoded, _) -> do
         master <- mallocForeignPtrBytes #size zk_master_t
         withForeignPtr master $ \masterPtr -> do
         zk_master_from_bytes masterPtr encoded
         addForeignPtrFinalizer zk_master_clear master
         return (ZkMaster master)

foreign import ccall zk_private_to_bytes :: Ptr CChar -> Ptr ZkPrivate -> IO ()
foreign import ccall zk_private_from_bytes :: Ptr ZkPrivate -> Ptr CChar -> IO ()
foreign import ccall "&zk_private_clear" zk_private_clear :: FunPtr (Ptr ZkPrivate -> IO ())

instance Serialize ZkPrivate where
  put (ZkPrivate ptr) =
    let bytes = unsafePerformIO $
          withForeignPtr ptr $ \p -> do
          allocaBytes privateLength $ \bytes -> do
          zk_private_to_bytes bytes p
          packCStringLen (bytes, privateLength)
    in  putByteString bytes
  get =
    do bytes <- getByteString privateLength
       return $ unsafePerformIO $ useAsCStringLen bytes $ \(encoded, _) -> do
         private <- mallocForeignPtrBytes #size zk_private_t
         withForeignPtr private $ \privatePtr -> do
         zk_private_from_bytes privatePtr encoded
         addForeignPtrFinalizer zk_private_clear private
         return (ZkPrivate private)

foreign import ccall zk_extract :: Ptr ZkPrivate -> CInt -> Ptr CChar -> Ptr ZkMaster -> IO ()

extractKey :: ZkMaster -> ByteString -> ZkPrivate
extractKey (ZkMaster masterPtr) s = unsafePerformIO $ do
  useAsCStringLen s $ \(s,len) -> do
  withForeignPtr masterPtr $ \master -> do
  private <- mallocForeignPtrBytes #size zk_private_t
  withForeignPtr private $ \privatePtr -> do
  zk_extract privatePtr (toEnum len) s master
  addForeignPtrFinalizer zk_private_clear private
  return (ZkPrivate private)

foreign import ccall zk_sign_init :: Ptr CChar -> Ptr CChar -> Ptr ZkPrivate -> CInt -> Ptr CChar -> IO ()

signInit :: ZkPrivate -> ByteString -> IO (ByteString, ByteString)
signInit (ZkPrivate private) id = do
  withForeignPtr private $ \privatePtr -> do
  useAsCStringLen id $ \(id, idlen) -> do
  allocaBytes signInitLength $ \commitmentPtr -> do
  allocaBytes signInitFactorLength $ \commitmentPrivatePtr -> do
  zk_sign_init commitmentPtr commitmentPrivatePtr privatePtr (toEnum idlen) id
  commitment <- packCStringLen (commitmentPtr, signInitLength)
  commitmentPrivate <- packCStringLen (commitmentPrivatePtr, signInitLength)
  return (commitment, commitmentPrivate)

foreign import ccall zk_blind :: Ptr CChar -> Ptr CChar -> Ptr CChar -> Ptr ZkParam -> CInt -> Ptr CChar -> CInt -> Ptr CChar -> IO ()

blind :: ZkParam -> ByteString -> ByteString -> ByteString -> IO (ByteString, ByteString)
blind (ZkParam param) id commitment s = do
  withForeignPtr param $ \paramPtr -> do
  useAsCStringLen id $ \(id, idlen) -> do
  useAsCStringLen s $ \(s, datalen) -> do
  useAsCStringLen commitment $ \(commitment, _) -> do
  allocaBytes blindedLength $ \blindedPtr -> do
  allocaBytes blindingFactorLength $ \blindingFactorPtr -> do
  zk_blind blindedPtr blindingFactorPtr commitment paramPtr (toEnum idlen) id (toEnum datalen) s
  blinded <- packCStringLen (blindedPtr, blindedLength)
  blindingFactor <- packCStringLen (blindingFactorPtr, blindingFactorLength)
  return (blinded, blindingFactor)

foreign import ccall zk_sign :: Ptr CChar -> Ptr CChar -> Ptr CChar -> Ptr ZkPrivate -> IO ()

sign :: ZkPrivate -> ByteString -> ByteString -> ByteString
sign (ZkPrivate private) commitment blinded = unsafePerformIO $ do
  withForeignPtr private $ \privatePtr -> do
  useAsCStringLen commitment $ \(commitment, commitmentLen) -> do
  useAsCStringLen blinded $ \(blinded, blindedLen) -> do
  allocaBytes blindedSignatureLength $ \signaturePtr -> do
  zk_sign signaturePtr commitment blinded privatePtr
  signature <- packCStringLen (signaturePtr, blindedSignatureLength)
  return signature

foreign import ccall zk_unblind :: Ptr CChar -> Ptr CChar -> Ptr CChar -> Ptr ZkParam -> IO ()

unblind :: ZkParam -> ByteString -> ByteString -> ByteString
unblind (ZkParam param) signature blindingFactor = unsafePerformIO $ do
  withForeignPtr param $ \paramPtr -> do
  useAsCStringLen signature $ \(signature, signatureLen) -> do
  useAsCStringLen blindingFactor $ \(blindingFactor, blindingFactorLen) -> do
  allocaBytes signatureLength $ \signaturePtr -> do
  zk_unblind signaturePtr signature blindingFactor paramPtr
  signature <- packCStringLen (signaturePtr, signatureLength)
  return signature

foreign import ccall zk_verify :: Ptr CChar -> CInt -> Ptr CChar -> Ptr ZkParam -> CInt -> Ptr CChar -> IO CInt

verify :: ZkParam -> ByteString -> ByteString -> ByteString -> CInt
verify (ZkParam param) id s signature = unsafePerformIO $ do
  withForeignPtr param $ \paramPtr -> do
  useAsCStringLen id $ \(id, idLen) -> do
  useAsCStringLen s $ \(s, sLen) -> do
  useAsCStringLen signature $ \(signature, signatureLen) -> do
  zk_verify signature (toEnum sLen) s paramPtr (toEnum idLen) id
