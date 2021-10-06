module Erl.Ssl
  ( AntiReplay
  , Key
  , Ciphers
  , SignScheme
  , Group
  , VerifyFn
  , VerifyEvent
  , VerifyFnResult
  , PartialChainFn
  , UserLookupFn
  , ProtocolVersion
  , LogLevel
  , OTPCertificate
  , BeastMitigation
  , CrlCheck
  , NamedCurve
  , HandshakeCompletion
  , Protocol
  , ClientSessionTickets
  , ServerSessionTickets
  , Verify
  , KeyPassword
  , CommonOptions
  , ServerOptions
  , ClientOptions
  , ListenOptions
  , ConnectOptions
  , ClientReuseSession
  , ClientReuseSessions
  , AppLevelProtocol
  , ClientPreferredNextProtocols
  , PskIdentity
  , SrpIdentity
  , MaxFragmentLength
  , SignatureAlgorithm
  , ProtocolPrecedence
  , ServerReuseSessionFn
  , Cipher
  , OptionToMaybe
  , SslSocket
  , defaultCommonOptions
  , defaultServerOptions
  , defaultClientOptions
  , defaultListenOptions
  , defaultConnectOptions
  , connectOptions
  , connectPassive
  , close
  , send
  , recv
  ) where

import Prelude
import ConvertableOptions (class ConvertOption, class ConvertOptionsWithDefaults, convertOptionsWithDefaults)
import Data.Either (Either(..))
import Data.Maybe (Maybe(..), fromMaybe')
import Data.Time.Duration (Milliseconds)
import Effect (Effect)
import Effect.Class (liftEffect)
import Erl.Atom (Atom, atom)
import Erl.Data.Binary (Binary)
import Erl.Data.Binary.IOData (IOData)
import Erl.Data.List (List)
import Erl.Data.Tuple (tuple2, tuple3)
import Erl.Kernel.File (FileName)
import Erl.Kernel.Inet (class Socket, ActiveError, ActiveSocket, ConnectAddress, ConnectError, ConnectedSocket, Hostname, PassiveSocket, Port, SendError, SocketMessageBehaviour, SocketType, activeErrorToPurs, connectErrorToPurs, optionsToErl, sendErrorToPurs)
import Erl.Kernel.Inet as Inet
import Erl.Kernel.Tcp as Tcp
import Erl.Otp.Types.Crypto as Crypto
import Erl.Otp.Types.PublicKey as PublicKey
import Erl.Types (class ToErl, NonNegInt, PosInt, Timeout, toErl)
import Foreign (Foreign, unsafeToForeign)
import Logger (logLevelToErl)
import Logger as Logger
import Partial.Unsafe (unsafeCrashWith)
import Prim.Row as Row
import Record as Record
import Unsafe.Reference (unsafeRefEq)

foreign import data SslSocket :: SocketMessageBehaviour -> SocketType -> Type

instance Socket (SslSocket ActiveSocket) where
  send = send
  recv = recv
  close = close
instance Socket (SslSocket PassiveSocket) where
  send = send
  recv = recv
  close = close

data AntiReplay
  = TenK
  | OneHundredK
  | Other Int Int Int

derive instance eqAntiReplay :: Eq AntiReplay

data BeastMitigation
  = OneNMinusOne
  | ZeroN
  | Disabled

derive instance eqBeastMitigation :: Eq BeastMitigation

data KeyExchangeAlgorithm
  = Rsa
  | Dhe_rsa
  | Dhe_dss
  | Ecdhe_cdsa
  | Ecdh_ecdsa
  | Ecdh_rsa
  | Srp_rsa
  | Srp_dss
  | Psk
  | Dhe_psk
  | Rsa_psk
  | Dh_anon
  | Ecdh_anon
  | Srp_anon
  | Any

derive instance eqKeyExchangeAlgo :: Eq KeyExchangeAlgorithm

data LegacyCipher
  = Rc4_128
  | Des_cbc
  | TripleDes_ede_cbc

derive instance eqLegacyCipher :: Eq LegacyCipher

data Cipher
  = Aes_128_cbc
  | Aes_256_cbc
  | Aes_128_gcm
  | Aes_256_gcm
  | Aes_128_ccm
  | Aes_256_ccm
  | Aes_128_ccm_8
  | Aes_256_ccm_8
  | Chacha20_poly1305
  | Legacy LegacyCipher

derive instance eqCipher :: Eq Cipher

data CipherMac
  = MacHash Hash
  | Aead

derive instance eqCipherMac :: Eq CipherMac

data CipherPrf
  = PrfHash Hash
  | DefaultPrf

derive instance eqCipherPhrf :: Eq CipherPrf

type CipherSuite
  = { keyExchange :: KeyExchangeAlgorithm
    , cipher :: Cipher
    , mac :: CipherMac
    , prf :: CipherPrf
    }

data Ciphers
  = CipherSuites (List CipherSuite)
  | OtherCipher String

derive instance eqCiphers :: Eq Ciphers

data Group
  = Secp256r1
  | Secp384r1
  | Secp521r1
  | Ffdhe2048
  | Ffdhe3072
  | Ffdhe4096
  | Ffdhe6144
  | Ffdhe8192

derive instance eqGroup :: Eq Group

data Key
  = RSAPrivateKey PublicKey.DerEncoded
  | DSAPrivateKey PublicKey.DerEncoded
  | ECPrivateKey PublicKey.DerEncoded
  | PrivateKeyInfo PublicKey.DerEncoded
  | OtherKey
    { algorithm :: SignAlgorithm
    , engine :: Crypto.EngineRef
    , key_id :: Crypto.KeyId
    , password :: Crypto.Password
    }

derive instance eqKey :: Eq Key

data CrlCheck
  = Peer
  | BestEffort

derive instance eqCrlCheck :: Eq CrlCheck

data NamedCurve
  = Sect571r1_Curve
  | Sect571k1_Curve
  | Secp521r1_Curve
  | Brainpoolp512r1_Curve
  | Sect409k1_Curve
  | Sect409r1_Curve
  | Brainpoolp384r1_Curve
  | Secp384r1_Curve
  | Sect283k1_Curve
  | Sect283r1_Curve
  | Brainpoolp256r1_Curve
  | Secp256k1_Curve
  | Secp256r1_Curve
  | Sect239k1_Curve
  | Sect233k1_Curve
  | Sect233r1_Curve
  | Secp224k1_Curve
  | Secp224r1_Curve
  | Sect193r1_Curve
  | Sect193r2_Curve
  | Secp192k1_Curve
  | Secp192r1_Curve
  | Sect163k1_Curve
  | Sect163r1_Curve
  | Sect163r2_Curve
  | Secp160k1_Curve
  | Secp160r1_Curve
  | Secp160r2_Curve

derive instance eqNamedCurve :: Eq NamedCurve

data HandshakeCompletion
  = Hello
  | Full

derive instance eqHsC :: Eq HandshakeCompletion

data Sha2
  = Sha224
  | Sha256
  | Sha384
  | Sha512

derive instance eqSha2 :: Eq Sha2

data Hash
  = Sha
  | Sha2 Sha2
  | Md5

derive instance eqHash :: Eq Hash

data SignAlgorithm
  = Rsa_Sign
  | Dsa_Sign
  | Ecdsa_Sign

derive instance eqSa :: Eq SignAlgorithm

data SignScheme
  = Rsa_pkcs1_sha256
  | Rsa_pkcs1_sha384
  | Rsa_pkcs1_sha512
  | Ecdsa_secp256r1_sha256
  | Ecdsa_secp384r1_sha384
  | Ecdsa_secp521r1_sha512
  | Rsa_pss_rsae_sha256
  | Rsa_pss_rsae_sha384
  | Rsa_pss_rsae_sha512
  | Rsa_pss_pss_sha256
  | Rsa_pss_pss_sha384
  | Rsa_pss_pss_sha512
  | Rsa_pkcs1_sha1
  | Ecdsa_sha1

derive instance eqSignScheme :: Eq SignScheme

data SignatureAlgorithm
  = SignatureAlgorithm Hash SignAlgorithm

derive instance eqSignatureAlgo :: Eq SignatureAlgorithm

data Protocol
  = Tls
  | Dtls

derive instance eqProtocol :: Eq Protocol

data ClientSessionTickets
  = Disabled_Client
  | Manual
  | Auto

derive instance eqClientSessionTickets :: Eq ClientSessionTickets

data ServerSessionTickets
  = Disabled_Server
  | Stateful
  | Stateless

derive instance eqServerSessionTickets :: Eq ServerSessionTickets

data Verify
  = VerifyNone
  | VerifyPeer

derive instance eqVerify :: Eq Verify

data ProtocolVersion
  = TlsVersion TlsVersion
  | DtlsVersion DtlsVersion

derive instance eqProtocolVersion :: Eq ProtocolVersion

data TlsVersion
  = Tlsv1_2
  | Tlsv1_3
  | TlsLegacyVersion TlsLegacyVersion

derive instance eqTlsVersion :: Eq TlsVersion

data DtlsVersion
  = Dtlsv1_2
  | DtlsLegacyVersion DtlsLegacyVersion

derive instance eqDtlsersion :: Eq DtlsVersion

data TlsLegacyVersion
  = Tlsv1
  | Tlsv1_1

derive instance eqTlsLegacyVersion :: Eq TlsLegacyVersion

data DtlsLegacyVersion
  = Dtlsv1

derive instance eqDtlsLegacyVersion :: Eq DtlsLegacyVersion

data LogLevel
  = All
  | None
  | Logger Logger.LogLevel

derive instance eqLogLevel :: Eq LogLevel

foreign import data OTPCertificate :: Type

instance eqOtpCert :: Eq OTPCertificate where
  eq = unsafeRefEq

foreign import data Extension :: Type

instance eqExtension :: Eq Extension where
  eq = unsafeRefEq

data SrpParamType
  = Srp_1024
  | Srp_1536
  | Srp_2048
  | Srp_3072
  | Srp_4096
  | Srp_6144
  | Srp_8192

derive instance eqSrpParamType :: Eq SrpParamType

data BadCert
  = Revoked Atom
  | OtherBadCert Atom

derive instance eqBadCert :: Eq BadCert

data VerifyEvent
  = BadCert BadCert
  | Extension Extension
  | Valid
  | ValidPeer

derive instance eqVerifyEvent :: Eq VerifyEvent

data VerifyFnResult
  = VerifyValid VerifyFn
  | VerifyFail String
  | VerifyUnknown VerifyFn

instance eqVerifyFnResult :: Eq VerifyFnResult where
  eq (VerifyValid fn1) (VerifyValid fn2) = unsafeRefEq fn1 fn2
  eq (VerifyFail s1) (VerifyFail s2) = s1 == s2
  eq (VerifyUnknown fn1) (VerifyUnknown fn2) = unsafeRefEq fn1 fn2
  eq _ _ = false

type VerifyFn
  = OTPCertificate -> VerifyEvent -> VerifyFnResult

type PartialChainFn
  = List PublicKey.DerEncoded -> Maybe PublicKey.DerEncoded

data UserLookupFn
  = PskLookup (Binary -> Maybe Binary)
  | SrpLookup
    ( Binary ->
      Maybe
        { srpParams :: SrpParamType
        , salt :: Binary
        , derivedKey :: Binary
        }
    )

instance eqUserLookupFn :: Eq UserLookupFn where
  eq (PskLookup fn1) (PskLookup fn2) = unsafeRefEq fn1 fn2
  eq (SrpLookup fn1) (SrpLookup fn2) = unsafeRefEq fn1 fn2
  eq _ _ = false

type KeyPassword
  = String

instance toErl_Group :: ToErl Group where
  toErl Secp256r1 = unsafeToForeign $ atom "Secp256r1"
  toErl Secp384r1 = unsafeToForeign $ atom "secp384r1"
  toErl Secp521r1 = unsafeToForeign $ atom "secp521r1"
  toErl Ffdhe2048 = unsafeToForeign $ atom "ffdhe2048"
  toErl Ffdhe3072 = unsafeToForeign $ atom "ffdhe3072"
  toErl Ffdhe4096 = unsafeToForeign $ atom "ffdhe4096"
  toErl Ffdhe6144 = unsafeToForeign $ atom "ffdhe6144"
  toErl Ffdhe8192 = unsafeToForeign $ atom "ffdhe8192"

instance toErl_SignScheme :: ToErl SignScheme where
  toErl Rsa_pkcs1_sha256 = unsafeToForeign $ atom "rsa_pkcs1_sha256"
  toErl Rsa_pkcs1_sha384 = unsafeToForeign $ atom "rsa_pkcs1_sha384"
  toErl Rsa_pkcs1_sha512 = unsafeToForeign $ atom "rsa_pkcs1_sha512"
  toErl Ecdsa_secp256r1_sha256 = unsafeToForeign $ atom "ecdsa_secp256r1_sha256"
  toErl Ecdsa_secp384r1_sha384 = unsafeToForeign $ atom "ecdsa_secp384r1_sha384"
  toErl Ecdsa_secp521r1_sha512 = unsafeToForeign $ atom "ecdsa_secp521r1_sha512"
  toErl Rsa_pss_rsae_sha256 = unsafeToForeign $ atom "rsa_pss_rsae_sha256"
  toErl Rsa_pss_rsae_sha384 = unsafeToForeign $ atom "rsa_pss_rsae_sha384"
  toErl Rsa_pss_rsae_sha512 = unsafeToForeign $ atom "rsa_pss_rsae_sha512"
  toErl Rsa_pss_pss_sha256 = unsafeToForeign $ atom "rsa_pss_pss_sha256"
  toErl Rsa_pss_pss_sha384 = unsafeToForeign $ atom "rsa_pss_pss_sha384"
  toErl Rsa_pss_pss_sha512 = unsafeToForeign $ atom "rsa_pss_pss_sha512"
  toErl Rsa_pkcs1_sha1 = unsafeToForeign $ atom "rsa_pkcs1_sha1"
  toErl Ecdsa_sha1 = unsafeToForeign $ atom "ecdsa_sha1"

instance toErl_SignatureAlgorithm :: ToErl SignatureAlgorithm where
  toErl (SignatureAlgorithm hash signAlgorithm) = unsafeToForeign $ tuple2 (toErl hash) (toErl signAlgorithm)

instance toErl_Hash :: ToErl Hash where
  toErl Sha = unsafeToForeign $ atom "sha"
  toErl (Sha2 sha2) = toErl sha2
  toErl Md5 = unsafeToForeign $ atom "md5"

instance toErl_Sha2 :: ToErl Sha2 where
  toErl Sha224 = unsafeToForeign $ atom "sha224"
  toErl Sha256 = unsafeToForeign $ atom "sha256"
  toErl Sha384 = unsafeToForeign $ atom "sha384"
  toErl Sha512 = unsafeToForeign $ atom "sha512"

instance toErl_SignAlgorithm :: ToErl SignAlgorithm where
  toErl Rsa_Sign = unsafeToForeign $ atom "rsa"
  toErl Dsa_Sign = unsafeToForeign $ atom "dsa"
  toErl Ecdsa_Sign = unsafeToForeign $ atom "ecdsa"

instance toErl_ClientSessionTickets :: ToErl ClientSessionTickets where
  toErl Disabled_Client = unsafeToForeign $ atom "disabled"
  toErl Manual = unsafeToForeign $ atom "manual"
  toErl Auto = unsafeToForeign $ atom "auto"

instance toErl_ClientReuseSessions :: ToErl ClientReuseSessions where
  toErl ClientNone = unsafeToForeign false
  toErl ClientAuto = unsafeToForeign true
  toErl ClientSave = unsafeToForeign $ atom "save"

instance toErl_ClientReuseSession :: ToErl ClientReuseSession where
  toErl (PreTls1_3 sessionId) = unsafeToForeign sessionId
  toErl (Tls1_3 sessionId sessionData) = unsafeToForeign $ tuple2 sessionId sessionData

instance toErl_MaxFragmentLength :: ToErl MaxFragmentLength where
  toErl Fragment_512 = unsafeToForeign 512
  toErl Fragment_1024 = unsafeToForeign 1024
  toErl Fragment_2048 = unsafeToForeign 2048
  toErl Fragment_4096 = unsafeToForeign 4096

instance toErl_ProtocolPrecedence :: ToErl ProtocolPrecedence where
  toErl Server = unsafeToForeign $ atom "server"
  toErl Client = unsafeToForeign $ atom "client"

instance toErl_Verify :: ToErl Verify where
  toErl VerifyNone = unsafeToForeign $ atom "verify_none"
  toErl VerifyPeer = unsafeToForeign $ atom "verify_peer"

instance toErl_ProtocolVersion :: ToErl ProtocolVersion where
  toErl (TlsVersion tls) = toErl tls
  toErl (DtlsVersion dtls) = toErl dtls

instance toErl_TlsVersion :: ToErl TlsVersion where
  toErl Tlsv1_2 = unsafeToForeign $ atom "tlsv1.2"
  toErl Tlsv1_3 = unsafeToForeign $ atom "tlsv1.3"
  toErl (TlsLegacyVersion legacy) = toErl legacy

instance toErl_TlsLegacyVersion :: ToErl TlsLegacyVersion where
  toErl Tlsv1 = unsafeToForeign $ atom "tlsv1"
  toErl Tlsv1_1 = unsafeToForeign $ atom "tlsv1.1"

instance toErl_DtlsVersion :: ToErl DtlsVersion where
  toErl Dtlsv1_2 = unsafeToForeign $ atom "dtlsv1.2"
  toErl (DtlsLegacyVersion legacy) = toErl legacy

instance toErl_DtlsLegacyVersion :: ToErl DtlsLegacyVersion where
  toErl Dtlsv1 = unsafeToForeign $ atom "dtlsv1"

instance toErl_ServerSessionTickets :: ToErl ServerSessionTickets where
  toErl Disabled_Server = unsafeToForeign $ atom "disabled"
  toErl Stateful = unsafeToForeign $ atom "stateful"
  toErl Stateless = unsafeToForeign $ atom "stateless"

instance toErl_Protocol :: ToErl Protocol where
  toErl Tls = unsafeToForeign $ atom "tls"
  toErl Dtls = unsafeToForeign $ atom "dtls"

instance toErl_LogLevel :: ToErl LogLevel where
  toErl All = unsafeToForeign $ atom "all"
  toErl None = unsafeToForeign $ atom "none"
  toErl (Logger level) = unsafeToForeign $ logLevelToErl level

instance toErl_Key :: ToErl Key where
  toErl (RSAPrivateKey key) = unsafeToForeign $ tuple2 (atom "RSAPrivateKey") (toErl key)
  toErl (DSAPrivateKey key) = unsafeToForeign $ tuple2 (atom "DSAPrivateKey") (toErl key)
  toErl (ECPrivateKey key) = unsafeToForeign $ tuple2 (atom "ECPrivateKey") (toErl key)
  toErl (PrivateKeyInfo key) = unsafeToForeign $ tuple2 (atom "PrivateKeyInfo") (toErl key)
  toErl
    ( OtherKey
        { algorithm
        , engine
        , key_id
        , password
        }
    ) =
    unsafeToForeign
      $
        { algorithm: toErl algorithm
        , engine: toErl engine
        , key_id: toErl key_id
        , password: toErl password
        }

instance toErl_HandshakeCompletion :: ToErl HandshakeCompletion where
  toErl Hello = unsafeToForeign $ atom "hello"
  toErl Full = unsafeToForeign $ atom "full"

instance toErl_NamedCurve :: ToErl NamedCurve where
  toErl Sect571r1_Curve = unsafeToForeign $ atom "sect571r1"
  toErl Sect571k1_Curve = unsafeToForeign $ atom "sect571k1"
  toErl Secp521r1_Curve = unsafeToForeign $ atom "secp521r1"
  toErl Brainpoolp512r1_Curve = unsafeToForeign $ atom "brainpoolp512r1"
  toErl Sect409k1_Curve = unsafeToForeign $ atom "sect409k1"
  toErl Sect409r1_Curve = unsafeToForeign $ atom "sect409r1"
  toErl Brainpoolp384r1_Curve = unsafeToForeign $ atom "brainpoolp384r1"
  toErl Secp384r1_Curve = unsafeToForeign $ atom "secp384r1"
  toErl Sect283k1_Curve = unsafeToForeign $ atom "sect283k1"
  toErl Sect283r1_Curve = unsafeToForeign $ atom "sect283r1"
  toErl Brainpoolp256r1_Curve = unsafeToForeign $ atom "brainpoolp256r1"
  toErl Secp256k1_Curve = unsafeToForeign $ atom "secp256k1"
  toErl Secp256r1_Curve = unsafeToForeign $ atom "secp256r1"
  toErl Sect239k1_Curve = unsafeToForeign $ atom "sect239k1"
  toErl Sect233k1_Curve = unsafeToForeign $ atom "sect233k1"
  toErl Sect233r1_Curve = unsafeToForeign $ atom "sect233r1"
  toErl Secp224k1_Curve = unsafeToForeign $ atom "secp224k1"
  toErl Secp224r1_Curve = unsafeToForeign $ atom "secp224r1"
  toErl Sect193r1_Curve = unsafeToForeign $ atom "sect193r1"
  toErl Sect193r2_Curve = unsafeToForeign $ atom "sect193r2"
  toErl Secp192k1_Curve = unsafeToForeign $ atom "secp192k1"
  toErl Secp192r1_Curve = unsafeToForeign $ atom "secp192r1"
  toErl Sect163k1_Curve = unsafeToForeign $ atom "sect163k1"
  toErl Sect163r1_Curve = unsafeToForeign $ atom "sect163r1"
  toErl Sect163r2_Curve = unsafeToForeign $ atom "sect163r2"
  toErl Secp160k1_Curve = unsafeToForeign $ atom "secp160k1"
  toErl Secp160r1_Curve = unsafeToForeign $ atom "secp160r1"
  toErl Secp160r2_Curve = unsafeToForeign $ atom "secp160r2"

instance toErl_CrlCheck :: ToErl CrlCheck where
  toErl Peer = unsafeToForeign $ atom "peer"
  toErl BestEffort = unsafeToForeign $ atom "best_effort"

instance toErl_Ciphers :: ToErl Ciphers where
  toErl (CipherSuites cipherSuites) =
    unsafeToForeign
      $ ( \{ keyExchange
          , cipher
          , mac
          , prf
          } ->
            { keyExchange: toErl keyExchange
            , cipher: toErl cipher
            , mac: toErl mac
            , prf: toErl prf
            }
        )
      <$> cipherSuites
  toErl (OtherCipher cipher) = unsafeToForeign cipher

instance toErl_KeyExchangeAlgorithm :: ToErl KeyExchangeAlgorithm where
  toErl Rsa = unsafeToForeign $ atom "rsa"
  toErl Dhe_rsa = unsafeToForeign $ atom "dhe_rsa"
  toErl Dhe_dss = unsafeToForeign $ atom "dhe_dss"
  toErl Ecdhe_cdsa = unsafeToForeign $ atom "ecdhe_cdsa"
  toErl Ecdh_ecdsa = unsafeToForeign $ atom "ecdh_ecdsa"
  toErl Ecdh_rsa = unsafeToForeign $ atom "ecdh_rsa"
  toErl Srp_rsa = unsafeToForeign $ atom "srp_rsa"
  toErl Srp_dss = unsafeToForeign $ atom "srp_dss"
  toErl Psk = unsafeToForeign $ atom "psk"
  toErl Dhe_psk = unsafeToForeign $ atom "dhe_psk"
  toErl Rsa_psk = unsafeToForeign $ atom "rsa_psk"
  toErl Dh_anon = unsafeToForeign $ atom "dh_anon"
  toErl Ecdh_anon = unsafeToForeign $ atom "ecdh_anon"
  toErl Srp_anon = unsafeToForeign $ atom "srp_anon"
  toErl Any = unsafeToForeign $ atom "any"

instance toErl_Cipher :: ToErl Cipher where
  toErl Aes_128_cbc = unsafeToForeign $ atom "aes_128_cbc"
  toErl Aes_256_cbc = unsafeToForeign $ atom "aes_256_cbc"
  toErl Aes_128_gcm = unsafeToForeign $ atom "aes_128_gcm"
  toErl Aes_256_gcm = unsafeToForeign $ atom "aes_256_gcm"
  toErl Aes_128_ccm = unsafeToForeign $ atom "aes_128_ccm"
  toErl Aes_256_ccm = unsafeToForeign $ atom "aes_256_ccm"
  toErl Aes_128_ccm_8 = unsafeToForeign $ atom "aes_128_ccm_8"
  toErl Aes_256_ccm_8 = unsafeToForeign $ atom "aes_256_ccm_8"
  toErl Chacha20_poly1305 = unsafeToForeign $ atom "chacha20_poly1305"
  toErl (Legacy legacy) = toErl legacy

instance toErl_CipherMac :: ToErl CipherMac where
  toErl (MacHash hash) = toErl hash
  toErl Aead = unsafeToForeign $ atom "aead"

instance toErl_CipherPrf :: ToErl CipherPrf where
  toErl (PrfHash hash) = toErl hash
  toErl DefaultPrf = unsafeToForeign $ atom "default_prf"

instance toErl_LegacyCipher :: ToErl LegacyCipher where
  toErl Rc4_128 = unsafeToForeign $ atom "rc4_128"
  toErl Des_cbc = unsafeToForeign $ atom "des_cbc"
  toErl TripleDes_ede_cbc = unsafeToForeign $ atom "tripledes_ede_cbc"

instance toErl_BeastMitigation :: ToErl BeastMitigation where
  toErl OneNMinusOne = unsafeToForeign $ atom "one_n_minus_one"
  toErl ZeroN = unsafeToForeign $ atom "zero_n"
  toErl Disabled = unsafeToForeign $ atom "disabled"

instance toErl_AntiReplay :: ToErl AntiReplay where
  toErl TenK = unsafeToForeign $ atom "10k"
  toErl OneHundredK = unsafeToForeign $ atom "100k"
  toErl (Other a b c) = unsafeToForeign $ tuple3 a b c

instance toErl_ClientPreferredNextProtocols :: ToErl ClientPreferredNextProtocols where
  toErl (ClientPreferredNextProtocols { precedence, client_prefs, defaultProtocol: Nothing }) = unsafeToForeign $ tuple2 (toErl precedence) client_prefs
  toErl (ClientPreferredNextProtocols { precedence, client_prefs, defaultProtocol: Just defaultProtocol }) = unsafeToForeign $ tuple3 (toErl precedence) client_prefs (toErl defaultProtocol)

type CommonOptions r
  = ( protocol :: Maybe Protocol
    , handshake :: Maybe HandshakeCompletion
    , cert :: Maybe (List PublicKey.DerEncoded)
    , certfile :: Maybe FileName
    , key :: Maybe Key
    , keyfile :: Maybe FileName
    , password :: Maybe KeyPassword
    , ciphers :: Maybe Ciphers
    , eccs :: Maybe (List NamedCurve)
    , signature_algs_cert :: Maybe (List SignScheme)
    , supported_groups :: Maybe (List Group)
    , secure_renegotiate :: Maybe Boolean
    , keep_secrets :: Maybe Boolean
    , depth :: Maybe Int
    --, verify_fun :: Maybe VerifyFn
    , crl_check :: Maybe CrlCheck
    --, crl_cache :: [any()]
    , max_handshake_size :: Maybe Int
    --, partial_chain :: Maybe PartialChainFn
    , versions :: Maybe (List ProtocolVersion)
    --, user_lookup_fun :: Maybe UserLookupFn
    , log_level :: Maybe LogLevel
    , hibernate_after :: Maybe Milliseconds
    , padding_check :: Maybe Boolean
    , beast_mitigation :: Maybe BeastMitigation
    , key_update_at :: Maybe PosInt
    , middlebox_comp_mode :: Maybe Boolean
    | r
    )

defaultCommonOptions ::
  forall r.
  Row.Union r (CommonOptions ()) (CommonOptions r) =>
  Record r -> Record (CommonOptions r)
defaultCommonOptions r =
  Record.union r
    { protocol: Nothing
    , handshake: Nothing
    , cert: Nothing
    , certfile: Nothing
    , key: Nothing
    , keyfile: Nothing
    , password: Nothing
    , ciphers: Nothing
    , eccs: Nothing
    , signature_algs_cert: Nothing
    , supported_groups: Nothing
    , secure_renegotiate: Nothing
    , keep_secrets: Nothing
    , depth: Nothing
    --, verify_fun: Nothing
    , crl_check: Nothing
    --, crl_cache: Nothing
    , max_handshake_size: Nothing
    --, partial_chain: Nothing
    , versions: Nothing
    --, user_lookup_fun: Nothing
    , log_level: Nothing
    , hibernate_after: Nothing
    , padding_check: Nothing
    , beast_mitigation: Nothing
    , key_update_at: Nothing
    , middlebox_comp_mode: Nothing
    }

-- todo - this is not at all clear from the docs...
type ServerReuseSessionFn
  = Binary -> PublicKey.DerEncoded -> Int -> Cipher -> Boolean

type SniFn
  = Hostname -> List (Record (ServerOptions (CommonOptions ())))

type AppLevelProtocol
  = Binary

type PskIdentity
  = String

type SrpIdentity
  = String

type ServerOptions r
  = ( cacerts :: Maybe (List PublicKey.DerEncoded)
    , cacertfile :: Maybe FileName
    , dh :: Maybe Binary -- todo - merge
    , dhfile :: Maybe FileName
    , verify :: Maybe Verify
    , fail_if_no_peer_cert :: Maybe Boolean
    , reuse_sessions :: Maybe Boolean
    --, reuse_session :: Maybe ServerReuseSessionFn
    , alpn_preferred_protocols :: Maybe (List AppLevelProtocol)
    , next_protocols_advertised :: Maybe (List AppLevelProtocol)
    , psk_identity :: Maybe PskIdentity
    , honor_cipher_order :: Maybe Boolean
    --, sni_hosts :: List (Tuple2 Hostname (ServerOptions (CommonOptions ()))) -- todo - more complicated due to recursion...
    --, sni_fun :: SniFn
    , honor_ecc_order :: Maybe Boolean
    , client_renegotiation :: Maybe Boolean
    , signature_algs :: Maybe (List SignatureAlgorithm)
    , session_tickets :: Maybe ServerSessionTickets
    , anti_replay :: Maybe AntiReplay
    , cookie :: Maybe Boolean
    , early_data :: Maybe Binary
    | r
    )

defaultServerOptions ::
  forall r.
  Row.Union r (ServerOptions ()) (ServerOptions r) =>
  Record r -> Record (ServerOptions r)
defaultServerOptions r =
  Record.union r
    { cacerts: Nothing
    , cacertfile: Nothing
    , dh: Nothing
    , dhfile: Nothing
    , verify: Nothing
    , fail_if_no_peer_cert: Nothing
    , reuse_sessions: Nothing
    --, reuse_session: Nothing
    , alpn_preferred_protocols: Nothing
    , next_protocols_advertised: Nothing
    , psk_identity: Nothing
    , honor_cipher_order: Nothing
    --, sni_hosts: Nothing
    --, sni_fun: Nothing
    , honor_ecc_order: Nothing
    , client_renegotiation: Nothing
    , signature_algs: Nothing
    , session_tickets: Nothing
    , anti_replay: Nothing
    , cookie: Nothing
    , early_data: Nothing
    }

type ListenOptions
  = ServerOptions (CommonOptions (Tcp.ListenOptions))

defaultListenOptions :: Record ListenOptions
defaultListenOptions = defaultServerOptions $ defaultCommonOptions $ Tcp.defaultListenOptions

data ClientReuseSessions
  = ClientNone
  | ClientSave
  | ClientAuto

derive instance eqClientReuseSessions :: Eq ClientReuseSessions

data ClientReuseSession
  = PreTls1_3 Binary
  | Tls1_3 Binary Binary

derive instance eqClientReuseSession :: Eq ClientReuseSession

data MaxFragmentLength
  = Fragment_512
  | Fragment_1024
  | Fragment_2048
  | Fragment_4096

derive instance eqMaxFragmentLength :: Eq MaxFragmentLength

data ProtocolPrecedence
  = Server
  | Client

derive instance eqProtocolPrecedence :: Eq ProtocolPrecedence

newtype ClientPreferredNextProtocols
  = ClientPreferredNextProtocols
  { precedence :: ProtocolPrecedence
  , client_prefs :: List AppLevelProtocol
  , defaultProtocol :: Maybe AppLevelProtocol
  }

derive newtype instance eqClientPreferredNextProtocols :: Eq ClientPreferredNextProtocols

type ClientOptions r
  = ( verify :: Maybe Verify
    , reuse_session :: Maybe ClientReuseSession
    , reuse_sessions :: Maybe ClientReuseSessions
    , cacerts :: Maybe (List PublicKey.DerEncoded)
    , cacertfile :: Maybe FileName
    , alpn_advertised_protocols :: Maybe (List AppLevelProtocol)
    , client_preferred_next_protocols :: Maybe ClientPreferredNextProtocols
    , psk_identity :: Maybe PskIdentity
    , srp_identity :: Maybe SrpIdentity
    , server_name_indication :: Maybe Hostname
    , max_fragment_length :: Maybe MaxFragmentLength
    -- {customize_hostname_check, customize_hostname_check()} |
    , signature_algs :: Maybe (List SignatureAlgorithm)
    , fallback :: Maybe Boolean
    , session_tickets :: Maybe ClientSessionTickets
    , use_ticket :: Maybe (List Binary)
    , early_data :: Maybe Binary
    | r
    )

defaultClientOptions ::
  forall r.
  Row.Union r (ClientOptions ()) (ClientOptions r) =>
  Row.Nub (ClientOptions r) (ClientOptions r) =>
  Record r -> Record (ClientOptions r)
defaultClientOptions r =
  Record.disjointUnion r
    { verify: Nothing
    , reuse_session: Nothing
    , reuse_sessions: Nothing
    , cacerts: Nothing
    , cacertfile: Nothing
    , alpn_advertised_protocols: Nothing
    , client_preferred_next_protocols: Nothing
    , psk_identity: Nothing
    , srp_identity: Nothing
    , server_name_indication: Nothing
    , max_fragment_length: Nothing
    -- {customize_hostname_check, customize_hostname_check()} |
    , signature_algs: Nothing
    , fallback: Nothing
    , session_tickets: Nothing
    , use_ticket: Nothing
    , early_data: Nothing
    }

type ConnectOptions
  = ClientOptions (CommonOptions (Inet.CommonOptions ()))

defaultConnectOptions :: Record ConnectOptions
defaultConnectOptions = defaultClientOptions $ defaultCommonOptions $ Inet.defaultCommonOptions {}

data OptionToMaybe
  = OptionToMaybe

derive instance eqOptionToMaybe :: Eq OptionToMaybe

instance convertOption_OptionToMaybeMode :: ConvertOption OptionToMaybe "mode" a a where
  convertOption _ _ val = val
else instance convertOption_OptionToMaybe :: ConvertOption OptionToMaybe sym (Maybe a) (Maybe a) where
  convertOption _ _ val = val
else instance convertOption_OptionToMaybe2 :: ConvertOption OptionToMaybe sym a (Maybe a) where
  convertOption _ _ val = Just val

connectOptions ::
  forall options.
  ConvertOptionsWithDefaults OptionToMaybe (Record ConnectOptions) options (Record ConnectOptions) =>
  options -> Record ConnectOptions
connectOptions options = convertOptionsWithDefaults OptionToMaybe defaultConnectOptions options

type ForcedOptions r
  = ( mode :: Inet.SocketMode
    | r
    )

forcedOptions :: Record (ForcedOptions ())
forcedOptions =
  { mode: Inet.BinaryData
  }

connectPassive ::
  forall options.
  Row.Lacks "active" options =>
  Row.Union (ForcedOptions ()) options (ForcedOptions options) =>
  Row.Nub (ForcedOptions options) (ForcedOptions options) =>
  ConvertOptionsWithDefaults OptionToMaybe (Record ConnectOptions) (Record (ForcedOptions options)) (Record (ForcedOptions ConnectOptions)) =>
  ConnectAddress -> Port -> Record options -> Timeout -> Effect (Either ConnectError (SslSocket PassiveSocket ConnectedSocket))
connectPassive address port options timeout = do
  let
    addressErl = toErl address

    forced = Record.disjointUnion forcedOptions options

    merged = convertOptionsWithDefaults OptionToMaybe defaultConnectOptions forced

    optionsErl = optionsToErl merged { active = Just Inet.Passive }
  liftEffect $ connectImpl (errorToLeft <<< connectErrorToPurs) Right addressErl port optionsErl (toErl timeout)

close :: forall socketType socketMessageBehaviour. SslSocket socketMessageBehaviour socketType -> Effect Unit
close = closeImpl

recv :: forall socketMessageBehaviour. SslSocket socketMessageBehaviour ConnectedSocket -> NonNegInt -> Timeout -> Effect (Either ActiveError Binary)
recv socket length timeout = recvImpl (errorToLeft <<< activeErrorToPurs) Right socket length (toErl timeout)

send :: forall socketMessageBehaviour. SslSocket socketMessageBehaviour ConnectedSocket -> IOData -> Effect (Either SendError Unit)
send = sendImpl (errorToLeft <<< sendErrorToPurs) Right

errorToLeft :: forall a b. Maybe a -> Either a b
errorToLeft = Left <<< fromMaybe' (\_ -> unsafeCrashWith "invalidError")

------------------------------------------------------------------------------
-- FFI
foreign import connectImpl ::
  forall socketMessageBehaviour.
  (Foreign -> Either ConnectError (SslSocket socketMessageBehaviour ConnectedSocket)) ->
  ((SslSocket socketMessageBehaviour ConnectedSocket) -> Either ConnectError (SslSocket socketMessageBehaviour ConnectedSocket)) ->
  Foreign ->
  Int ->
  List Foreign ->
  Foreign ->
  Effect (Either ConnectError (SslSocket socketMessageBehaviour ConnectedSocket))

foreign import closeImpl ::
  forall socketType socketMessageBehaviour.
  SslSocket socketMessageBehaviour socketType -> Effect Unit

foreign import recvImpl ::
  forall socketMessageBehaviour.
  (Foreign -> Either ActiveError Binary) ->
  (Binary -> Either ActiveError Binary) ->
  SslSocket socketMessageBehaviour ConnectedSocket ->
  NonNegInt ->
  Foreign ->
  Effect (Either ActiveError Binary)

foreign import sendImpl ::
  forall socketMessageBehaviour.
  (Foreign -> Either SendError Unit) ->
  (Unit -> Either SendError Unit) ->
  SslSocket socketMessageBehaviour ConnectedSocket ->
  IOData ->
  Effect (Either SendError Unit)
