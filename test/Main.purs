-- | erl-ssl has never had a test suite. It gained one when `certfile`,
-- | `keyfile`, `cacertfile` and `dhfile` changed type: they used to be
-- | `SandboxedPath`, they are now `Filename`, and nothing in this repository
-- | would have noticed if that conversion had stopped working.
-- |
-- | These tests are about the option row rather than about TLS. What they pin
-- | down is the one thing the type change could break -- that a `Filename`
-- | still reaches `ssl:listen/2` as the bytes the OS will open, and that a
-- | field left unset still contributes no option at all.
module Test.Main where

import Prelude

import Control.Monad.Free (Free)
import Data.Maybe (Maybe(..))
import Effect (Effect)
import Erl.Data.Binary (Binary)
import Erl.Data.List (List)
import Erl.Kernel.Filename (filename, filenameToString, parseAbsFile, rawFilename, toFilename)
import Erl.Kernel.Inet (optionsToErl)
import Erl.Ssl (defaultListenOptions)
import Erl.Test.EUnit (TestF, runTests, suite, test)
import Foreign (Foreign)
import Test.Assert (assertEqual)

main :: Effect Unit
main = void $ runTests filenameOptionTests

filenameOptionTests :: Free TestF Unit
filenameOptionTests =
  suite "ssl options carrying a Filename" do
    test "certfile and keyfile reach the option list as their bytes" do
      let
        options =
          optionsToErl defaultListenOptions
            { certfile = filename "/etc/ssl/cert.pem"
            , keyfile = filename "/etc/ssl/key.pem"
            }
      assertEqual
        { actual: lookupOption "certfile" options
        , expected: Just "/etc/ssl/cert.pem"
        }
      assertEqual
        { actual: lookupOption "keyfile" options
        , expected: Just "/etc/ssl/key.pem"
        }

    test "cacertfile and dhfile reach the option list as their bytes" do
      let
        options =
          optionsToErl defaultListenOptions
            { cacertfile = filename "/etc/ssl/ca.pem"
            , dhfile = filename "/etc/ssl/dh.pem"
            }
      assertEqual
        { actual: lookupOption "cacertfile" options
        , expected: Just "/etc/ssl/ca.pem"
        }
      assertEqual
        { actual: lookupOption "dhfile" options
        , expected: Just "/etc/ssl/dh.pem"
        }

    -- Every one of these is a `Maybe`, and a `Nothing` has to vanish rather
    -- than become an empty name: ssl reads `{certfile, <<>>}` as a request to
    -- open "", not as an absent option.
    test "a field left unset contributes no option" do
      let
        options = optionsToErl defaultListenOptions
      assertEqual { actual: lookupOption "certfile" options, expected: Nothing }
      assertEqual { actual: lookupOption "keyfile" options, expected: Nothing }
      assertEqual { actual: lookupOption "cacertfile" options, expected: Nothing }
      assertEqual { actual: lookupOption "dhfile" options, expected: Nothing }

    -- The reason these fields are `Filename` and not `Path Abs File`: a path
    -- is what you compose, a filename is what you hand the runtime. Here the
    -- bridge is crossed at an actual call site rather than in isolation.
    test "a composed path arrives the same way a raw name does" do
      let
        options =
          optionsToErl defaultListenOptions
            { certfile = toFilename <$> parseAbsFile "/etc/ssl/cert.pem" }
      assertEqual
        { actual: lookupOption "certfile" options
        , expected: Just "/etc/ssl/cert.pem"
        }

    -- `..` is rejected at parse time, so there is no Filename to put in the
    -- field and the option is simply absent -- rather than ssl being handed a
    -- traversal that resolves somewhere the caller did not mean.
    test "a path containing .. never becomes an option" do
      let
        traversal = toFilename <$> parseAbsFile "/etc/ssl/../../../etc/shadow"
        options = optionsToErl defaultListenOptions { certfile = traversal }
      assertEqual { actual: filenameToString =<< traversal, expected: Nothing }
      assertEqual { actual: lookupOption "certfile" options, expected: Nothing }

-- | The option list is erlang's shape rather than ours, so the lookup is FFI.
-- | What comes back is the raw value, and reading it as a name is the same
-- | round trip any consumer of `file:list_dir_all/1` makes.
lookupOption :: String -> List Foreign -> Maybe String
lookupOption key options =
  filenameToString <<< rawFilename =<< lookupOptionImpl Just Nothing key options

foreign import lookupOptionImpl
  :: (forall a. a -> Maybe a)
  -> (forall a. Maybe a)
  -> String
  -> List Foreign
  -> Maybe Binary
