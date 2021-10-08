{-
Welcome to a Spago project!
You can edit this file as you like.
-}
{ name = "erl-ssl"
, dependencies =
  [ "convertable-options"
  , "datetime"
  , "effect"
  , "either"
  , "erl-atom"
  , "erl-binary"
  , "erl-kernel"
  , "erl-lists"
  , "erl-logger"
  , "erl-otp-types"
  , "erl-tuples"
  , "foreign"
  , "maybe"
  , "partial"
  , "prelude"
  , "record"
  , "unsafe-reference"
  ]
, packages = ./packages.dhall
, sources = [ "src/**/*.purs" ]
, backend = "purerl"
}
