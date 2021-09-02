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
  , "maybe"
  , "erl-atom"
  , "erl-binary"
  , "erl-lists"
  , "erl-kernel"
  , "erl-tuples"
  , "erl-logger"
  , "erl-otp-types"
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

