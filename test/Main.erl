-module(test_main@foreign).

-export([lookupOptionImpl/4, sniOptionImpl/1]).

%% ssl's options are a proplist of {Key, Value} pairs, and optionsToErl builds
%% it as opaque terms. Reaching into it from PureScript would need a decoder
%% for a shape that is erlang's rather than ours, so the lookup lives here.
%%
%% Only a binary value is reported. That is the point of the assertion: a
%% Filename has to arrive as the bytes ssl will hand the OS, not as a wrapper
%% that merely prints like one.
lookupOptionImpl(Just, Nothing, Key, Options) ->
  case lists:keyfind(binary_to_atom(Key), 1, Options) of
    {_, Value} when is_binary(Value) -> Just(Value);
    _ -> Nothing
  end.

sniOptionImpl(Options) ->
  case lists:keyfind(server_name_indication, 1, Options) of
    {_, V} when is_list(V) -> unicode:characters_to_binary(["charlist:", V]);
    {_, V} when is_atom(V) -> <<"atom:", (atom_to_binary(V))/binary>>;
    {_, V} when is_binary(V) -> <<"binary:", V/binary>>;
    false -> <<"absent">>
  end.
