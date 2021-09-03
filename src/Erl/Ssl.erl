-module (erl_ssl@foreign).

-export([ connectImpl/6
        , recvImpl/5
        , sendImpl/4
        , closeImpl/1
        ]).

connectImpl(Left, Right, Address, Port, Options, Timeout) ->
    fun() ->
            Address2 = if is_binary(Address) -> binary_to_list(Address);
                       true -> Address
                    end,
            case ssl:connect(Address2, Port, Options, Timeout) of
                {ok, Socket} ->
                    Right(Socket);
                {error, Reason} ->
                    Left(Reason)
            end
    end.

recvImpl(Left, Right, Socket, Length, Timeout) ->
    fun() ->
            case ssl:recv(Socket, Length, Timeout) of
                {ok, Packet} ->
                    Right(Packet);
                {error, Reason} ->
                    Left(Reason)
            end
    end.

sendImpl(Left, Right, Socket, Packet) ->
    fun() ->
            case ssl:send(Socket, Packet) of
                ok ->
                    Right(unit);
                {error, Reason} ->
                    Left(Reason)
            end
    end.

closeImpl(Socket) ->
    fun() ->
            _ = ssl:close(Socket),
            unit
    end.