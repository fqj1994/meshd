-module(protocol).
-export([gen_master_key/1, parseData/1]).


hashn(Method, Text, From, To, 0) ->
    Length = To - From,
    <<_:From/binary, X:Length/binary, _/binary>> = crypto:hash(Method, Text),
    X;
hashn(Method, Text, From, To, Cnt) when Cnt > 0 ->
    Length = To - From,
    <<_:From/binary, X:Length/binary, _/binary>> = crypto:hash(Method, Text),
    hashn(Method, X, From, To, Cnt - 1).


gen_master_key(Password) ->
    {hashn(sha256, Password, 0, 32, 1024), hashn(sha512, Password, 32, 64, 1024), hashn(sha256, Password, 0, 16, 1024)}.


parseData(<<Len:4/little-signed-integer-unit:8, AuthTag:16/binary, EncryptedData/binary>> = Data) ->
    if
        Len < 0 ->
            disconnected;
        size(EncryptedData) >= Len ->
            <<RealEncryptedData:Len/binary, Reamaining/binary>> = EncryptedData,
            {ok, AuthTag, RealEncryptedData, Reamaining};
        true ->
            {insufficient, Data}
    end;
parseData(Data) ->
    {insufficient, Data}.
