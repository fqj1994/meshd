-module(fwd_client).

-behaviour(gen_server).

%% API functions
-export([start_link/0]).

%% gen_server callbacks
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%%%===================================================================
%%% API functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------


init([RemoteHost, RemotePort, {EncryptionMasterKey, AuthenticationKey, InitIV}]) ->
    {ok, Sock} = gen_tcp:connect(RemoteHost, RemotePort, [binary, {packet, 0}, {active, true}]),
    RandKey = crypto:strong_rand_bytes(32),
    gen_tcp:send(Sock, crypto:block_encrypt(aes_ecb, EncryptionMasterKey, RandKey)),
    {ok, #{key=>RandKey, authkey=>AuthenticationKey, socket=>Sock, ivsend=>InitIV, ivrecv=>InitIV, tmpdata=><<>>}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_cast({connect, _RemoteHost, _RemotePort, _DataProcess}, State) ->
    {noreply, State};
handle_cast({send, Data}, State) ->
    #{key := EncKey, authkey := AAD, ivsend := IV, socket := Sock} = State,
    {CipherText, CipherTag} = crypto:block_encrypt(aes_gcm, EncKey, IV, {AAD, Data}),
    Len = size(CipherText),
    gen_tcp:send(Sock, <<Len:4/little-signed-integer-unit:8, CipherText:16/binary, CipherText/binary>>),
    NextIV = crypto:next_iv(aes_cbc, CipherTag),
    {noreply, State#{ivsend => NextIV}};
handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info({tcp, Socket, Data}, State) ->
    #{socket := Socket, tmpdata := Buffer, key := EncKey, authkey := AAD, ivrecv := IV} = State,
    case protocol:parseData(<<Buffer/binary, Data/binary>>) of
        {ok, AuthTag, EncryptedData, Reamaining} ->
            DecryptedData = crypto:block_decrypt(aes_gcm, EncKey, IV, {AAD, EncryptedData, AuthTag}),
            case DecryptedData of
                error ->
                    gen_tcp:close(Socket),
                    {stop, normal, State};
                _ ->
                    NextIV = crypto:next_iv(aes_gcm, AuthTag),
                    {noreply, State#{tmpdata => Reamaining, ivrecv => NextIV}}
            end;
        {insufficient, Data} ->
            {noreply, State#{tmpdata => Data}}
    end;
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
