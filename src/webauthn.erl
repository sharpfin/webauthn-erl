-module(webauthn).

-export([
    challenge/0,
    register_response/4,
    sign_response/7
]).

-define(CURVE, secp256r1).
-define(ALGORITHM, ecdsa).
-define(DIGEST, sha256).

%%====================================================================
%% API functions
%%====================================================================

%% challenge()
%%  Returns a new challenge (32 random bytes in URL safe Base64 encoding).

-spec challenge() -> binary().
challenge() ->
    Random = crypto:strong_rand_bytes(32),
    base64url:encode(Random).

%% register_response(ClientDataBase64, RegDataBase64, Challenge, Origin)
%%  Validates registration response and returns the public key and key handle.

-spec register_response(binary(), binary(), binary(), binary()) ->
    {ok, binary(), binary()} | {error, validation_failed | wrong_signature | unsupported_key }.
register_response(ClientDataBase64, RegDataBase64, Challenge, Origin) ->
    try
        ClientData = parse_client_data(ClientDataBase64),
        ok = validate_client_data(ClientData, <<"webauthn.create">>, Challenge, Origin),

        {PublicKey, CredentialId} = parse_reg_data(RegDataBase64),
        {ok, PublicKey, CredentialId}
    catch
        throw:Message ->
            {error, Message}
    end.

%% sign_response(ClientDataBase64, SignatureDataBase64, AuthenicatorData
%%               Challenge, Origin, PubKeyEncoded, Counter)
%%  Validates response and returns the new counter value if the signature is valid.

-spec sign_response(binary(), binary(), binary(), binary(), binary(), binary(), integer()) ->
    {ok, integer()} | {error, validation_failed | wrong_signature | bad_counter}.
sign_response(ClientDataBase64, SignatureDataBase64, AuthenicatorData,
              Challenge, Origin, PubKeyEncoded, Counter) ->
    try
        PubKey = decode_public_key(PubKeyEncoded),

        ClientData = parse_client_data(ClientDataBase64),
        ok = validate_client_data(ClientData, <<"webauthn.get">>, Challenge, Origin),

        DecodedAuthenticatorData = base64url:decode(AuthenicatorData),
        SecurityKeyCounter = verify_counter(DecodedAuthenticatorData, Counter),

        ClientDataHash = crypto:hash(?DIGEST, base64url:decode(ClientDataBase64)),
        DataToVerify = <<DecodedAuthenticatorData/bytes, ClientDataHash/bytes>>,

        SignatureData = base64url:decode(SignatureDataBase64),

        case crypto:verify(?ALGORITHM, ?DIGEST, DataToVerify, SignatureData, PubKey) of
            true ->
                {ok, SecurityKeyCounter};
            false ->
                throw(wrong_signature)
        end
    catch
        throw:Message ->
            {error, Message}
    end.

%%====================================================================
%% Internal functions
%%====================================================================

validate_client_data({Type, Challenge, Origin}, Type, Challenge, Origin) ->
    ok;
validate_client_data(_, _, _, _) ->
    throw(validation_failed).

verify_counter(AuthenicatorData, PreviousCounter) ->
    <<_:33/bytes, BinaryCounter:4/bytes, _/bytes>> = AuthenicatorData,
    SecurityKeyCounter = binary:decode_unsigned(BinaryCounter, big),
    case SecurityKeyCounter > PreviousCounter of
        true ->
            SecurityKeyCounter;
        false ->
            throw(bad_counter)
    end.

parse_client_data(Base64Data) ->
    ClientData = base64url:decode(Base64Data),
    Properties = json:decode(ClientData),

    Type = maps:get(<<"type">>, Properties),
    Challenge = maps:get(<<"challenge">>, Properties),
    Origin = maps:get(<<"origin">>, Properties),

    {Type, Challenge, Origin}.

parse_reg_data(Base64Data) ->
    CborData = base64url:decode(Base64Data),
    Map = cbor:decode(CborData),

    AuthData = maps:get(<<"authData">>, Map),
    <<_:53/bytes, CredentialLength0:2/bytes, Rest/bytes>> = AuthData,

    CredentialLength = binary:decode_unsigned(CredentialLength0, big),
    <<CredentialId:CredentialLength/bytes, PublicKey0/bytes>> = Rest,

    {base64url:encode(PublicKey0), base64url:encode(CredentialId)}.

decode_public_key(Base64PublicKey) ->
    CborPublicKey = base64url:decode(Base64PublicKey),
    CosePublicKey = cbor:decode(CborPublicKey),

    {X, Y} = read_cose_key(CosePublicKey),

    [
      <<4, X/bytes, Y/bytes>>,
      ?CURVE
    ].

read_cose_key(#{1 := 2, 3 := -7, -1 := 1, -2 := X, -3 := Y}) ->
    {X, Y};
read_cose_key(_) ->
    throw(unsupported_key).
