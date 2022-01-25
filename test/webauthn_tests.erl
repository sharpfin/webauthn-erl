-module(webauthn_tests).

-include_lib("eunit/include/eunit.hrl").

-define(REG_CLI_DATA,
    <<"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRG1YZG1tV2p",
      "ZWUlkS3prb2UtWlhRNWNObkszaUJ1MjFEeHhlVXFBVjdHSSIsIm9yaWdpbiI6Im",
      "h0dHBzOi8vbG9jYWwuYXBwLnNoYXJwZmluLnRlY2giLCJjcm9zc09yaWdpbiI6Z",
      "mFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29t",
      "cGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHR",
      "wczovL2dvby5nbC95YWJQZXgifQ">>).

-define(REG_DATA,
    <<"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEJSjJ4TKepmj53_lUIK1FZUv",
      "oIomXn7OdhxWvmaMrxu5BAAAABAAAAAAAAAAAAAAAAAAAAAAAQFy1Byym6mQzxH",
      "pfm-Nnpa6BJ80PtM9WKPucvJVANJ4D_h8i9OzpaPgzRrvVcBb7s9r2c8NWzu8Cc",
      "CNJoT7ExdSlAQIDJiABIVgguivC2bowAR7RyUk8ZG9Dp5aNqC0nc2UHXFmz0O1A",
      "058iWCCeO6Yj6Shx38HMgD4Rr6j1F7KmAaxyiEUJngoJG3tfRg">>).

-define(REG_CHALLENGE, <<"DmXdmmWjYYIdKzkoe-ZXQ5cNnK3iBu21DxxeUqAV7GI">>).

-define(SIGN_CLI_DATA,
    <<"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiVlRVbnNJejN1ZUpLVXUtcDRBWkJkc0ljbGZIRExKZTc3VUdqTE53T1ZIcyIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWwuYXBwLnNoYXJwZmluLnRlY2giLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ">>).

-define(SIGN_DATA,
    <<"MEYCIQDz35Wb-vlHbufRYHHw3SkuV4AUJ1cVCC2QMgLkz50ULgIhALsi8x9Db24bkh0dq4KSO0HRMmSw8wsOzpSEMxfOmfgE">>).

-define(SIGN_CHALLENGE, <<"VTUnsIz3ueJKUu-p4AZBdsIclfHDLJe77UGjLNwOVHs">>).

-define(ORIGIN, <<"https://local.app.sharpfin.tech">>).

-define(KEY_HANDLE,
    <<"XLUHLKbqZDPEel-b42elroEnzQ-0z1Yo-5y8lUA0ngP-HyL07Olo",
      "-DNGu9VwFvuz2vZzw1bO7wJwI0mhPsTF1A">>).

-define(AUTHENTICATOR_DATA, <<"JSjJ4TKepmj53_lUIK1FZUvoIomXn7OdhxWvmaMrxu4BAAAADA">>).

register_response_ok_test() ->
    ClientData = ?REG_CLI_DATA,
    RegData = ?REG_DATA,
    Challenge = ?REG_CHALLENGE,
    Origin = ?ORIGIN,
    KeyHandle = ?KEY_HANDLE,

    {ok, _, KH} = webauthn:register_response(ClientData, RegData, Challenge, Origin),
    ?assertEqual(KeyHandle, KH).

register_response_wrong_origin_test() ->
    ClientData = ?REG_CLI_DATA,
    RegData = ?REG_DATA,
    Challenge = ?REG_CHALLENGE,
    Origin = <<"https://wrong">>,
    ?assertEqual({error, validation_failed},
                 webauthn:register_response(ClientData, RegData, Challenge, Origin)).

register_response_wrong_challenge_test() ->
    ClientData = ?REG_CLI_DATA,
    RegData = ?REG_DATA,
    Challenge = <<"VW8J11BJMOLFbly_uoQ089PuB3EX5sdyiljX34ooBlq">>,
    Origin = ?ORIGIN,
    ?assertEqual({error, validation_failed},
                webauthn:register_response(ClientData, RegData, Challenge, Origin)).

register_response_wrong_type_test() ->
    ClientDataJson = <<"{\"type\":\"navigator.id.wrong\",",
                       "\"challenge\":\"VW8J11BJMOLFbly_uoQ089PuB3EX5sdyiljX34ooBlQ\","
                       "\"origin\":\"https://local.app.sharpfin.tech\"}">>,
    ClientDataBase64 = base64url:encode(ClientDataJson),
    RegData = ?REG_DATA,
    Challenge = ?REG_CHALLENGE,
    Origin = ?ORIGIN,
    ?assertEqual({error, validation_failed},
                    webauthn:register_response(ClientDataBase64, RegData, Challenge, Origin)).

register_response_wrong_client_data_test() ->
    ClientDataJson = <<"{\"challenge\":\"VW8J11BJMOLFbly_uoQ089PuB3EX5sdyiljX34ooBlQ\","
                       "\"origin\":\"https://localhost\",\"cid_pubkey\":\"\"}">>,
    ClientDataBase64 = base64url:encode(ClientDataJson),
    RegData = ?REG_DATA,
    Challenge = ?REG_CHALLENGE,
    Origin = ?ORIGIN,
    ?assertError({badkey, <<"type">>},
                    webauthn:register_response(ClientDataBase64, RegData, Challenge, Origin)).

sign_response_ok_test() ->
    Origin = ?ORIGIN,

    RegClientData = ?REG_CLI_DATA,
    RegData = ?REG_DATA,
    RegChallenge = ?REG_CHALLENGE,
    {ok, PubKey, _} = webauthn:register_response(RegClientData, RegData, RegChallenge, Origin),

    Challenge = ?SIGN_CHALLENGE,
    ClientData = ?SIGN_CLI_DATA,
    SignData = ?SIGN_DATA,
    AuthenticatorData = ?AUTHENTICATOR_DATA,

    ?assertEqual({ok, 12},
                webauthn:sign_response(ClientData, SignData, AuthenticatorData, Challenge, Origin, PubKey, 0)).

sign_response_bad_counter_test() ->
    Origin = ?ORIGIN,

    RegClientData = ?REG_CLI_DATA,
    RegData = ?REG_DATA,
    RegChallenge = ?REG_CHALLENGE,
    {ok, PubKey, _} = webauthn:register_response(RegClientData, RegData, RegChallenge, Origin),

    Challenge = ?SIGN_CHALLENGE,
    ClientData = ?SIGN_CLI_DATA,
    SignData = ?SIGN_DATA,
    AuthenticatorData = ?AUTHENTICATOR_DATA,

    ?assertEqual({error, bad_counter},
                webauthn:sign_response(ClientData, SignData, AuthenticatorData, Challenge, Origin, PubKey, 1000)).