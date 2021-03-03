%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc Utility functions
-module(esaml_util).

-include_lib("xmerl/include/xmerl.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("esaml.hrl").

-define(IDP_CACHE_VALIDITY_SEC, application:get_env(esaml, idp_cache_validity_sec, 3600)).

-export([datetime_to_saml/1, saml_to_datetime/1]).
-export([start_ets/0, check_dupe_ets/2]).
-export([folduntil/3, thread/2, threaduntil/2]).
-export([build_nsinfo/2]).
-export([load_private_key/1, load_certificate_chain/1, load_certificate/1, load_metadata/1]).
-export([unique_id/0]).
-export([base64_decode/1]).

-type fp_hash_type() :: sha | md5 | sha256 | sha384 | sha512.

%% @doc Converts a calendar:datetime() into SAML time string
-spec datetime_to_saml(calendar:datetime()) -> esaml:datetime().
datetime_to_saml(Time) ->
    {{Y, Mo, D}, {H, Mi, S}} = Time,
    lists:flatten(io_lib:format("~4.10.0B-~2.10.0B-~2.10.0BT~2.10.0B:~2.10.0B:~2.10.0BZ", [Y, Mo, D, H, Mi, S])).

%% @doc Converts a SAML time string into a calendar:datetime()
%%
%% Inverse of datetime_to_saml/1
-spec saml_to_datetime(esaml:datetime()) -> calendar:datetime().
saml_to_datetime(Stamp) ->
    StampBin = if is_list(Stamp) -> list_to_binary(Stamp); true -> Stamp end,
    <<YBin:4/binary, "-", MoBin:2/binary, "-", DBin:2/binary, "T",
        HBin:2/binary, ":", MiBin:2/binary, ":", SBin:2/binary, Rest/binary>> = StampBin,
    %% check that time in UTC timezone because we don't handle another timezones properly
    $Z = binary:last(Rest),
    F = fun(B) -> list_to_integer(binary_to_list(B)) end,
    {{F(YBin), F(MoBin), F(DBin)}, {F(HBin), F(MiBin), F(SBin)}}.

%% @private
-spec folduntil(F :: fun(), Acc :: term(), List :: []) -> AccOut :: term().
folduntil(_F, Acc, []) -> Acc;
folduntil(F, Acc, [Next | Rest]) ->
    case F(Next, Acc) of
        {stop, AccOut} -> AccOut;
        NextAcc -> folduntil(F, NextAcc, Rest)
    end.

%% @private
thread([], Acc) -> Acc;
thread([F | Rest], Acc) ->
    thread(Rest, F(Acc)).

%% @private
-spec threaduntil([fun((Acc :: term()) -> {error, term()} | {stop, term()} | term())], InitAcc :: term()) -> {ok, term()} | {error, term()}.
threaduntil([], Acc) -> {ok, Acc};
threaduntil([F | Rest], Acc) ->
    case (catch F(Acc)) of
        {'EXIT', Reason} ->
            {error, Reason};
        {error, Reason} ->
            {error, Reason};
        {stop, LastAcc} ->
            {ok, LastAcc};
        NextAcc ->
            threaduntil(Rest, NextAcc)
    end.

%% @private
-spec build_nsinfo(#xmlNamespace{}, #xmlElement{}) -> #xmlElement{}.
build_nsinfo(Ns, Attr = #xmlAttribute{name = Name}) ->
    case string:tokens(atom_to_list(Name), ":") of
        [NsPrefix, Rest] ->
            Attr#xmlAttribute{namespace = Ns, nsinfo = {NsPrefix, Rest}};
        _ -> Attr#xmlAttribute{namespace = Ns}
    end;
build_nsinfo(Ns, Elem = #xmlElement{name = Name, content = Kids, attributes = Attrs}) ->
    Elem2 = case string:tokens(atom_to_list(Name), ":") of
        [NsPrefix, Rest] ->
            Elem#xmlElement{namespace = Ns, nsinfo = {NsPrefix, Rest}};
        _ -> Elem#xmlElement{namespace = Ns}
    end,
    Elem2#xmlElement{attributes = [build_nsinfo(Ns, Attr) || Attr <- Attrs],
        content = [build_nsinfo(Ns, Kid) || Kid <- Kids]};
build_nsinfo(_Ns, Other) -> Other.

%% @private
start_ets() ->
    {ok, spawn_link(fun() ->
        register(esaml_ets_table_owner, self()),
        ets:new(esaml_assertion_seen, [set, public, named_table]),
        ets:new(esaml_privkey_cache, [set, public, named_table]),
        ets:new(esaml_certbin_cache, [set, public, named_table]),
        ets:new(esaml_idp_meta_cache, [set, public, named_table]),
        ets_table_owner()
    end)}.

%% @private
ets_table_owner() ->
    receive
        stop -> ok;
        _ -> ets_table_owner()
    end.

%% @doc Loads a private key from a file on disk (or ETS memory cache)
-spec load_private_key(Path :: string()) -> #'RSAPrivateKey'{}.
load_private_key(Path) ->
    case ets:lookup(esaml_privkey_cache, Path) of
        [{_, Key}] -> Key;
        _ ->
            {ok, KeyFile} = file:read_file(Path),
            [KeyEntry] = public_key:pem_decode(KeyFile),
            Key = case public_key:pem_entry_decode(KeyEntry) of
                #'PrivateKeyInfo'{privateKey = KeyData} when is_list(KeyData) ->
                    public_key:der_decode('RSAPrivateKey', list_to_binary(KeyData));
                #'PrivateKeyInfo'{privateKey = KeyData} when is_binary(KeyData) ->
                    public_key:der_decode('RSAPrivateKey', KeyData);
                Other -> Other
            end,
            ets:insert(esaml_privkey_cache, {Path, Key}),
            Key
    end.

-spec load_certificate(Path :: string()) -> binary().
load_certificate(CertPath) ->
    [CertBin] = load_certificate_chain(CertPath),
    CertBin.

%% @doc Loads certificate chain from a file on disk (or ETS memory cache)
-spec load_certificate_chain(Path :: string()) -> [binary()].
load_certificate_chain(CertPath) ->
    case ets:lookup(esaml_certbin_cache, CertPath) of
        [{_, CertChain}] -> CertChain;
        _ ->
            {ok, CertFile} = file:read_file(CertPath),
            CertChain = [CertBin || {'Certificate', CertBin, not_encrypted} <- public_key:pem_decode(CertFile)],
            ets:insert(esaml_certbin_cache, {CertPath, CertChain}),
            CertChain
    end.

%% @doc Reads IDP metadata from a URL (or ETS memory cache)
-spec load_metadata(Url :: string()) -> esaml:idp_metadata().
load_metadata(Url) ->
    NotOlderThan = erlang:system_time(seconds) - ?IDP_CACHE_VALIDITY_SEC,
    case ets:lookup(esaml_idp_meta_cache, Url) of
        [{Url, Meta, Timestamp}] when Timestamp >= NotOlderThan ->
            Meta;
        _ ->
            {ok, {{_Ver, 200, _}, _Headers, Body}} = httpc:request(get, {Url, []}, [{autoredirect, true}], []),
            {Xml, _} = xmerl_scan:string(Body, [{namespace_conformant, false}]),
            {ok, Meta = #esaml_idp_metadata{}} = esaml:decode_idp_metadata(Xml),
            ets:insert(esaml_idp_meta_cache, {Url, Meta, erlang:system_time(seconds)}),
            Meta
    end.

%% @doc Checks for a duplicate assertion using ETS tables in memory on all available nodes.
%%
%% This is a helper to be used as a DuplicateFun with esaml_sp:validate_assertion/3.
%% If you aren't using standard erlang distribution for your app, you probably don't
%% want to use this.
-spec check_dupe_ets(esaml:assertion(), Digest :: binary()) -> ok | {error, duplicate_assertion}.
check_dupe_ets(A, Digest) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    NowSecs = calendar:datetime_to_gregorian_seconds(Now),
    DeathSecs = esaml:stale_time(A),
    {ResL, _BadNodes} = rpc:multicall(erlang, apply, [fun() ->
        case (catch ets:lookup(esaml_assertion_seen, Digest)) of
            [{Digest, seen} | _] -> seen;
            _ -> ok
        end
    end, []]),
    case lists:member(seen, ResL) of
        true ->
            {error, duplicate_assertion};
        _ ->
            Until = DeathSecs - NowSecs + 1,
            rpc:multicall(erlang, apply, [fun() ->
                case ets:info(esaml_assertion_seen) of
                    undefined ->
                        Me = self(),
                        Pid = spawn(fun() ->
                            register(esaml_ets_table_owner, self()),
                            ets:new(esaml_assertion_seen, [set, public, named_table]),
                            ets:new(esaml_privkey_cache, [set, public, named_table]),
                            ets:new(esaml_certbin_cache, [set, public, named_table]),
                            ets:insert(esaml_assertion_seen, {Digest, seen}),
                            Me ! {self(), ping},
                            ets_table_owner()
                        end),
                        receive
                            {Pid, ping} -> ok
                        end;
                    _ ->
                        ets:insert(esaml_assertion_seen, {Digest, seen})
                end,
                {ok, _} = timer:apply_after(Until * 1000, erlang, apply, [fun() ->
                    ets:delete(esaml_assertion_seen, Digest)
                end, []])
            end, []]),
            ok
    end.

%% @doc Returns a unique xsd:ID string suitable for SAML use.
-spec unique_id() -> string().
unique_id() ->
    <<R:64>> = crypto:strong_rand_bytes(8),
    T = try
        erlang:system_time() % needs ERTS-7.0
    catch
        error:undef ->
            {Mega, Sec, Micro} = erlang:now(),
            Mega * 1000000 * 1000000 + Sec * 1000000 + Micro
    end,
    lists:flatten(io_lib:format("_~.16b~.16b", [R, T])).

%% @doc Decodes a base64 string, fixing the padding as needed
-spec base64_decode(binary() | iolist()) -> binary().
base64_decode(IOList) when not is_binary(IOList) ->
    base64_decode(iolist_to_binary(IOList));
base64_decode(Binary) ->
    Trimmed = re:replace(Binary, "\\s+", "", [global, {return, binary}]),
    if
        byte_size(Trimmed) rem 4 == 3 ->
            base64:decode(<<Trimmed/binary, "=">>);
        byte_size(Trimmed) rem 4 == 2 ->
            base64:decode(<<Trimmed/binary, "==">>);
        true ->
            base64:decode(Trimmed)
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

datetime_test() ->
    "2013-05-02T17:26:53Z" = datetime_to_saml({{2013, 5, 2}, {17, 26, 53}}),
    {{1990, 11, 23}, {18, 1, 1}} = saml_to_datetime("1990-11-23T18:01:01Z").

build_nsinfo_test() ->
    EmptyNs = #xmlNamespace{},
    FooNs = #xmlNamespace{nodes = [{"foo", 'urn:foo:'}]},

    E1 = #xmlElement{name = 'foo', content = [#xmlText{value = 'bar'}]},
    E1 = build_nsinfo(EmptyNs, E1),

    E2 = #xmlElement{name = 'foo:Blah', content = [#xmlText{value = 'bar'}]},
    E2Ns = E2#xmlElement{nsinfo = {"foo", "Blah"}, namespace = FooNs},
    E2Ns = build_nsinfo(FooNs, E2),

    E3 = #xmlElement{name = 'blah:George', content = [E2]},
    E3Ns = E3#xmlElement{nsinfo = {"blah", "George"}, namespace = FooNs, content = [E2Ns]},
    E3Ns = build_nsinfo(FooNs, E3).

-include("xmerl_xpath_macros.hrl").

-record(b, {name, ctext}).

xpath_attr_test() ->
    {Xml, _} = xmerl_scan:string("<a><b name=\"foo\"><c name=\"bar\">hi</c></b><b name=\"foobar\"><c name=\"foofoo\"></c></b></a>", [{namespace_conformant, true}]),
    Ns = [],
    Fun = ?xpath_attr("/a/b[@name='foo']/c/@name", b, name),
    Rec = Fun(#b{}),
    ?assertMatch(#b{name = "bar"}, Rec),
    Fun2 = ?xpath_attr("/a/b[@name='foobar']/c/@name", b, name),
    Rec2 = Fun2(Rec),
    ?assertMatch(#b{name = "foofoo"}, Rec2),
    Fun3 = ?xpath_attr("/a/b[@name='bar']/c/@name", b, name),
    Rec3 = Fun3(Rec2),
    ?assertMatch(Rec2, Rec3).

xpath_attr_trans_test() ->
    {Xml, _} = xmerl_scan:string("<a><b name=\"foo\"><c name=\"bar\">hi</c></b><b name=\"foobar\"><c name=\"foofoo\"></c></b></a>", [{namespace_conformant, true}]),
    Ns = [],
    Fun = ?xpath_attr("/a/b[@name='foobar']/c/@name", b, name, fun(X) ->
        list_to_atom(X) end),
    Rec = Fun(#b{}),
    ?assertMatch(#b{name = foofoo}, Rec).

xpath_text_test() ->
    {Xml, _} = xmerl_scan:string("<a><b name=\"foo\"><c name=\"bar\">hi</c></b><b name=\"foobar\"><c name=\"foofoo\"></c></b></a>", [{namespace_conformant, true}]),
    Ns = [],
    Fun = ?xpath_text("/a/b[@name='foo']/c/text()", b, ctext),
    Rec = Fun(#b{}),
    ?assertMatch(#b{ctext = "hi"}, Rec),
    Fun2 = ?xpath_text("/a/b[@name='foobar']/c/text()", b, ctext),
    Rec2 = Fun2(Rec),
    ?assertMatch(Rec, Rec2),
    Fun3 = ?xpath_text("/a/b[@name='bar']/c/text()", b, name),
    Rec3 = Fun3(Rec2),
    ?assertMatch(Rec2, Rec3).

base64_decode_test() ->
    D = fun base64_decode/1,
    ?assertEqual(<<"test">>, D(<<"dGVzdA==">>)),
    ?assertEqual(<<"test">>, D(<<"dGVzdA=">>)),
    ?assertEqual(<<"test">>, D(<<"dGVzdA">>)),
    ?assertEqual(<<"test">>, D(<<"dGVz\tdA">>)),
    ?assertEqual(<<"test">>, D(<<"\nd\nGV\r\t\nz\td\nA==">>)),
    ?assertEqual(<<"test">>, D(<<"\nd\nGV\r\t\nz\td\nA=">>)),
    ?assertEqual(<<"test">>, D(<<"\nd\nGV\r\t\nz\td\nA">>)),
    ?assertEqual(<<"test">>, D(<<"dGV zd A= =">>)),
    ?assertEqual(<<"test">>, D(<<"   dGV zdA= ">>)),
    ?assertEqual(<<"test">>, D(<<"d  G  Vz dA ">>)),
    ?assertEqual(<<"test">>, D(<<"dGVz \t dA  ">>)),
    ?assertEqual(<<"test">>, D(<<"\nd\n  GV\r \t\nz \td \nA=     =">>)),
    ?assertEqual(<<"test">>, D(<<"\n  d\nGV \r\t\nz\td\nA =">>)),
    ?assertEqual(<<"test">>, D(<<"\n d\nGV\r \t\nz\td\n  A">>)),
    ProblematicCert = <<"\nMIIKiTCCCXGgAwIBAgIMIQIs49RuQE5CmJx2MA0GCSqGSIb3DQEBCwUAMIGNMQsw\nCQYDVQQGEwJERTFFMEMGA1UECgw8VmVyZWluIHp1ciBGb2VyZGVydW5nIGVpbmVz\nIERldXRzY2hlbiBGb3JzY2h1bmdzbmV0emVzIGUuIFYuMRAwDgYDVQQLDAdERk4t\nUEtJMSUwIwYDVQQDDBxERk4tVmVyZWluIEdsb2JhbCBJc3N1aW5nIENBMB4XDTE5\nMDUyMDEzNDUwN1oXDTIxMDgyMTEzNDUwN1owezELMAkGA1UEBhMCREUxEDAOBgNV\nBAgMB0hhbWJ1cmcxEDAOBgNVBAcMB0hhbWJ1cmcxLjAsBgNVBAoMJURldXRzY2hl\ncyBFbGVrdHJvbmVuLVN5bmNocm90cm9uIERFU1kxGDAWBgNVBAMMD2l0LWlkcDEu\nZGVzeS5kZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKSvMgaZYA7z\nvdk1c2zdF5ZtKjRIEFROj4+0+8GFmiD0CuzJulOeMzZvj1AuzrBgnhb//d+O5MXo\nW76gw7nB8IRxykhGjXgEHGhH1tPeALIg8luzTs9Dg2WVTk2ksFbyNtBSLk18DFQe\nGbEHVqzaNQZDt7UTp1/ZLfAEqq/y8uVY6qWt1m4b0N7qVbjKputa/7rtaqzEbVI+\nI9OZ7G7Vi5ngm356Auo5rq2Px0efSEtpzFXdvcD5huFh7dTLasjKkn8rULyOP3hG\nTT9x9QDSa4v8NzhCmNX65o3FWEmS9SicTAduzYpayQXzT7jD2fNdDCPZIIUtCnbX\nB8ejQKGw4wHwIhfpRt/0F1xFr3mvvFgEwa0aRb7huBgHB5M02lKKTqeTEOU6lhvZ\ncDnD8xVSaxBoLCqNyLfjoDKcyrTDypiVd0hxDRRslCTPqPkpPSv0TPNphdx7rzmS\nVfsqUN8+3op/jcwgos6m+Cq8fi/GmwP+4ddVKYrLDrC4MkcwwK49b0mYFJTpKw2T\nDInXAAoCxHSqai4zFSoOr/hvDYIcuYtyBo03WOTIaa3dEjcDKz28OjiVP6S8fxTf\nnu7ZApOlO7NmxdvPUCFagVykSgx0fE4vBGkntFo/cqop0IfBaLusX6ATuEOvdykE\nmvLEbXZlSWDmhqrJ5cqSrpqHiilwy/LpAgMBAAGjggX4MIIF9DBXBgNVHSAEUDBO\nMAgGBmeBDAECAjANBgsrBgEEAYGtIYIsHjAPBg0rBgEEAYGtIYIsAQEEMBAGDisG\nAQQBga0hgiwBAQQEMBAGDisGAQQBga0hgiwCAQQEMAkGA1UdEwQCMAAwDgYDVR0P\nAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4E\nFgQUVlwbb+Cqc52uzJAiNifZYKr/ul8wHwYDVR0jBBgwFoAUazqYi/nyU4na4K2y\nMh4JH+iqO3QwTQYDVR0RBEYwRIILaWRwLmRlc3kuZGWCD2l0LWlkcDEuZGVzeS5k\nZYIPd3d3LmlkcC5kZXN5LmRlghN3d3cuaXQtaWRwMS5kZXN5LmRlMIGNBgNVHR8E\ngYUwgYIwP6A9oDuGOWh0dHA6Ly9jZHAxLnBjYS5kZm4uZGUvZGZuLWNhLWdsb2Jh\nbC1nMi9wdWIvY3JsL2NhY3JsLmNybDA/oD2gO4Y5aHR0cDovL2NkcDIucGNhLmRm\nbi5kZS9kZm4tY2EtZ2xvYmFsLWcyL3B1Yi9jcmwvY2FjcmwuY3JsMIHbBggrBgEF\nBQcBAQSBzjCByzAzBggrBgEFBQcwAYYnaHR0cDovL29jc3AucGNhLmRmbi5kZS9P\nQ1NQLVNlcnZlci9PQ1NQMEkGCCsGAQUFBzAChj1odHRwOi8vY2RwMS5wY2EuZGZu\nLmRlL2Rmbi1jYS1nbG9iYWwtZzIvcHViL2NhY2VydC9jYWNlcnQuY3J0MEkGCCsG\nAQUFBzAChj1odHRwOi8vY2RwMi5wY2EuZGZuLmRlL2Rmbi1jYS1nbG9iYWwtZzIv\ncHViL2NhY2VydC9jYWNlcnQuY3J0MIIDYAYKKwYBBAHWeQIEAgSCA1AEggNMA0oA\ndwBvU3asMfAxGdiZAKRRFf93FRwR2QLBACkGjbIImjfZEwAAAWrVfTZrAAAEAwBI\nMEYCIQD0mmStkmh+Z4ksxcRcbp2LwgQDTpv9YWER1KqCdgzK8wIhAJpy8oV921cT\naDdlr8EfDnPng8/pkG1W1TBEdvn7IZfTAHcAVYHUwhaQNgFK6gubVzxT8MDkOHhw\nJQgXL6OqHQcT0wwAAAFq1X03awAABAMASDBGAiEAlVOnHwpBu46PiMTAA3/4cFcd\nT0L8S8BnDRDKhrr9o5oCIQCSM/tCfTpJVsQVifdSVy0l7jFjzmTwZK65qBoAfxy2\nZwB2AKrnC388uNVmyGwvFpecn0RfaasOtFNVibL3egMBBPPNAAABatV9NlUAAAQD\nAEcwRQIgN/3vNtrmIq2CZGYIZ0lps4iAnUfsOXvDC5v//2rIxeUCIQDudMLT7xaz\nKtkqgA9+8Mdk0MF5ES89MvQGq5NVDGZMfgB2AKS5CZC0GFgUh7sTosxncAo8NZgE\n+RvfuON3zQ7IDdwQAAABatV9NrgAAAQDAEcwRQIgHqMj/L6hec2Ak8CoOhUVYiDj\niAEnuCIB3wpEdkyKO1sCIQD55kh3loGJTbnXGNz8gmhh970OK83uojQUFbXKxlOG\nVgB3AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABatV9NqgAAAQD\nAEgwRgIhAIh9VdYT3nha5G8Pwx6yqoZhR7dHWvqyErcY14ASsR8dAiEAr7MYiJXR\ndrANan/2KCe/6vYNi1Y7IQSefq5O1i/SQOAAdQC72d+8H4pxtZOUI5eqkntHOFeV\nCqtS6BqQlmQ2jh7RhQAAAWrVfTaiAAAEAwBGMEQCIGNcYlth/yWhkrO5hAvuoOKt\nWE8CfYLwnburP7rEmPjaAiBr8/dSYdmFwi1uTnc6e37rMPRtDs56Y570HBxSjWjf\n0wB2AESUZS6w7s6vxEAH2Kj+KMDa5oK+2MsxtT/TM5a1toGoAAABatV9OxgAAAQD\nAEcwRQIhANanNRnso0tne9t1tfW9dsp0OnSKQ5EvMai2ylHTXejZAiAlI4i3EgoN\nCT3ly72Alt068nqKYJh/K8j0U5oEW6qLpzANBgkqhkiG9w0BAQsFAAOCAQEASjk6\nTb661ffLGAAfjrDCGzPO7oeZEU5/OdS+uDCKnzRFjAforTkN8C062/0ij+etyAtE\nsxmjNDEaMLwik1M7pMcMv69R1FPoa6yNY+H1Dd+N1riLBTGoHvQSVxRohy0ILcvb\n3OcNZ4cHVqNZuswrwcG9qpyRKRRGcnfR0sM/53NhApuL5RkwO2qsr9z9aeIJaFCT\nJ8wTqCAkm+VulzGYrfx0IxvLmOTL1aYrRXBv5BlJFIl6AAyraxWYYnSuVR9k7sUO\nn0x55YgdfBDUnx27ZqxMbMOlmBUYKhQupNyPhLjphNJAJ5b7kcmNdOBmfWXAow1G\nKNtQ1LpWqdS41Y38Ag=\n\t\t\t">>,
    ProblematicCertNoWhitespace = <<"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">>,
    ProblematicCertFixedPadding = <<"\nMIIKiTCCCXGgAwIBAgIMIQIs49RuQE5CmJx2MA0GCSqGSIb3DQEBCwUAMIGNMQsw\nCQYDVQQGEwJERTFFMEMGA1UECgw8VmVyZWluIHp1ciBGb2VyZGVydW5nIGVpbmVz\nIERldXRzY2hlbiBGb3JzY2h1bmdzbmV0emVzIGUuIFYuMRAwDgYDVQQLDAdERk4t\nUEtJMSUwIwYDVQQDDBxERk4tVmVyZWluIEdsb2JhbCBJc3N1aW5nIENBMB4XDTE5\nMDUyMDEzNDUwN1oXDTIxMDgyMTEzNDUwN1owezELMAkGA1UEBhMCREUxEDAOBgNV\nBAgMB0hhbWJ1cmcxEDAOBgNVBAcMB0hhbWJ1cmcxLjAsBgNVBAoMJURldXRzY2hl\ncyBFbGVrdHJvbmVuLVN5bmNocm90cm9uIERFU1kxGDAWBgNVBAMMD2l0LWlkcDEu\nZGVzeS5kZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKSvMgaZYA7z\nvdk1c2zdF5ZtKjRIEFROj4+0+8GFmiD0CuzJulOeMzZvj1AuzrBgnhb//d+O5MXo\nW76gw7nB8IRxykhGjXgEHGhH1tPeALIg8luzTs9Dg2WVTk2ksFbyNtBSLk18DFQe\nGbEHVqzaNQZDt7UTp1/ZLfAEqq/y8uVY6qWt1m4b0N7qVbjKputa/7rtaqzEbVI+\nI9OZ7G7Vi5ngm356Auo5rq2Px0efSEtpzFXdvcD5huFh7dTLasjKkn8rULyOP3hG\nTT9x9QDSa4v8NzhCmNX65o3FWEmS9SicTAduzYpayQXzT7jD2fNdDCPZIIUtCnbX\nB8ejQKGw4wHwIhfpRt/0F1xFr3mvvFgEwa0aRb7huBgHB5M02lKKTqeTEOU6lhvZ\ncDnD8xVSaxBoLCqNyLfjoDKcyrTDypiVd0hxDRRslCTPqPkpPSv0TPNphdx7rzmS\nVfsqUN8+3op/jcwgos6m+Cq8fi/GmwP+4ddVKYrLDrC4MkcwwK49b0mYFJTpKw2T\nDInXAAoCxHSqai4zFSoOr/hvDYIcuYtyBo03WOTIaa3dEjcDKz28OjiVP6S8fxTf\nnu7ZApOlO7NmxdvPUCFagVykSgx0fE4vBGkntFo/cqop0IfBaLusX6ATuEOvdykE\nmvLEbXZlSWDmhqrJ5cqSrpqHiilwy/LpAgMBAAGjggX4MIIF9DBXBgNVHSAEUDBO\nMAgGBmeBDAECAjANBgsrBgEEAYGtIYIsHjAPBg0rBgEEAYGtIYIsAQEEMBAGDisG\nAQQBga0hgiwBAQQEMBAGDisGAQQBga0hgiwCAQQEMAkGA1UdEwQCMAAwDgYDVR0P\nAQH/BAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATAdBgNVHQ4E\nFgQUVlwbb+Cqc52uzJAiNifZYKr/ul8wHwYDVR0jBBgwFoAUazqYi/nyU4na4K2y\nMh4JH+iqO3QwTQYDVR0RBEYwRIILaWRwLmRlc3kuZGWCD2l0LWlkcDEuZGVzeS5k\nZYIPd3d3LmlkcC5kZXN5LmRlghN3d3cuaXQtaWRwMS5kZXN5LmRlMIGNBgNVHR8E\ngYUwgYIwP6A9oDuGOWh0dHA6Ly9jZHAxLnBjYS5kZm4uZGUvZGZuLWNhLWdsb2Jh\nbC1nMi9wdWIvY3JsL2NhY3JsLmNybDA/oD2gO4Y5aHR0cDovL2NkcDIucGNhLmRm\nbi5kZS9kZm4tY2EtZ2xvYmFsLWcyL3B1Yi9jcmwvY2FjcmwuY3JsMIHbBggrBgEF\nBQcBAQSBzjCByzAzBggrBgEFBQcwAYYnaHR0cDovL29jc3AucGNhLmRmbi5kZS9P\nQ1NQLVNlcnZlci9PQ1NQMEkGCCsGAQUFBzAChj1odHRwOi8vY2RwMS5wY2EuZGZu\nLmRlL2Rmbi1jYS1nbG9iYWwtZzIvcHViL2NhY2VydC9jYWNlcnQuY3J0MEkGCCsG\nAQUFBzAChj1odHRwOi8vY2RwMi5wY2EuZGZuLmRlL2Rmbi1jYS1nbG9iYWwtZzIv\ncHViL2NhY2VydC9jYWNlcnQuY3J0MIIDYAYKKwYBBAHWeQIEAgSCA1AEggNMA0oA\ndwBvU3asMfAxGdiZAKRRFf93FRwR2QLBACkGjbIImjfZEwAAAWrVfTZrAAAEAwBI\nMEYCIQD0mmStkmh+Z4ksxcRcbp2LwgQDTpv9YWER1KqCdgzK8wIhAJpy8oV921cT\naDdlr8EfDnPng8/pkG1W1TBEdvn7IZfTAHcAVYHUwhaQNgFK6gubVzxT8MDkOHhw\nJQgXL6OqHQcT0wwAAAFq1X03awAABAMASDBGAiEAlVOnHwpBu46PiMTAA3/4cFcd\nT0L8S8BnDRDKhrr9o5oCIQCSM/tCfTpJVsQVifdSVy0l7jFjzmTwZK65qBoAfxy2\nZwB2AKrnC388uNVmyGwvFpecn0RfaasOtFNVibL3egMBBPPNAAABatV9NlUAAAQD\nAEcwRQIgN/3vNtrmIq2CZGYIZ0lps4iAnUfsOXvDC5v//2rIxeUCIQDudMLT7xaz\nKtkqgA9+8Mdk0MF5ES89MvQGq5NVDGZMfgB2AKS5CZC0GFgUh7sTosxncAo8NZgE\n+RvfuON3zQ7IDdwQAAABatV9NrgAAAQDAEcwRQIgHqMj/L6hec2Ak8CoOhUVYiDj\niAEnuCIB3wpEdkyKO1sCIQD55kh3loGJTbnXGNz8gmhh970OK83uojQUFbXKxlOG\nVgB3AO5Lvbd1zmC64UJpH6vhnmajD35fsHLYgwDEe4l6qP3LAAABatV9NqgAAAQD\nAEgwRgIhAIh9VdYT3nha5G8Pwx6yqoZhR7dHWvqyErcY14ASsR8dAiEAr7MYiJXR\ndrANan/2KCe/6vYNi1Y7IQSefq5O1i/SQOAAdQC72d+8H4pxtZOUI5eqkntHOFeV\nCqtS6BqQlmQ2jh7RhQAAAWrVfTaiAAAEAwBGMEQCIGNcYlth/yWhkrO5hAvuoOKt\nWE8CfYLwnburP7rEmPjaAiBr8/dSYdmFwi1uTnc6e37rMPRtDs56Y570HBxSjWjf\n0wB2AESUZS6w7s6vxEAH2Kj+KMDa5oK+2MsxtT/TM5a1toGoAAABatV9OxgAAAQD\nAEcwRQIhANanNRnso0tne9t1tfW9dsp0OnSKQ5EvMai2ylHTXejZAiAlI4i3EgoN\nCT3ly72Alt068nqKYJh/K8j0U5oEW6qLpzANBgkqhkiG9w0BAQsFAAOCAQEASjk6\nTb661ffLGAAfjrDCGzPO7oeZEU5/OdS+uDCKnzRFjAforTkN8C062/0ij+etyAtE\nsxmjNDEaMLwik1M7pMcMv69R1FPoa6yNY+H1Dd+N1riLBTGoHvQSVxRohy0ILcvb\n3OcNZ4cHVqNZuswrwcG9qpyRKRRGcnfR0sM/53NhApuL5RkwO2qsr9z9aeIJaFCT\nJ8wTqCAkm+VulzGYrfx0IxvLmOTL1aYrRXBv5BlJFIl6AAyraxWYYnSuVR9k7sUO\nn0x55YgdfBDUnx27ZqxMbMOlmBUYKhQupNyPhLjphNJAJ5b7kcmNdOBmfWXAow1G\nKNtQ1LpWqdS41Y38Ag==\n\t\t\t">>,
    ProblematicCertFixedPaddingNoWhitespace = <<"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">>,
    ?assertEqual(D(ProblematicCert), D(ProblematicCertNoWhitespace)),
    ?assertEqual(D(ProblematicCert), D(ProblematicCertFixedPadding)),
    ?assertEqual(D(ProblematicCert), D(ProblematicCertFixedPaddingNoWhitespace)).

-endif.
