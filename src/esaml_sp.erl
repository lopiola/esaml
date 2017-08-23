%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% @doc SAML Service Provider (SP) routines
-module(esaml_sp).

-include("esaml.hrl").
-include_lib("xmerl/include/xmerl.hrl").

-export([generate_authn_request/2, generate_metadata/1]).
-export([validate_assertion/3]).
-export([generate_logout_request/3, generate_logout_response/3]).
-export([validate_logout_request/2, validate_logout_response/2]).

-type xml() :: #xmlElement{} | #xmlDocument{}.
-type dupe_fun() :: fun((esaml:assertion(), Digest :: binary()) -> ok | term()).
-export_type([dupe_fun/0]).

%% @private
-spec add_xml_id(xml()) -> xml().
add_xml_id(Xml) ->
    Xml#xmlElement{attributes = Xml#xmlElement.attributes ++ [
        #xmlAttribute{name = 'ID',
            value = esaml_util:unique_id(),
            namespace = #xmlNamespace{}}
    ]}.

%% @doc Return an AuthnRequest as an XML element
-spec generate_authn_request(IdpURL :: string(), esaml:sp()) -> #xmlElement{}.
generate_authn_request(IdpURL, SP = #esaml_sp{entity_id = EntityId, consume_uri = ConsumeURI}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),

    Xml = esaml:to_xml(#esaml_authnreq{issue_instant = Stamp,
        destination = IdpURL,
        issuer = EntityId,
        consumer_location = ConsumeURI}),
    if SP#esaml_sp.sign_requests ->
        xmerl_dsig:sign(Xml, SP#esaml_sp.key, SP#esaml_sp.certificate);
        true ->
            add_xml_id(Xml)
    end.

%% @doc Return a LogoutRequest as an XML element
-spec generate_logout_request(IdpURL :: string(), NameID :: string(), esaml:sp()) -> #xmlElement{}.
generate_logout_request(IdpURL, NameID, SP = #esaml_sp{metadata_uri = MetaURI}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),

    Xml = esaml:to_xml(#esaml_logoutreq{issue_instant = Stamp,
        destination = IdpURL,
        issuer = MetaURI,
        name = NameID,
        reason = user}),
    if SP#esaml_sp.sign_requests ->
        xmerl_dsig:sign(Xml, SP#esaml_sp.key, SP#esaml_sp.certificate);
        true ->
            add_xml_id(Xml)
    end.

%% @doc Return a LogoutResponse as an XML element
-spec generate_logout_response(IdpURL :: string(), esaml:status_code(), esaml:sp()) -> #xmlElement{}.
generate_logout_response(IdpURL, Status, SP = #esaml_sp{metadata_uri = MetaURI}) ->
    Now = erlang:localtime_to_universaltime(erlang:localtime()),
    Stamp = esaml_util:datetime_to_saml(Now),

    Xml = esaml:to_xml(#esaml_logoutresp{issue_instant = Stamp,
        destination = IdpURL,
        issuer = MetaURI,
        status = Status}),
    if SP#esaml_sp.sign_requests ->
        xmerl_dsig:sign(Xml, SP#esaml_sp.key, SP#esaml_sp.certificate);
        true ->
            add_xml_id(Xml)
    end.

%% @doc Return the SP metadata as an XML element
-spec generate_metadata(esaml:sp()) -> #xmlElement{}.
generate_metadata(#esaml_sp{} = SP) ->
    Xml = esaml:get_sp_metadata(SP),
    case SP#esaml_sp.sign_metadata of
        true ->
            xmerl_dsig:sign(Xml, SP#esaml_sp.key, SP#esaml_sp.certificate);
        false ->
            add_xml_id(Xml)
    end.

%% @doc Validate and parse a LogoutRequest element
-spec validate_logout_request(xml(), esaml:sp()) ->
    {ok, esaml:logoutreq()} | {error, Reason :: term()}.
validate_logout_request(Xml, SP = #esaml_sp{}) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
        {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],


    % @TODO currently logout request is not supported, below issues should be
    % sorted out when it is.

    % @todo this should be configurable
    IDPSignsLogoutRequests = false,
    % @todo IDP record should be passed to this function so we can get the FPs
    Fingerprints = any,

    esaml_util:threaduntil([
        fun(X) ->
            case xmerl_xpath:string("/samlp:LogoutRequest", X, [{namespace, Ns}]) of
                [#xmlElement{}] -> X;
                _ -> {error, bad_assertion}
            end
        end,
        fun(X) ->
            if IDPSignsLogoutRequests ->
                case xmerl_dsig:verify(X, Fingerprints) of
                    ok -> X;
                    OuterError -> {error, OuterError}
                end;
                true -> X
            end
        end,
        fun(X) ->
            case (catch esaml:decode_logout_request(X)) of
                {ok, LR} -> LR;
                {'EXIT', Reason} -> {error, Reason};
                Err -> Err
            end
        end
    ], Xml).

%% @doc Validate and parse a LogoutResponse element
-spec validate_logout_response(xml(), esaml:sp()) ->
    {ok, esaml:logoutresp()} | {error, Reason :: term()}.
validate_logout_response(Xml, SP = #esaml_sp{}) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
        {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'},
        {"ds", 'http://www.w3.org/2000/09/xmldsig#'}],

    % @TODO currently logout response is not supported, below issues should be
    % sorted out when it is.

    % @todo IDP record should be passed to this function so we can get the FPs
    Fingerprints = any,

    esaml_util:threaduntil([
        fun(X) ->
            case xmerl_xpath:string("/samlp:LogoutResponse", X, [{namespace, Ns}]) of
                [#xmlElement{}] -> X;
                _ -> {error, bad_assertion}
            end
        end,
        fun(X) ->
            % Signature is optional on the logout_response. Verify it if we have it.
            case xmerl_xpath:string("/samlp:LogoutResponse/ds:Signature", X, [{namespace, Ns}]) of
                [#xmlElement{}] ->
                    case xmerl_dsig:verify(X, Fingerprints) of
                        ok -> X;
                        OuterError -> {error, OuterError}
                    end;
                _ -> X
            end
        end,
        fun(X) ->
            case (catch esaml:decode_logout_response(X)) of
                {ok, LR} -> LR;
                {'EXIT', Reason} -> {error, Reason};
                Err -> Err
            end
        end,
        fun(LR = #esaml_logoutresp{status = success}) -> LR;
            (#esaml_logoutresp{status = S}) -> {error, S} end
    ], Xml).


-spec get_encrypted_assertion(Xml :: [#xmlElement{}], #esaml_sp{}) -> #xmlElement{}.
get_encrypted_assertion(Xml, #esaml_sp{key = PrivKey}) ->
    Ns = [
        {"samlp", "urn:oasis:names:tc:SAML:2.0:protocol"},
        {"saml", "urn:oasis:names:tc:SAML:2.0:assertion"},
        {"xenc", "http://www.w3.org/2001/04/xmlenc#"},
        {"ds", "http://www.w3.org/2000/09/xmldsig#"}
    ],
    EncMethodXML = xmerl_xpath:string("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:EncryptionMethod", Xml, [{namespace, Ns}]),
    true = lists:member(get_attr_value(EncMethodXML, 'Algorithm'), [
        "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
        "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
    ]),

    % TODO verify if the same as our cert
%%    EncCert = get_text(xmerl_xpath:string("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/ds:KeyInfo/ds:X509Data/ds:X509Certificate", Xml, [{namespace, Ns}])),

    KeyCipherValueB64 = get_text(xmerl_xpath:string("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue", Xml, [{namespace, Ns}])),
    KeyCipherValue = base64:decode(KeyCipherValueB64),

    EncAssCipherTextB64 = get_text(xmerl_xpath:string("/samlp:Response/saml:EncryptedAssertion/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue", Xml, [{namespace, Ns}])),
    EncAssCipherText = base64:decode(EncAssCipherTextB64),

    AESKey = public_key:decrypt_private(KeyCipherValue, PrivKey, [{rsa_pad, rsa_pkcs1_oaep_padding}]),

    Assertion = aes_cbc_decrypt(EncAssCipherText, AESKey),
    {AssertionXml, _} = xmerl_scan:string(binary_to_list(Assertion), [{namespace_conformant, true}]),
    [Res] = xmerl_xpath:string("/saml:Assertion", AssertionXml, [{namespace, Ns}]),
    Res.

%% @doc Validate and decode an assertion envelope in parsed XML
%%
%% The dupe_fun argument is intended to detect duplicate assertions
%% in the case of a replay attack.
-spec validate_assertion(xml(), dupe_fun(), esaml:sp()) ->
    {ok, esaml:assertion()} | {error, Reason :: term()}.
validate_assertion(Xml, SP = #esaml_sp{}, IdP = #esaml_idp{}) ->
    Ns = [{"samlp", 'urn:oasis:names:tc:SAML:2.0:protocol'},
        {"saml", 'urn:oasis:names:tc:SAML:2.0:assertion'}],

    #esaml_idp{
        trusted_fingerprints = IdPTrustedFPs,
        % TODO use this option to decide if we should look for Assertion or EncryptedAssertion
        % and log sensible error when it is not present.
        encrypts_assertions = IdpEncryptsAssertions,
        signs_assertions = IdPSignsAssertions,
        signs_envelopes = IDPSignsEnvelopes
    } = IdP,

    esaml_util:threaduntil([
        fun(X) ->
            case xmerl_xpath:string("/samlp:Response/saml:Assertion", X, [{namespace, Ns}]) of
                [] ->
                    case xmerl_xpath:string("/samlp:Response/saml:EncryptedAssertion", X, [{namespace, Ns}]) of
                        [] ->
                            {error, bad_assertion};
                        _ ->
                            % TODO maybe pass just the EncryptedAssertion node
                            get_encrypted_assertion(Xml, SP)
                    end;
                [A] ->
                    A
            end
        end,
        fun(A) ->
            if IDPSignsEnvelopes ->
                case xmerl_dsig:verify(Xml, IdPTrustedFPs) of
                    ok -> A;
                    OuterError -> {error, {envelope, OuterError}}
                end;
                true -> A
            end
        end,
        fun(A) ->
            if IdPSignsAssertions ->
                case xmerl_dsig:verify(A, IdPTrustedFPs) of
                    ok -> A;
                    InnerError -> {error, {assertion, InnerError}}
                end;
                true -> A
            end
        end,
        fun(A) ->
            case esaml:validate_assertion(A, SP#esaml_sp.consume_uri, SP#esaml_sp.entity_id) of
                {ok, AR} -> AR;
                {error, Reason} -> {error, Reason}
            end
        end
    ], Xml).


% Retrieves text value from #xmlElement{}
-spec get_text(#xmlElement{} | [#xmlElement{}]) -> binary().
get_text([XmlElement]) ->
    get_text(XmlElement);
get_text(#xmlElement{content = [#xmlText{value = Val}]}) ->
    Val.


% Retrieves attribute value from #xmlElement{}
-spec get_attr_value(#xmlElement{} | [#xmlElement{}], atom()) -> binary().
get_attr_value([XmlElement], AttrName) ->
    get_attr_value(XmlElement, AttrName);
get_attr_value(#xmlElement{attributes = Nodes}, AttrName) ->
    case lists:keyfind('Algorithm', 2, Nodes) of
        false ->
            throw({attr_not_found, AttrName});
        #xmlAttribute{value = Val} ->
            Val
    end.

% Decrypts AES CBC encrypted text. crypto will pick desired algorithm
% (AES-CBC-128 or AES-CBC-256) based on key length.
-spec aes_cbc_decrypt(CipherTextWithPadding :: binary(), AESKey :: binary()) ->
    binary().
aes_cbc_decrypt(<<IVec:16/binary, CipherText/binary>>, AESKey) ->
    DecryptPadded = crypto:block_decrypt(aes_cbc, AESKey, IVec, CipherText),
    unpad_aes_cbc(DecryptPadded).


% Removes padding from AES CBC decrypted text
-spec unpad_aes_cbc(binary()) -> binary().
unpad_aes_cbc(B) ->
    Size = size(B),
    {_, B2} = split_binary(B, Size - 1),
    [Pad] = binary_to_list(B2),
    Len = case Pad of
        0 ->
            %% the entire last block is padding
            Size - 16;
        _ ->
            Size - Pad
    end,
    {Bfinal, _} = split_binary(B, Len),
    Bfinal.


-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

-endif.