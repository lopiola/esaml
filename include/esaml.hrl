%% esaml - SAML for erlang
%%
%% Copyright (c) 2013, Alex Wilson and the University of Queensland
%% All rights reserved.
%%
%% Distributed subject to the terms of the 2-clause BSD license, see
%% the LICENSE file in the root of the distribution.

%% data types / message records

-include_lib("public_key/include/public_key.hrl").

-record(esaml_org, {
    name = "" :: esaml:localized_string(),
    displayname = "" :: esaml:localized_string(),
    url = "" :: esaml:localized_string()}).

-record(esaml_contact, {
    name = "" :: string(),
    email = "" :: string()}).

-record(esaml_sp, {
    entity_id = "" :: string(),
    org = #esaml_org{} :: esaml:org(),
    tech = #esaml_contact{} :: esaml:contact(),
    key :: #'RSAPrivateKey'{} | undefined,
    certificate :: binary() | undefined,
    rollover_new_key :: #'RSAPrivateKey'{} | undefined,
    rollover_new_certificate :: binary() | undefined,
    cert_chain = [] :: [binary()],
    sign_metadata = false :: boolean(),
    sign_requests = false :: boolean(),
    want_assertions_signed = true :: boolean(),
    metadata_uri = "" :: string(),
    consume_uri = "" :: string(),
    logout_uri :: string() | undefined}).

-record(esaml_idp_metadata, {
    org = #esaml_org{} :: esaml:org(),
    tech = #esaml_contact{} :: esaml:contact(),
    signed_requests = true :: boolean(),
    certificate :: binary() | undefined,
    entity_id = "" :: string(),
    redirect_login_location = undefined :: undefined | string(),
    post_login_location = undefined :: undefined | string(),
    logout_location :: string() | undefined,
    name_format = unknown :: esaml:name_format(),
    trusted_fingerprints = [] :: [binary()]
}).

-record(esaml_idp, {
    metadata = undefined :: undefined | #esaml_idp_metadata{},
    preferred_sso_binding = http_redirect :: http_redirect | http_post,
    signs_logout_requests = true :: boolean()
}).

-record(esaml_authnreq, {
    version = "2.0" :: esaml:version(),
    issue_instant = "" :: esaml:datetime(),
    destination = "" :: string(),
    issuer = "" :: string(),
    consumer_location = "" :: string()}).

-record(esaml_subject, {
    name = "" :: string(),
    confirmation_method = bearer :: atom(),
    notonorafter = "" :: esaml:datetime()}).

-record(esaml_assertion, {
    version = "2.0" :: esaml:version(),
    issue_instant = "" :: esaml:datetime(),
    recipient = "" :: string(),
    issuer = "" :: string(),
    subject = #esaml_subject{} :: esaml:subject(),
    conditions = [] :: esaml:conditions(),
    attributes = [] :: proplists:proplist()}).

-record(esaml_logoutreq, {
    version = "2.0" :: esaml:version(),
    issue_instant = "" :: esaml:datetime(),
    destination = "" :: string(),
    issuer = "" :: string(),
    name = "" :: string(),
    reason = user :: esaml:logout_reason()}).

-record(esaml_logoutresp, {
    version = "2.0" :: esaml:version(),
    issue_instant = "" :: esaml:datetime(),
    destination = "" :: string(),
    issuer = "" :: string(),
    status = unknown :: esaml:status_code()}).

-record(esaml_response, {
    version = "2.0" :: esaml:version(),
    issue_instant = "" :: esaml:datetime(),
    destination = "" :: string(),
    issuer = "" :: string(),
    status = unknown :: esaml:status_code(),
    assertion = #esaml_assertion{} :: esaml:assertion()}).
