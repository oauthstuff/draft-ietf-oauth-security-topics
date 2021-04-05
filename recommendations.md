# Recommendations {#recommendations}
    
This section describes the set of security mechanisms the OAuth
working group recommends to OAuth implementers.

## Protecting Redirect-Based Flows {#rec_redirect}

When comparing client redirect URIs against pre-registered URIs, authorization
servers MUST utilize exact string matching except for port numbers in
`localhost` redirection URIs of native apps, see (#iuv_countermeasures). This
measure contributes to the prevention of leakage of authorization codes and
access tokens (see (#insufficient_uri_validation)). It can also help to detect
mix-up attacks (see (#mix_up)).

Clients and AS MUST NOT expose URLs that forward the user’s browser to
arbitrary URIs obtained from a query parameter ("open redirector").
Open redirectors can enable exfiltration of authorization codes and
access tokens, see (#open_redirector_on_client).

Clients MUST prevent Cross-Site Request Forgery (CSRF). In this
context, CSRF refers to requests to the redirection endpoint that do
not originate at the authorization server, but a malicious third party
(see Section 4.4.1.8. of [@RFC6819] for details). Clients that have
ensured that the authorization server supports PKCE [@RFC7636] MAY
rely the CSRF protection provided by PKCE. In OpenID Connect flows,
the `nonce` parameter provides CSRF protection. Otherwise, one-time
use CSRF tokens carried in the `state` parameter that are securely
bound to the user agent MUST be used for CSRF protection (see
(#csrf_countermeasures)).
        
When an OAuth client can interact with more than one authorization server, a
defense against mix-up attacks (see (#mix_up)) is REQUIRED. To this end, clients
SHOULD 

  * use the `iss` parameter as a countermeasure according to
    [@draft-ietf-oauth-iss-auth-resp], or 
  * use an alternative countermeasure based on an `iss` value in the
    authorization response (such as the `iss` Claim in the ID Token in
    [@!OpenID] or in [@JARM] responses), processing it as described in
    [@draft-ietf-oauth-iss-auth-resp].

In the absence of these options, clients MAY instead use distinct redirect URIs
to identify authorization endpoints and token endpoints, as described in
(#mixupcountermeasures).

An AS that redirects a request potentially containing user credentials
MUST avoid forwarding these user credentials accidentally (see
(#redirect_307) for details).


### Authorization Code Grant {#ac}

Clients MUST prevent injection (replay) of authorization codes into the
authorization response by attackers. Public clients MUST use PKCE [@!RFC7636] to
this end. For confidential clients, the use of PKCE [@!RFC7636] is RECOMMENDED.
With additional precautions, described in (#nonce_as_injection_protection),
confidential clients MAY use the OpenID Connect `nonce` parameter and the
respective Claim in the ID Token [@!OpenID] instead. In any case, the PKCE
challenge or OpenID Connect `nonce` MUST be transaction-specific and securely
bound to the client and the user agent in which the transaction was started.

Note: Although PKCE was designed as a mechanism to protect native
apps, this advice applies to all kinds of OAuth clients, including web
applications.

When using PKCE, clients SHOULD use PKCE code challenge methods that
do not expose the PKCE verifier in the authorization request.
Otherwise, attackers that can read the authorization request (cf.
Attacker A4 in (#secmodel)) can break the security provided
by PKCE. Currently, `S256` is the only such method.

Authorization servers MUST support PKCE [@!RFC7636].

Authorization servers MUST provide a way to detect their support for
PKCE. It is RECOMMENDED for AS to publish the element
`code_challenge_methods_supported` in their AS metadata ([@!RFC8414])
containing the supported PKCE challenge methods (which can be used by
the client to detect PKCE support). AS MAY instead provide a
deployment-specific way to ensure or determine PKCE support by the AS.

Authorization servers MUST mitigate PKCE Downgrade Attacks by ensuring that a
token request containing a `code_verifier` parameter is accepted only if a
`code_challenge` parameter was present in the authorization request, see
(#pkce_downgrade_countermeasures) for details.

### Implicit Grant
    
The implicit grant (response type "token") and other response types
causing the authorization server to issue access tokens in the
authorization response are vulnerable to access token leakage and
access token replay as described in (#insufficient_uri_validation),
(#credential_leakage_referrer), (#browser_history), and
(#access_token_injection).
    
Moreover, no viable mechanism exists to cryptographically bind access
tokens issued in the authorization response to a certain client as it
is recommended in (#token_replay_prevention). This makes replay
detection for such access tokens at resource servers impossible.
    
In order to avoid these issues, clients SHOULD NOT use the implicit
grant (response type "token") or other response types issuing
access tokens in the authorization response, unless access token injection
in the authorization response is prevented and the aforementioned token leakage
vectors are mitigated.

Clients SHOULD instead use the response type "code" (aka authorization
code grant type) as specified in (#ac) or any other response type that
causes the authorization server to issue access tokens in the token
response, such as the "code id\_token" response type. This allows the
authorization server to detect replay attempts by attackers and
generally reduces the attack surface since access tokens are not
exposed in URLs. It also allows the authorization server to
sender-constrain the issued tokens (see next section).

## Token Replay Prevention {#token_replay_prevention}

### Access Tokens
 
A sender-constrained access token scopes the applicability of an access
token to a certain sender. This sender is obliged to demonstrate knowledge
of a certain secret as prerequisite for the acceptance of that token at
the recipient (e.g., a resource server).

Authorization and resource servers SHOULD use mechanisms for
sender-constraining access tokens to prevent token replay, such as
Mutual TLS for OAuth 2.0 [@!RFC8705] (see (#pop_tokens)).

### Refresh Tokens

Refresh tokens MUST be sender-constrained or use refresh token
rotation as described in (#refresh_token_protection).


## Access Token Privilege Restriction

The privileges associated with an access token SHOULD be restricted to
the minimum required for the particular application or use case. This
prevents clients from exceeding the privileges authorized by the
resource owner. It also prevents users from exceeding their privileges
authorized by the respective security policy. Privilege restrictions
also help to reduce the impact of access token leakage.

In particular, access tokens SHOULD be restricted to certain resource
servers (audience restriction), preferably to a single resource
server. To put this into effect, the authorization server associates
the access token with certain resource servers and every resource
server is obliged to verify, for every request, whether the access
token sent with that request was meant to be used for that particular
resource server. If not, the resource server MUST refuse to serve the
respective request. Clients and authorization servers MAY utilize the
parameters `scope` or `resource` as specified in [@!RFC6749] and
[@I-D.ietf-oauth-resource-indicators], respectively, to determine the
resource server they want to access.

Additionally, access tokens SHOULD be restricted to certain resources
and actions on resource servers or resources. To put this into effect,
the authorization server associates the access token with the
respective resource and actions and every resource server is obliged
to verify, for every request, whether the access token sent with that
request was meant to be used for that particular action on the
particular resource. If not, the resource server must refuse to serve
the respective request. Clients and authorization servers MAY utilize
the parameter `scope` as specified in [@!RFC6749] and `authorization_details` as specified in [@I-D.ietf-oauth-rar] to determine those
resources and/or actions.

## Resource Owner Password Credentials Grant

The resource owner password credentials grant MUST NOT be used. This
grant type insecurely exposes the credentials of the resource owner to
the client. Even if the client is benign, this results in an increased
attack surface (credentials can leak in more places than just the AS)
and users are trained to enter their credentials in places other than
the AS.

Furthermore, adapting the resource owner password credentials grant to
two-factor authentication, authentication with cryptographic
credentials (cf. WebCrypto [@webcrypto], WebAuthn [@webauthn]), and
authentication processes that require multiple steps can be hard or
impossible.


## Client Authentication
Authorization servers SHOULD use client authentication if possible.

It is RECOMMENDED to use asymmetric (public-key based) methods for
client authentication such as mTLS [@!RFC8705] or
`private_key_jwt` [@!OpenID]. When asymmetric methods for client
authentication are used, authorization servers do not need to store
sensitive symmetric keys, making these methods more robust against a
number of attacks.


## Other Recommendations

The use of OAuth Metadata [@!RFC8414] can help to improve the security of OAuth
deployments: 

 * It ensures that security features and other new OAuth features can be enabled
   automatically by compliant software libraries. 
 * It reduces chances for misconfigurations, for example misconfigured endpoint
   URLs (that might belong to an attacker) or misconfigured security features.
 * It can help to facilitate rotation of cryptographic keys and to ensure
   cryptographic agility.

It is therefore RECOMMENDED that AS publish OAuth metadata according to
[@!RFC8414] and that clients make use of this metadata to configure themselves
when available.

Authorization servers SHOULD NOT allow clients to influence their
`client_id` or `sub` value or any other Claim if that can cause
confusion with a genuine resource owner (see (#client_impersonating)).

It is RECOMMENDED to use end-to-end TLS. If TLS
traffic needs to be terminated at an intermediary, refer to
(#tls_terminating) for further security advice.
