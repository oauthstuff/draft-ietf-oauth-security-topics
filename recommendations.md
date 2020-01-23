# Recommendations {#recommendations}
    
This section describes the set of security mechanisms the OAuth
working group recommends to OAuth implementers.

## Protecting Redirect-Based Flows {#rec_redirect}

Authorization servers MUST utilize exact matching of client redirect
URIs against pre-registered URIs. This measure contributes to the
prevention of leakage of authorization codes and access tokens
(depending on the grant type). It can also help to detect mix-up attacks
(see below).

Clients SHOULD avoid forwarding the user’s browser to a URI obtained
from a query parameter ("open redirector") since such a function can enable
exfiltration of authorization codes and access tokens. If there is a strong
need for this kind of redirect, clients are advised to implement
appropriate countermeasures against open redirection, e.g., as
described by OWASP [@owasp_redir].


Clients MUST prevent Cross-Site Request Forgery (CSRF). In this
context, CSRF refers to redirections to the redirection endpoint that
do not originate at the authorization server, but a malicious third
party (see Section 4.4.1.8. of [@RFC6819] for details). One-time use
CSRF tokens carried in the `state` parameter that are securely bound
to the user agent SHOULD be used for that purpose. Alternatively, if
PKCE [@RFC7636] is used by the client and the client has ensured that
the authorization server supports PKCE, the client MAY opt to not use
`state` for CSRF protection, as such protection is provided by PKCE.
In this case, `state` MAY be used again for its original purpose,
namely transporting data about the application state of the client
(see (#csrf_countermeasures)).
        
        
In order to prevent mix-up attacks, clients MUST only process redirect
responses of the authorization server they sent the respective request
to and from the same user agent this authorization request was
initiated with. Clients MUST store the authorization server they sent
an authorization request to and bind this information to the user
agent and ensure that the subsequent token request, if applicable, is
sent to the same authorization server. Clients SHOULD use distinct
redirect URIs for each authorization server as a means to identify the
authorization server a particular response came from.

An AS that redirects a request potentially containing user credentials
MUST avoid forwarding these user credentials accidentally (see
(#redirect_307) for details).


### Authorization Code Grant {#ac}

Clients utilizing the authorization code grant type MUST use PKCE
[@!RFC7636] or the OpenID Connect `nonce` parameter and ID Token Claim
[@!OpenID] to detect and prevent attempts to inject (replay)
authorization codes into the authorization response by an attacker.
The PKCE challenge or OpenID Connect `nonce` must be
transaction-specific and securely bound to the client and the user
agent in which the transaction was started.

Note: although PKCE so far was recommended as a mechanism to protect
native apps, this advice applies to all kinds of OAuth clients,
including web applications.

When using PKCE, clients SHOULD use PKCE code challenge methods that
do not expose the PKCE verifier in the authorization request.
Otherwise, attackers that can read the authorization request (cf.
Attacker A4 in (#secmodel)) can trivially break the security provided
by PKCE. Currently, `S256` is the only such method.

Authorization servers MUST support PKCE [@!RFC7636].

Authorization servers MUST provide a way to detect their support for
PKCE. To this end, they MUST either (a) publish the element
`code_challenge_methods_supported` in their AS metadata ([@!RFC8418])
containing the supported PKCE challenge methods (which can be used by
the client to detect PKCE support) or (b) provide a
deployment-specific way to ensure or determine PKCE support by the AS.

Authorization servers SHOULD furthermore consider the recommendations
given in [@!RFC6819], Section 4.4.1.1, on authorization code replay
prevention.

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
 
A sender-constrained access token scopes the applicability of an access
token to a certain sender. This sender is obliged to demonstrate knowledge
of a certain secret as prerequisite for the acceptance of that token at
the recipient (e.g., a resource server).

Authorization servers SHOULD use mechanisms for sender-constrained
access tokens as described in (#pop_tokens), such as Mutual TLS for
OAuth 2.0 [@I-D.ietf-oauth-mtls], in order to prevent token replay.
Refresh tokens MUST be sender-constrained or use refresh token
rotation as described in (#refresh_token_protection).

It is RECOMMENDED to use end-to-end TLS. If TLS
traffic needs to be terminated at an intermediary, refer to
(#tls_terminating) for further security advice.

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
Authorization servers SHOULD use client authentication.

It is RECOMMENDED to use asymmetric (public-key based) methods for
client authentication such as mTLS [@I-D.ietf-oauth-mtls] or
`private_key_jwt` [@!OpenID]. When asymmetric methods for client
authentication are used, authorization servers do not need to store
sensitive symmetric keys, making these methods more robust against a
number of attacks.


## Other Recommendations

Authorization servers SHOULD NOT allow clients to influence their
`client_id` or `sub` value or any other claim that might cause
confusion with a genuine resource owner (see (#client_impersonating)).
