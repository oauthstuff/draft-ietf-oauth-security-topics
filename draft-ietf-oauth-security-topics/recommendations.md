# Recommendations {#recommendations}
    
This section describes the set of security mechanisms the OAuth
working group recommendeds to OAuth implementers.

## Protecting Redirect-Based Flows {#rec_redirect}

Authorization servers MUST utilize exact matching of client redirect
URIs against pre-registered URIs. This measure contributes to the
prevention of leakage of authorization codes and access tokens
(depending on the grant type). It also helps to detect mix-up attacks.

Clients SHOULD avoid forwarding the user’s browser to a URI obtained
from a query parameter since such a function could be utilized to
exfiltrate authorization codes and access tokens. If there is a strong
need for this kind of redirects, clients are advised to implement
appropriate countermeasures against open redirection, e.g., as
described by the OWASP [@!owasp].


Clients MUST prevent CSRF and ensure that each authorization response
is only accepted once. One-time use CSRF tokens carried in the `state`
parameter, which are securely bound to the user agent, SHOULD be used
for that purpose.
        

In order to prevent mix-up attacks, clients MUST only process redirect
responses of the OAuth authorization server they sent the respective
request to and from the same user agent this authorization request was
initiated with. Clients MUST memorize which authorization server they
sent an authorization request to and bind this information to the user
agent and ensure any sub-sequent messages are sent to the same
authorization server. Clients SHOULD use AS-specific redirect URIs as
a means to identify the AS a particular response came from.
 

Note: [@!I-D.bradley-oauth-jwt-encoded-state] gives advice on how to
implement CSRF prevention and AS matching using signed JWTs in the
`state` parameter. 

### Authorization Code Grant {#ac}

Clients utilizing the authorization grant type MUST use PKCE
[@!RFC7636] in order to (with the help of the authorization server)
detect and prevent attempts to inject (replay) authorization codes
into the authorization response. The PKCE challenges must be
transaction-specific and securely bound to the user agent in which the
transaction was started. OpenID Connect clients MAY use the `nonce`
parameter of the OpenID Connect authentication request as specified in
[@!OpenID] in conjunction with the corresponding ID Token claim for
the same purpose.

Note: although PKCE so far was recommended as a mechanism to protect
native apps, this advice applies to all kinds of OAuth clients,
including web applications.

Authorization servers MUST bind authorization codes to a certain
client and authenticate it using an appropriate mechanism (e.g. client
credentials or PKCE).

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
grant (response type "token") or any other response type issuing
access tokens in the authorization response, such as "token id\_token"
and "code token id\_token", unless the issued access tokens are
sender-constrained and access token injection in the authorization
response is prevented. 
 
A sender constrained access token scopes the applicability of an access
token to a certain sender. This sender is obliged to demonstrate knowledge
of a certain secret as prerequisite for the acceptance of that token at
the recipient (e.g., a resource server).

Clients SHOULD instead use the response type "code" (aka authorization code
grant type) as specified in (#ac) or any other response type that
causes the authorization server to issue access tokens in the token response.
This allows the authorization server to detect replay attempts and 
generally reduces the attack surface since access tokens are not exposed in URLs. It also allows the authorization server to sender-constrain the issued tokens.

## Token Replay Prevention {#token_replay_prevention}

Authorization servers SHOULD use TLS-based methods for sender constrained access 
tokens as described in  (#pop_tokens), such as token 
binding [@!I-D.ietf-oauth-token-binding] or Mutual TLS for 
OAuth 2.0 [@!I-D.ietf-oauth-mtls] in order to prevent token replay. 
It is also recommended to use end-to-end TLS whenever possible.

## Access Token Privilege Restriction

The privileges associated with an access token SHOULD be restricted to the
minimum required for the particular application or use case. This prevents
clients from exceeding the privileges authorized by the resource owner. It also
prevents users from exceeding their privileges authorized by the respective
security policy. Privilege restrictions also limit the impact of token leakage
although more effective counter-measures are described in 
(#token_replay_prevention).

In particular, access tokens SHOULD be restricted to certain resource servers, 
preferably to a single resource server. To put this into effect, the authorization server
associates the access token with certain resource servers and every resource server 
is obliged to verify for every request, whether the access token sent with that request 
was meant to be used for that particular resource server.  If not, the resource server 
MUST refuse to serve the respective request. Clients and authorization servers MAY 
utilize the parameters 
`scope` or `resource` as 
specified in [@!RFC6749] and 
[@!I-D.ietf-oauth-resource-indicators], respectively, to determine
the resource server they want to access.

Additionally, access tokens SHOULD be restricted to certain resources
and actions on resource servers or resources. To put this into effect,
the authorization server associates the access token with the
respective resource and actions and every resource server is obliged
to verify for every request, whether the access token sent with that
request was meant to be used for that particular action on the
particular resource. If not, the resource server must refuse to serve
the respective request. Clients and authorization servers MAY utilize
the parameter `scope` as specified in [@!RFC6749] to determine those
resources and/or actions.


