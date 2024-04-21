# The Updated OAuth 2.0 Attacker Model {#secmodel}

In [@RFC6819], a threat model is laid out that describes the threats against
which OAuth deployments must be protected. While doing so, [@RFC6819] makes
certain assumptions about attackers and their capabilities, i.e., implicitly
establishes an attacker model. In the following, this attacker model is made
explicit and is updated and expanded to account for the potentially dynamic
relationships involving multiple parties (as described in (#Introduction)), to
include new types of attackers and to define the attacker model more clearly.

The goal of this document is to ensure that the authorization of a resource
owner (with a user agent) at an authorization server and the subsequent usage of
the access token at a resource server is protected, as good as practically
possible, at least against the following attackers:

  * (A1) Web Attackers that can set up and operate an arbitrary number of
    network endpoints (besides the "honest" ones) including browsers and
    servers. Web attackers may set up web sites that are visited by the resource
    owner, operate their own user agents, and participate in the protocol.

    Web attackers may, in particular, operate OAuth clients that are registered
    at the authorization server, and operate their own authorization and
    resource servers that can be used (in parallel to the "honest" ones) by the
    resource owner and other resource owners.

    It must also be assumed that web attackers can lure the user to
    navigate their browser to arbitrary attacker-chosen URIs at any time. In practice, this
    can be achieved in many ways, for example, by injecting malicious
    advertisements into advertisement networks, or by sending
    legitimate-looking emails.

    Web attackers can use their own user credentials to create new
    messages as well as any secrets they learned previously. For
    example, if a web attacker learns an authorization code of a user
    through a misconfigured redirect URI, the web attacker can then
    try to redeem that code for an access token.

    They cannot, however, read or manipulate messages that are not
    targeted towards them (e.g., sent to a URL controlled by a
    non-attacker controlled authorization server).

  * (A2) Network Attackers that additionally have full control over
    the network over which protocol participants communicate. They can
    eavesdrop on, manipulate, and spoof messages, except when these
    are properly protected by cryptographic methods (e.g., TLS).
    Network attackers can also block arbitrary messages.

While an example for a web attacker would be a customer of an internet
service provider, network attackers could be the internet service
provider itself, an attacker in a public (Wi-Fi) network using ARP
spoofing, or a state-sponsored attacker with access to internet
exchange points, for instance.

The aforementioned attackers (A1) and (A2) conform to the attacker model that was used in formal analysis
efforts for OAuth [@arXiv.1601.01229]. This is a minimal attacker model.
Implementers MUST take into account all possible types of attackers in the
environment of their OAuth implementations. For example, in [@arXiv.1901.11520],
a very strong attacker model is used that includes attackers that have
full control over the token endpoint. This models effects of a
possible misconfiguration of endpoints in the ecosystem, which can be avoided
by using authorization server metadata as described in (#other_recommendations). Such an attacker is therefore not listed here.

However, previous attacks on OAuth have shown that the following types of
attackers are relevant in particular:

  * (A3) Attackers that can read, but not modify, the contents of the
    authorization response (i.e., the authorization response can leak
    to an attacker).

    Examples for such attacks include open redirector attacks, insufficient
    checking of redirect URIs (see (#insufficient_uri_validation)), problems
    existing on mobile operating systems (where different apps can register
    themselves on the same URI), mix-up attacks (see (#mix_up)), where the
    client is tricked into sending credentials to an attacker-controlled authorization server, and
    the fact that URLs are often stored/logged by browsers (history), proxy
    servers, and operating systems.
  * (A4) Attackers that can read, but not modify, the contents of the
    authorization request (i.e., the authorization request can leak,
    in the same manner as above, to an attacker).
  * (A5) Attackers that can acquire an access token issued by an authorization server. For
    example, a resource server can be compromised by an attacker, an
    access token may be sent to an attacker-controlled resource server
    due to a misconfiguration, or a resource owner is social-engineered into
    using an attacker-controlled resource server. See also (#comp_res_server).

(A3), (A4) and (A5) typically occur together with either (A1) or (A2).
Attackers can collaborate to reach a common goal.

Note that an attacker (A1) or (A2) can be a resource owner or
act as one. For example, such an attacker can use their own browser to replay
tokens or authorization codes obtained by any of the attacks described
above at the client or resource server.

This document focuses on threats resulting from attackers (A1) to (A5).

