# The Updated OAuth 2.0 Attacker Model

In [@RFC6819], an attacker model was laid out that described the
capabilities of attackers against which OAuth deployments must defend.
In the following, this attacker model is updated to account for the
potentially dynamic relationships involving multiple parties (as
described above), to include new types of attackers, and to define the
attacker model more clearly.

OAuth 2.0 MUST ensure that the authorization of the resource owner
(RO) (with a user agent) at an authorization server (AS) and the
subsequent usage of the access token at the resource server (RS) is
protected at least against the following attackers:

  * (A1) Web Attackers that control an arbitrary number of network
    endpoints (except for the concrete RO, AS, and RS). Web attackers
    may set up web sites that are visited by the RO, operate their own
    user agents, participate in the protocol using their own user
    credentials, etc.
    
    Web attackers may, in particular, operate OAuth clients that are
    registered at AS, and operate their own authorization and resource
    servers that can be used (in parallel) by ROs.
    
    It must also be assumed that web attackers can lure the user to
    open arbitrary attacker-chosen URIs at any time. This can be
    achieved through many ways, for example, by injecting malicious
    advertisements into advertisement networks, or by sending
    legit-looking emails.
    
  * (A2) Network Attackers that additionally have full control over
    the network over which protocol participants communicate. They can
    eavesdrop on, manipulate, and spoof messages, except when these
    are properly protected by cryptographic methods (e.g., TLS).
    Network attackers can also block arbitrary messages.
    
These attackers conform to the attacker model that was used in formal
analysis efforts for OAuth [@arXiv.1601.01229]. This is a minimal
attacker model. Implementers MUST take into account all possible
attackers in the environment in which their OAuth implementations are
expected to run. Previous attacks on OAuth have shown that OAuth
deployments SHOULD in particular consider the following, stronger
attackers:

  * (A3) Attackers that can read, but not modify, the contents of the
    authorization response (i.e., the authorization response can leak
    to an attacker).
    
    Examples for such attacks include open redirector
    attacks, problems existing on mobile operating systems (where
    different apps can register themselves on the same URI), so-called
    mix-up attacks, where the client is tricked into sending
    credentials to a attacker-controlled AS, and the fact that URLs
    are often stored/logged by browsers (history), proxy servers, and
    operating systems.
  * (A4) Attackers that can read, but not modify, the contents of the
    authorization request (i.e., the authorization request can leak,
    in the same manner as above, to an attacker).
  * (A5) Attackers that control a resource server used by RO with
    an access token issued by AS. For example, a resource server can
    be compromised by an attacker, an access token may be sent to an
    attacker-controlled resource server due to a misconfiguration, or
    an RO is social-engineered into using a attacker-controlled RS.
    
Note that in this attacker model, an attacker (see A1) can be a RO or
act as one. For example, an attacker can use his own browser to replay
tokens or authorization codes obtained by any of the attacks described
above at the client or RS.

This document discusses the additional threats resulting from these
attackers in detail and recommends suitable mitigations. Attacks in an
even stronger attacker model are discussed, for example, in
[@arXiv.1901.11520].
    
