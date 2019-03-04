# The Updated OAuth 2.0 Threat Model

In [RFC6819], a threat model was laid out that described the
capabilities of attackers against which OAuth deployments must defend.
In the following, this threat model is updated to account for the
potentially dynamic relationships involving multiple parties (as
described above), to include new threats, and to make it more clearly
defined.

OAuth 2.0 aims to ensure that the authorization of the resource owner (RO) (with a user
agent) at an authorization server (AS) and the subsequent usage of the
access token at the resource server (RS) is protected at least against
the following threats:

  * (T1) Web Attackers that control an arbitrary number of network
    endpoints (except for RO, AS, and RS). Web attackers may set up
    web sites that are visited by the RO, operate their own user
    agents, participate in the protocol using their own user
    credentials, etc.
    
    Web attackers may, in particular, operate OAuth clients that are
    registered at AS, and operate their own authorization and resource
    servers that can be used (in parallel) by ROs.
    
    It must also be assumed that web attackers can lure the user to
    open arbitrary attacker-chosen URIs at any time. This can be
    achieved through many ways, for example, by injecting malicious
    advertisements into advertisement networks, or by sending
    legit-looking emails.
    
  * (T2) Network Attackers that additionally have full control over
    the network over which protocol participants communicate. They can
    eavesdrop on, manipulate, and spoof messages, except when these
    are properly protected by cryptographic methods (e.g., TLS).
    Network attacker can also block specific messages.
    
These threats conform to the threat model that was used in formal
analysis efforts for OAuth [@!arXiv.1601.01229]. Previous attacks on
OAuth have shown that, ideally, OAuth deployments protect against an
even strong attacker model that is described by the following threats:

  * (T3) The contents of the authorization response can leak to an
    attacker (the attacker can read, but not modify the responses).
    
    Examples for such attacks include open redirector
    attacks, problems existing on mobile operating systems (where
    different apps can register themselves on the same URI), so-called
    mix-up attacks, where the client is tricked into sending
    credentials to a attacker-controlled AS, and the fact that URLs
    are often stored/logged by browsers (history), proxy servers, and
    operating systems.
  * (T4) The contents of the authorization request can leak, in the
    same manner, to an attacker.
  * (T5) An access token may be sent to an attacker-controlled
    resource server (for example, due to a misconfiguration or if an
    RO is tricked into using a attacker-controlled RS).
    
Note that in this threat model, an attacker can be a RP or act as one
(see T1). For example, an attacker can use his own browser to replay
tokens or authorization codes obtained by any of the attacks described
above at the client or RS.
    
This document discusses these additional threats in detail and
recommends suitable mitigations.
    
