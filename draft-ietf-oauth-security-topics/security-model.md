# The OAuth 2.0 Threat Model

OAuth 2.0 aims to ensure that the authorization of a user (with a user
agent) U at an authorization server AS and the subsequent usage of the
access token at the resource server RS is protected at least against
the following threats:

  * (T1) Web Attackers that control an arbitrary number of
    network endpoints (except for U, AS, and RS). Web attackers may
    set up web sites that are visited by U, operate their own user
    agents, participate in the protocol using other user identifiers
    (except for the one of U), etc.
    
    Web attackers may, in particular, operate OAuth clients that are
    registered at AS, and operate their own authorization and resource
    servers that can be used (in parallel) by U.
    
  * (T2) Network Attackers that additionally have full control over
    the network over which protocol participants communicate. They can
    read, manipulate, and spoof messages, unless these messages are
    properly protected by cryptographic methods (e.g., TLS).

These threats conform to the threat model that was used in formal
analysis efforts for OAuth [@!arXiv.1601.01229]. Previous attacks on
OAuth have shown that, ideally, OAuth deployments protect against an
even strong attacker model that implies the following attacks:

<!-- the following cannot always be assumed: PKCE CC Attack -->
  * (T3) The contents of the authorization response can leak to an
    attacker (the attacker can read, but not modify the responses).
    This is motivated by previous open redirector attacks, problems
    existing on mobile operating systems (where different apps can
    register themselves on the same URI), and the fact that URLs are
    often stored/logged by browsers (history), proxy servers, and
    operating systems.
  * (T4) The contents of the authorization request can leak, in the
    same manner, to an attacker.
    
Protection against these further threats cannot be achieved by every
deployment. For example, if confidentiality of the state value is
needed for a secure operation of OAuth (see
XXXXX-LinkToStatePKCEDiscussion-XXXX), this confidentiality is broken
by both assumptions. 
    
<!-- Check if we can/want to include leakage of the auth request here. Could be doable. -->

