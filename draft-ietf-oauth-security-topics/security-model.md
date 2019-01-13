# The Updated OAuth 2.0 Threat Model

In [RFC6819], a threat model was laid out that described the
capabilities of attackers against which OAuth deployments must defend.
In the following, this threat model is updated to account for the
potentially dynamic relationships involving multiple parties (as
described above), to include new threats, and to make it more clearly
defined.

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
    eavesdrop on, manipulate, and spoof messages, escept when these
    are properly protected by cryptographic methods (e.g., TLS).
    Network attacker can also block specific messages.

These threats conform to the threat model that was used in formal
analysis efforts for OAuth [@!arXiv.1601.01229]. Previous attacks on
OAuth have shown that, ideally, OAuth deployments protect against an
even strong attacker model that entails the following threats:

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
    
Protection against T3 and T4 cannot be achieved by every deployment.
For example, if confidentiality of the state value is needed for a
secure operation of OAuth (see XXXXX-LinkToStatePKCEDiscussion-XXXX),
this confidentiality is broken by both assumptions. Nonetheless,
implementors should try to protect against T3 and T4 as far as possible.
    
<!-- Check if we can/want to include leakage of the auth request here. Could be doable. -->
<!-- Check if we want to discuss main properties here? -->
