# The Updated OAuth 2.0 Attacker Model {#secmodel}

In [@RFC6819], an attacker model is laid out that describes the
capabilities of attackers against which OAuth deployments must be
protected. In the following, this attacker model is updated to account
for the potentially dynamic relationships involving multiple parties
(as described in (#Introduction)), to include new types of attackers and to define
the attacker model more clearly.

OAuth MUST ensure that the authorization of the resource owner (RO)
(with a user agent) at the authorization server (AS) and the subsequent
usage of the access token at the resource server (RS) is protected at
least against the following attackers:

  * (A1) Web Attackers that can set up and operate an arbitrary number
    of network endpoints including browsers and servers (except for
    the concrete RO, AS, and RS). Web attackers may set up web sites
    that are visited by the RO, operate their own user agents, and
    participate in the protocol. 
    
    Web attackers may, in particular, operate OAuth clients that are
    registered at AS, and operate their own authorization and resource
    servers that can be used (in parallel) by the RO and other
    resource owners.
    
    It must also be assumed that web attackers can lure the user to
    open arbitrary attacker-chosen URIs at any time. In practice, this
    can be achieved in many ways, for example, by injecting malicious
    advertisements into advertisement networks, or by sending
    legit-looking emails.
    
    Web attackers can use their own user credentials to create new
    messages as well as any secrets they learned previously. For
    example, if a web attacker learns an authorization code of a user
    through a misconfigured redirect URI, the web attacker can then
    try to redeem that code for an access token.
    
    They cannot, however, read or manipulate messages that are not
    targeted towards them (e.g., sent to a URL controlled by a
    non-attacker controlled AS).
    
  * (A2) Network Attackers that additionally have full control over
    the network over which protocol participants communicate. They can
    eavesdrop on, manipulate, and spoof messages, except when these
    are properly protected by cryptographic methods (e.g., TLS).
    Network attackers can also block arbitrary messages.
    
While an example for a web attacker would be a customer of an internet
service provider, network attackers could be the internet service
provider itself, an attacker in a public (wifi) network using ARP
spoofing, or a state-sponsored attacker with access to internet
exchange points, for instance.
    
These attackers conform to the attacker model that was used in formal analysis
efforts for OAuth [@arXiv.1601.01229]. This is a minimal attacker model.
Implementers MUST take into account all possible types of attackers in the
environment in which their OAuth implementations are expected to run. Previous
attacks on OAuth have shown that OAuth deployments SHOULD in particular consider
the following, stronger attackers in addition to those listed above:

  * (A3) Attackers that can read, but not modify, the contents of the
    authorization response (i.e., the authorization response can leak
    to an attacker).
    
    Examples for such attacks include open redirector attacks, insufficient
    checking of redirect URIs (see (#insufficient_uri_validation)), problems
    existing on mobile operating systems (where different apps can register
    themselves on the same URI), mix-up attacks (see (#mix_up)), where the
    client is tricked into sending credentials to a attacker-controlled AS, and
    the fact that URLs are often stored/logged by browsers (history), proxy
    servers, and operating systems.
  * (A4) Attackers that can read, but not modify, the contents of the
    authorization request (i.e., the authorization request can leak,
    in the same manner as above, to an attacker).
  * (A5) Attackers that can acquire an access token issued by AS. For
    example, a resource server can be compromised by an attacker, an
    access token may be sent to an attacker-controlled resource server
    due to a misconfiguration, or an RO is social-engineered into
    using a attacker-controlled RS. See also (#comp_res_server).
    
(A3), (A4) and (A5) typically occur together with either (A1) or (A2).
Attackers can collaborate to reach a common goal. 

Note that in this attacker model, an attacker (see A1) can be a RO or
act as one. For example, an attacker can use his own browser to replay
tokens or authorization codes obtained by any of the attacks described
above at the client or RS.

This document focusses on threats resulting from these attackers.
Attacks in an even stronger attacker model are discussed, for example,
in [@arXiv.1901.11520].
    
