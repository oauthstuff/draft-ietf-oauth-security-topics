# Introduction {#Introduction}

Since its publication in [@!RFC6749] and [@!RFC6750], OAuth 2.0
("OAuth" in the following) has gotten massive traction in the market
and became the standard for API protection and the basis for federated
login using OpenID Connect [@!OpenID]. While OAuth is used in a
variety of scenarios and different kinds of deployments, the following
challenges can be observed:

  * OAuth implementations are being attacked through known implementation
	  weaknesses and anti-patterns. Although most of these threats are discussed
	  in the OAuth 2.0 Threat Model and Security Considerations [@!RFC6819],
   	continued exploitation demonstrates a need for more specific
	  recommendations, easier to implement mitigations, and more defense in depth.
    
  * OAuth is being used in environments with higher security requirements than
    considered initially, such as Open Banking, eHealth, eGovernment, and
    Electronic Signatures. Those use cases call for stricter guidelines and
    additional protection.
	  
  * OAuth is being used in much more dynamic setups than originally anticipated,
	  creating new challenges with respect to security. Those challenges go beyond
	  the original scope of [@!RFC6749], [@!RFC6750], and [@!RFC6819].
    
    OAuth initially assumed a static relationship between client,
    authorization server and resource servers. The URLs of AS and RS were
    known to the client at deployment time and built an anchor for the
    trust relationship among those parties. The validation whether the
    client talks to a legitimate server was based on TLS server
    authentication (see [@!RFC6819], Section 4.5.4). With the increasing
    adoption of OAuth, this simple model dissolved and, in several
    scenarios, was replaced by a dynamic establishment of the relationship
    between clients on one side and the authorization and resource servers
    of a particular deployment on the other side. This way, the same
    client could be used to access services of different providers (in
    case of standard APIs, such as e-mail or OpenID Connect) or serve as a
    frontend to a particular tenant in a multi-tenancy environment.
    Extensions of OAuth, such as the OAuth 2.0 Dynamic Client Registration
    Protocol [@RFC7591] and OAuth 2.0 Authorization Server Metadata
    [@RFC8414] were developed in order to support the usage of OAuth in
    dynamic scenarios.
	  
  * Technology has changed. For example, the way browsers treat fragments when
	  redirecting requests has changed, and with it, the implicit grant's
	  underlying security model.
	  
This document provides updated security recommendations to address
these challenges. It does not supplant the security advice given in
[@!RFC6749], [@!RFC6750], and [@!RFC6819], but complements those
documents.

This document introduces new requirements and deprecates some modes of operation
that are deemed less secure or even insecure. Naturally, not all existing
ecosystems and implementations are compatible to the new requirements, but it is
RECOMMENDED that implementers upgrade their implementations and ecosystems when
feasible.
	  
## Structure

The remainder of this document is organized as follows: The next
section summarizes the most important recommendations of the OAuth
working group for every OAuth implementor. Afterwards, the updated the
OAuth attacker model is presented. Subsequently, a detailed analysis
of the threats and implementation issues that can be found in the wild
today is given along with a discussion of potential countermeasures.

## Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL
NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED",
"MAY", and "OPTIONAL" in this document are to be interpreted as
described in BCP 14 [@RFC2119] [@RFC8174] when, and only when, they
appear in all capitals, as shown here.

This specification uses the terms "access token", "authorization
endpoint", "authorization grant", "authorization server", "client",
"client identifier" (client ID), "protected resource", "refresh
token", "resource owner", "resource server", and "token endpoint"
defined by OAuth 2.0 [@!RFC6749].
