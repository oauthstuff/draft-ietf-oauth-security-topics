# Introduction {#Introduction}

Since its publication in [@!RFC6749] and [@!RFC6750], OAuth 2.0 (referred to as simply "OAuth" in the following) has gained massive traction in the market
and became the standard for API protection and the basis for federated
login using OpenID Connect [@!OpenID.Core]. While OAuth is used in a
variety of scenarios and different kinds of deployments, the following
challenges can be observed:

  * OAuth implementations are being attacked through known implementation
	  weaknesses and anti-patterns (i.e., well-known patterns that are considered
    insecure). Although most of these threats are discussed in the OAuth 2.0
	  Threat Model and Security Considerations [@!RFC6819], continued exploitation
   	demonstrates a need for more specific recommendations, easier to implement
	  mitigations, and more defense in depth.

  * OAuth is being used in environments with higher security requirements than
    considered initially, such as Open Banking, eHealth, eGovernment, and
    Electronic Signatures. Those use cases call for stricter guidelines and
    additional protection.

  * OAuth is being used in much more dynamic setups than originally anticipated,
	  creating new challenges with respect to security. Those challenges go beyond
	  the original scope of [@!RFC6749], [@!RFC6750], and [@!RFC6819].

    OAuth initially assumed static relationships between clients,
    authorization servers, and resource servers. The URLs of the servers were
    known to the client at deployment time and built an anchor for the
    trust relationships among those parties. The validation of whether the
    client is talking to a legitimate server was based on TLS server
    authentication (see [@!RFC6819], Section 4.5.4). With the increasing
    adoption of OAuth, this simple model dissolved and, in several
    scenarios, was replaced by a dynamic establishment of the relationship
    between clients on one side and the authorization and resource servers
    of a particular deployment on the other side. This way, the same
    client could be used to access services of different providers (in
    case of standard APIs, such as e-mail or OpenID Connect) or serve as a
    front end to a particular tenant in a multi-tenant environment.
    Extensions of OAuth, such as the OAuth 2.0 Dynamic Client Registration
    Protocol [@RFC7591] and OAuth 2.0 Authorization Server Metadata
    [@RFC8414] were developed to support the use of OAuth in
    dynamic scenarios.

  * Technology has changed. For example, the way browsers treat fragments when
	  redirecting requests has changed, and with it, the implicit grant's
	  underlying security model.

This document provides updated security recommendations to address these
challenges. It introduces new requirements beyond those defined in existing
specifications such as OAuth 2.0 [@RFC6749] and OpenID Connect [@OpenID.Core]
and deprecates some modes of operation that are deemed less secure or even
insecure. However, this document does not supplant the security advice given in
[@!RFC6749], [@!RFC6750], and [@!RFC6819], but complements those documents.

Naturally, not all existing ecosystems and implementations are
compatible with the new requirements and following the best practices described in
this document may break interoperability. Nonetheless, it is RECOMMENDED that
implementers upgrade their implementations and ecosystems as soon as feasible.

OAuth 2.1, under developement as [@I-D.ietf-oauth-v2-1], will incorporate
security recommendations from this document.

## Structure

The remainder of this document is organized as follows: The next section
summarizes the most important best practices for every OAuth implementor.
Afterwards, the updated OAuth attacker model is presented. Subsequently, a
detailed analysis of the threats and implementation issues that can be found in
the wild today is given along with a discussion of potential countermeasures.

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

An "open redirector" is an endpoint on a web server that forwards a user’s
browser to an arbitrary URI obtained from a query parameter.
