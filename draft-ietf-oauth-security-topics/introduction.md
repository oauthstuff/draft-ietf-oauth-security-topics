# Introduction {#Introduction}
      
It's been a while since OAuth has been published in [@!RFC6749] and
[@!RFC6750]. Since publication, OAuth 2.0 has gotten massive traction
in the market and became the standard for API protection and, as
foundation of OpenID Connect [@!OpenID], identity providing. While
OAuth was used in a variety of scenarios and different kinds of
deployments, the following challenges could be observed: 

  * OAuth implementations are being attacked through known
	implementation weaknesses and anti-patterns (CSRF, referrer
	header). Although most of these threats are discussed in the OAuth
	2.0 Threat Model and Security Considerations [@!RFC6819],
	continued exploitation demonstrates there may be a need for more
	specific recommendations or that the existing mitigations are too
	difficult to deploy.
	  
  * Technology has changed, e.g., the way browsers treat fragments in
	some situations, which may change the implicit grant's underlying
	security model.
	  
  * OAuth is used in much more dynamic setups than originally
	anticipated, creating new challenges with respect to security.
	Those challenges go beyond the original scope of [@!RFC6749],
	[@!RFC6749], and [@!RFC6819].
	  
	  
OAuth initially assumed a static relationship between client,
authorization server and resource servers. The URLs of AS and RS were
known to the client at deployment time and built an anchor for the
trust relationship among those parties. The validation whether the
client talks to a legitimate server was based on TLS server
authentication (see [@!RFC6819], Section 4.5.4). With the increasing
adoption of OAuth, this simple model dissolved and, in several
scenarios, was replaced by a dynamic establishment of the relationship
between clients on one side and the authorization and resource servers
of a particular deployment on the other side. This way the same client
could be used to access services of different providers (in case of
standard APIs, such as e-Mail or OpenID Connect) or serves as a
frontend to a particular tenant in a multi-tenancy. Extensions of
OAuth, such as [@!RFC7591] and [@!RFC8414] were developed in order to
support the usage of OAuth in dynamic scenarios. As a challenge to the
community, such usage scenarios open up new attack angles, 
which are discussed in this document.
	  
The remainder of the document is organized as follows: The next
section updates the OAuth threat model. Afterwards, the most important
recommendations of the OAuth working group for every OAuth implementor
are summarized. Subsequently, a detailed analysis of the threats and
implementation issues which can be found in the wild today is given
along with a discussion of potential countermeasures.
    
