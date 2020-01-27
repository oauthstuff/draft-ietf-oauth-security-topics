# Document History

   [[ To be removed from the final specification ]]
   
   -14
   
   * Changes from WGLC feedback
   * Editorial changes
   * AS MUST announce PKCE support either in metadata or using deployment-specific ways (before: SHOULD)
   
   -13
   
   * Discourage use of Resource Owner Password Credentials Grant
   * Added text on client impersonating resource owner
   * Recommend asymmetric methods for client authentication
   * Encourage use of PKCE mode "S256"
   * PKCE may replace state for CSRF protection
   * AS SHOULD publish PKCE support
   * Cleaned up discussion on auth code injection
   * AS MUST support PKCE
   
   -12
   
   * Added updated attacker model
   
   -11
   
   * Adapted section 2.1.2 to outcome of consensus call
   * more text on refresh token inactivity and implementation note on refresh token replay detection via refresh token rotation

   -10
   
   * incorporated feedback by Joseph Heenan
   * changed occurrences of SHALL to MUST
   * added text on lack of token/cert binding support tokens issued in
      the authorization response as justification to not recommend
      issuing tokens there at all
   * added requirement to authenticate clients during code exchange
      (PKCE or client credential) to 2.1.1.
   * added section on refresh tokens
   * editorial enhancements to 2.1.2 based on feedback

   -09

   * changed text to recommend not to use implicit but code
   * added section on access token injection
   *  reworked sections 3.1 through 3.3 to be more specific on implicit
      grant issues

   -08

   * added recommendations re implicit and token injection
   * uppercased key words in Section 2 according to RFC 2119

   -07

   * incorporated findings of Doug McDorman
   * added section on HTTP status codes for redirects
   *  added new section on access token privilege restriction based on
      comments from Johan Peeters

   -06

   *  reworked section 3.8.1
   *  incorporated Phil Hunt's feedback
   *  reworked section on mix-up
   *  extended section on code leakage via referrer header to also cover
      state leakage
   *  added Daniel Fett as author
   *  replaced text intended to inform WG discussion by recommendations
      to implementors
   *  modified example URLs to conform to RFC 2606

   -05

   *  Completed sections on code leakage via referrer header, attacks in
      browser, mix-up, and CSRF
   *  Reworked Code Injection Section
   *  Added reference to OpenID Connect spec
   *  removed refresh token leakage as respective considerations have
      been given in section 10.4 of RFC 6749
   *  first version on open redirection
   *  incorporated Christian Mainka's review feedback

   -04

   *  Restructured document for better readability
   *  Added best practices on Token Leakage prevention

   -03

   *  Added section on Access Token Leakage at Resource Server
   *  incorporated Brian Campbell's findings

   -02

   *  Folded Mix up and Access Token leakage through a bad AS into new
      section for dynamic OAuth threats
   *  reworked dynamic OAuth section

   -01

   *  Added references to mitigation methods for token leakage
   *  Added reference to Token Binding for Authorization Code
   *  incorporated feedback of Phil Hunt
   *  fixed numbering issue in attack descriptions in section 2

   -00 (WG document)

   *  turned the ID into a WG document and a BCP
   *  Added federated app login as topic in Other Topics
