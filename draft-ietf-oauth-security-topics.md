%%%
title = "OAuth 2.0 Security Best Current Practice"
abbrev = "OAuth 2.0 Security BCP"
ipr = "trust200902"
area = "Security"
workgroup = "Web Authorization Protocol"
keyword = ["security", "oauth2", "best current practice"]
updates = [ 6749, 6750, 6819 ]
tocdepth = 4

[seriesInfo]
name = "Internet-Draft"
value = "draft-ietf-oauth-security-topics-latest"
stream = "IETF"
status = "bcp"

[[author]]
initials="T."
surname="Lodderstedt"
fullname="Torsten Lodderstedt"
organization="SPRIND"
    [author.address]
    email = "torsten@lodderstedt.net"

[[author]]
initials="J."
surname="Bradley"
fullname="John Bradley"
organization="Yubico"
    [author.address]
    email = "ve7jtb@ve7jtb.com"

[[author]]
initials="A."
surname="Labunets"
fullname="Andrey Labunets"
organization="Independent Researcher"
    [author.address]
    email = "isciurus@gmail.com"

[[author]]
initials="D."
surname="Fett"
fullname="Daniel Fett"
organization="Authlete"
    [author.address]
    email = "mail@danielfett.de"

%%%

.# Abstract

This document describes best current security practice for OAuth 2.0. It updates
and extends the threat model and security advice given in RFC 6749,
RFC 6750, and RFC 6819 to incorporate practical experiences gathered since
OAuth 2.0 was published and covers new threats relevant due to the broader
application of OAuth 2.0. Further, it deprecates some modes of operation that are
deemed less secure or even insecure.

{mainmatter}

{{A_mainmatter.md}}
{{B_references.md}}

{backmatter}
{{C_documenthistory.md}}
