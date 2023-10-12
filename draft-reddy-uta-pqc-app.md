---
title: "Post-Quantum Cryptography Recommendations for Internet Applications"
abbrev: "PQC Recommendations for Applications"
category: std

docname: draft-reddy-uta-pqc-app-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time Area"
workgroup: "uta"
keyword:
 - PQC
 - DNS


venue:
  group: "uta"
  type: "Working Group"
  mail: "uta@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/uta/"


stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"


normative:

informative:
  SP-800-56C:
     title: "Recommendation for Key-Derivation Methods in Key-Establishment Schemes"
     target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Cr2.pdf
     date: false

--- abstract

Post-quantum cryptography brings some new challenges to applications, end users, and system administrators.
This document describes characteristics unique to application protocols and best practices for deploying
Quantum-Ready usage profiles for applications.

--- middle

# Introduction

The visible face of the Internet largely consists of services that employ a client-server architecture in which a client communicates with an application service.  When a client communicates with an application service using protocols such as TLS 1.3 {{?RFC8446}}, DTLS 1.3 {{?RFC9147}}, or a protocol built on those (QUIC {{?RFC9001}} being a notable example), the client and server can perform ephemeral public-key exchange mechanisms, such as ECDH, to derive the shared secret for forward secrecy. They can validate each other's identity using X.509 certificates to establish secure communication.

The industry has successfully upgraded TLS versions while deprecating old versions (e.g., SSLv2), and many
protocols have transitioned from RSA to ECC improving security while also reducing key sizes.  The
transition to post-quantum crypto brings different challenges, most significantly, the new algorithms:
  1. are not fully trusted
  2. use larger key sizes
  3. higher CPU utilization

TLS client implementations, TLS server implementations, and
applications can reduce the impact of these three challenges through various techniques described in subsequent
sections.

<!--

The presence of a Cryptographically Relevant Quantum Computer (CRQC) would render state-of-the-art, traditional public-key algorithms deployed today obsolete, since the assumptions about the intractability of the mathematical problems for these algorithms that offer confident levels of security today no longer apply in the presence of a CRQC. This means there is a requirement to update protocols and infrastructure to use post-quantum algorithms, which are public-key algorithms designed to be secure against CRQCs as well as classical computers. The
traditional cryptographic primitives that need to be replaced by PQC are discussed in {{?I-D.ietf-pquip-pqc-engineers}}.

All applications can be vulnerable to active or passive attacks by adversaries utilizing CRQCs, each to varying degrees of significance for both the user and the underlying system. This document delves into Quantum-Ready usage profiles for applications specifically designed to protect against passive and on-path attacks using CRQCs.
-->


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses terms defined in
{{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this
document, it is helpful to be able to divide cryptographic algorithms
into three classes:

"Traditional Algorithm": An asymmetric cryptographic algorithm based
on integer factorisation, finite field discrete logarithms or elliptic
curve discrete logarithms. In the context of TLS, examples of
traditional key exchange algorithms include Elliptic Curve
Diffie-Hellman.

"Post-Quantum Algorithm": An asymmetric cryptographic algorithm that
is believed to be secure against attacks using quantum computers as
well as classical computers. Examples of PQC key exchange algorithms
include Kyber.

"Hybrid" key exchange, in this context, means the use of two component
key exchange algorithms -- one one traditional algorithm and one
Post-Quantum algorithm.  The final shared secret key is secure when at
least one of the component key exchange algorithms remains
unbroken. It is referred to as PQ/T Hybrid Scheme in
{{?I-D.ietf-pquip-pqt-hybrid-terminology}}.


<!--

# Timeline for transition {#timeline}

The timeline and driving motivation for Quantum-Ready Encrypted DNS transition differ between data confidentiality and data authentication (e.g., signature). Digital signatures are used within X.509 certificates, Certificate Revocation Lists (CRLs), and to sign messages.

Encrypted payloads transmitted via Transport Layer Security (TLS) can be susceptible to decryption if an attacker gains access to the traditional asymmetric public keys used in the TLS key exchange. TLS implementations commonly utilize Diffie-Hellman schemes for key exchange. If an attacker has copies of an entire set of encrypted payloads, including the TLS setup, it could employ CRQCs to potentially decrypt the payload by determining the private key.

For data confidentiality, we are concerned with the so-called "Harvest Now, Decrypt Later" attack where a malicious actor with adequate resources can launch an attack to store encrypted data today that can be decrypted once a CRQC is available. This implies that, every day, encrypted data is susceptible to the attack by not implementing quantum-safe strategies, as it corresponds to data being deciphered in the future.

For client/server certificate based authentication, it is often the case that the certificate's signature has a very short lifetime, which means that the time between the certificate being signed and its verification during the TLS handshake is limited.

# Data Confidentiality {#confident}

The migration to PQC is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there is a desire or a requirement for protocols that use both algorithm types. The primary goal of a hybrid key exchange mechanism is to facilitate
the establishment of a shared secret which remains secure as long as as one of the component key exchange mechanisms remains unbroken.

{{!I-D.ietf-tls-hybrid-design}} provides a construction for hybrid key exchange in TLS 1.3 version. It meets the the primary goal of hybrid key exchange and other additional goals are discussed in Section 1.5 of {{!I-D.ietf-tls-hybrid-design}}.

Applications MUST migrate to TLS 1.3 and support hybrid key exchange defined in {{!I-D.ietf-tls-hybrid-design}}.
-->


# Attacks

A concern with data confidentiality is a *store-now/decrypt-later*
attack where data encrypted with traditional algorithms is stored and
later decrypted using a post-quantum computer.  The mitigation against
this threat is using a post-quantum algorithm or a hybrid algorithm.
The storage time of this encrypted data might vary from seconds to
decades.

> Note: describe active attack?


# Timeline

Today we are doing traditional algorithms.

Tomorrow we need to do both traditional algorithms and post-quantum algorithms at the same time.

Some day, we might be able to avoid using traditional algorithms and solely use post-quantum algorithms,
saving some CPU and bytes on the wire.


# Authentication

While CRQCs could decrypt previous TLS sessions, client/server
authentication cannot be retroactively broken.

> Note: Dan does not agree, or perhaps said another way:  what does "broken" mean
in this context?  I mean, usually a client is authenticated by the user's password
(which is good for ... years?  90 days?  whatever the password rotation policy
might be), and frequently the client is authenticated by a bearer token ("HTTP cookie"),
which could be obtained and could be presented to the server by the attacker, giving
the attacker access.  Maybe you're just talking of server authentication can't be
retroactively broken??  Actually, I'm not sure what's being claim.

<!--

The Quantum-Ready
authentication property can be utilized in scenarios where an on-path
attacker possesses network devices equipped with CRQCs, capable of
breaking traditional authentication protocols.

The Quantum-Ready authentication property ensures authentication through either a Post-Quantum Certificate or a PQ/T hybrid scheme. A Post-Quantum X.509 Certificate using Dilithium is defined in {{?I-D.ietf-lamps-dilithium-certificates}}. The PQ/T Hybrid Authentication property is currently still under active exploration and discussion in the LAMPS WG, and consensus may evolve over time regarding its adoption.


To decide whether and when to support a Post-Quantum Certificate (PQC) or a PQ/T hybrid scheme for client and server authentication, it is important to consider factors such as the frequency and duration of system upgrades, as well as the anticipated availability of CRQCs.
-->

# Application Protocols

## Encrypted DNS

The privacy risks for end users exchanging DNS messages in clear text are discussed in {{!RFC7518}}. Transport Layer Security (TLS) is employed to ensure privacy for DNS. DNS encryption provided by TLS (e.g., DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC) eliminates opportunities for eavesdropping and on-path tampering while in transit through the network.

Encrypted DNS messages transmitted using Transport Layer Security (TLS) may be vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the TLS key exchange. If an attacker possesses copies of an entire set of encrypted DNS messages, including the TLS setup, it could use CRQC to potentially decrypt the message content by determining the private key.

Encrypted DNS protocols will have to support the Quantum-Ready usage profile discussed in {#confident}.

<!--
## Hybrid public-key encryption (HPKE)

Hybrid public-key encryption (HPKE) is a scheme that provides public key encryption of arbitrary-sized plaintexts given a recipient's public key. HPKE utilizes a non-interactive ephemeral-static Diffie-Hellman exchange to establish a shared secret.  The motivation for standardizing a public key encryption scheme is explained in the introduction of {{!RFC9180}}.

HPKE can be extended to support hybrid post-quantum Key Encapsulation Mechanisms (KEMs) as defined in {{?I-D.westerbaan-cfrg-hpke-xyber768d00-02}}. Kyber, which is a KEM does not support the static-ephemeral key exchange that allows HPKE based on DH based KEMs.

> Dan: nothing in this section tells implementor what to do, or what to be worried about.  I propose removing.
-->

### Interaction with Application Encrypted Client Hello {#ech}

Client TLS libraries and applications use Encrypted Client Hello (ECH) {{?I-D.ietf-tls-esni}} to prevent passive
observation of the intended server identity in the TLS handshake which requires also deploying encrypted DNS,
otherwise a passive listener can observe DNS queries (or responses) and infer same server identity that was
being protected with ECH.

To protect against a CRQC, with TLS exchange with the DNS server and with the application server have to
both be either post-quantum algorithms or hybrid algorithms.

ECH uses HPKE for public key encryption. ECH MUST incorporate support for hybrid post-quantum KEMs to protect against the 'Harvest Now, Decrypt Later' attack.

## WebRTC

In WebRTC, secure channels are setup via DTLS and DTLS-SRTP {{!RFC5763}} keying for SRTP {{!RFC3711}} for  media channels and the Stream Control Transmission Protocol (SCTP) over DTLS {{!RFC8261}} for data channels.

Secure channels may be vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the DTLS key exchange. If an attacker possesses copies of an entire set of encrypted media, including the DTLS setup, it could use CRQC to potentially decrypt the media by determining the private key.

WebRTC media and data channels will have to support the Quantum-Ready usage profile discussed in {#confident}.

The other challenge is that PQC KEMs often come with large public keys and PQC Signature schemes come with large
signatures in comparison with traditional algorithms (as discussed in Section 12 and 13 of {{?I-D.ietf-pquip-pqc-engineers}}). In many cases, UDP datagrams are restricted to sizes smaller than 1500 bytes. If IP fragmentation needs to be avoided, each DTLS handshake message must be fragmented over several DTLS records, with each record intended to fit within a single UDP datagram. This approach could potentially lead to increased time to complete the DTLS handshake and involve multiple round-trips in lossy networks. It may also extend the time required to set up secure WebRTC channels. One potential mitigation strategy to avoid the delay is to prevent the duplication of key shares, as discussed in Section 4 of {{!I-D.ietf-tls-hybrid-design}}.

## HTTP

TODO.

### Oblivious HTTP

Oblivious HTTP {{?I-D.ietf-ohai-ohttp}} allows clients to encrypt messages exchanged with an Oblivious Target Resource (target). The messages are encapsulated in encrypted messages to an Oblivious Gateway Resource (gateway), which offers Oblivious HTTP access to the target. The gateway is accessed via an Oblivious Relay Resource (relay), which proxies the encapsulated messages to hide the identity of the client. Overall, this architecture is designed in such a way that the relay cannot inspect the contents of messages, and the gateway and target cannot learn the client's identity from a single transaction. Oblivious HTTP uses HPKE for encapsulating binary HTTP messages to protect their contents.

Oblivious HTTP is vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the HPKE. If an attacker possesses copies of an entire set of encapsulated HTTP messages, it could use CRQC to potentially decrypt the message content by determining the private key. The attacker can potentially be the Oblivious Relay Resource.

The "ohttp" SvcParamKey defined in {{?I-D.ietf-ohai-svcb-config}} is used to indicate that a service described in an SVCB RR can be accessed as a target using an associated gateway. For the "dns" scheme, as defined in {{!I-D.draft-ietf-add-svcb-dns}}, the presence of the "ohttp" parameter means that the DNS server being described has a DNS over HTTP (DoH) {{!RFC8484}} service that can be accessed using Oblivious HTTP.

Oblivious HTTP and DNS over Oblivious HTTP MUST incorporate support for hybrid post-quantum KEMs to protect against the 'Harvest Now, Decrypt Later' attack.


## NFS

TLS support for TLS is described in {{!RFC9289}} which describes only opportunisticly using TLS.  This leaves
the communication vulnerable to a downgrade attack to plaintext or to a traditional algorithm.  This should be
improved so that the NFS client can at least alert such a downgrade and ideally prevent such a downgrade attack.

## NTP

TLS support for NTP is described in {{?RFC8915}}.  Compromise of NTP can cause a system's clock to advance backwards
or forwards from real time, causing either success or failure to use a certificate or other time-based
authenticator.

## SMTP

TLS support for SMTP is described in {{?RFC3207}}.  There are no
specific recommendations for SMTP except what is described in {{ech}}.

> TODO:  Discuss DANE, which may have specific recommendations to write here or perhaps in the earlier DNS section.

## SUBMISSION

TLS support for SUBMISSION is described in {{Section 3.3 of
?RFC8314}}.  There are no specific recommendations for SUBMISSION beyond {{ech}}.

## IMAP

TLS support for IMAP is described in {{Section 3.2 of ?RFC8314}}.
There are no specific recommendations for IMAP except what is
described in {{ech}}.


# Security Considerations

Post-quantum algorithms selected for standardization are relatively
new and they they have not been subject to the same depth of study as
traditional algorithms. PQC implementations will also be new and
therefore more likely to contain implementation bugs than the
battle-tested crypto implementations that we rely on today. In
addition, certain deployments may need to retain traditional
algorithms due to regulatory constraints, for example FIPS
{{SP-800-56C}} or PCI compliance. Hybrid key exchange enables
potential security against "Harvest Now, Decrypt Later" attack provide
for time to react in the case of the announcement of a devastating
attack agaist any one algorithm, while not fully abandoning
traditional cryptosystems.

# Acknowledgements
{:numbered="false"}

Thanks to Dan Wing for suggesting wider document scope.


