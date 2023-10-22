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
 - WebRTC
 - HPKE
 - ESNI
 - Hybrid

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

The visible face of the Internet largely consists of services that employ a client-server architecture in which a client communicates with an application service.  When a client communicates with an application service using protocols such as TLS 1.3 {{?RFC8446}}, DTLS 1.3 {{?RFC9147}}, or a protocol built on those (QUIC {{?RFC9001}} being a notable example), the client and server can perform ephemeral public-key exchange mechanism, such as ECDH, to derive the shared secret for forward secrecy. They can validate each other's identity using X.509 certificates to establish secure communication.

The presence of a Cryptographically Relevant Quantum Computer (CRQC) would render state-of-the-art, traditional public-key algorithms deployed today obsolete and insecure, since the assumptions about the intractability of the mathematical problems for these algorithms that offer confident levels of security today no longer apply in the presence of a CRQC. This means there is a requirement to update protocols and infrastructure to use post-quantum algorithms, which are public-key algorithms designed to be secure against CRQCs as well as classical computers. The traditional cryptographic primitives that need to be replaced by PQC are discussed in {{?I-D.ietf-pquip-pqc-engineers}}.

The industry has successfully upgraded TLS versions while deprecating old versions (e.g., SSLv2), and many
protocols have transitioned from RSA to Elliptic Curve Cryptography (ECC) improving security while also reducing key sizes. The transition to post-quantum crypto brings different challenges, most significantly, the new Post-Quantum algorithms:

  1. are not fully trusted
  2. use larger key sizes
  3. have higher CPU and memory utilization

All applications transmitting messages over untrusted networks can be susceptible to active or passive attacks by adversaries using CRQCs, with varying degrees of significance for both users and the underlying systems. This document explores Quantum-Ready usage profiles for applications specifically designed to defend against passive and on-path attacks employing CRQCs. TLS client and server implementations, as well as applications, can mitigate the impact of these challenges through various techniques described in subsequent sections.


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
Diffie-Hellman (ECDH); which is almost always used in the ephemeral mode referred to 
as Elliptic Curve Diffie-Hellman Ephemeral (ECDHE).

"Post-Quantum Algorithm": An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Examples of PQC key exchange algorithms include the Module-Lattice Key Encapsulation Mechanism (ML-KEM), also called Kyber.

"Hybrid" key exchange, in this context, means the use of two component
key exchange algorithms -- one traditional algorithm and one
Post-Quantum algorithm.  The final shared secret key is secure when at
least one of the component key exchange algorithms remains
unbroken. It is referred to as PQ/T Hybrid Scheme in
{{?I-D.ietf-pquip-pqt-hybrid-terminology}}.

The same categories also apply to digital signature algorithms as used in X.509 certificates, Certificate Transparency SCTs, OCSP statements, Remote Attestations, and any other mechanism that contributes signatures to a TLS handshake.


# Timeline for transition {#timeline}

The timeline and driving motivation for Quantum-Ready transition differ between data confidentiality and data authentication (e.g., signature). Digital signatures are used within X.509 certificates, Certificate Revocation Lists (CRLs), and to sign messages.

Encrypted payloads transmitted via Transport Layer Security (TLS) can be susceptible to decryption if an attacker equipped with a CRQC gains access to the traditional asymmetric public keys used in the TLS key exchange and the transmitted ciphertext. TLS implementations commonly utilize Diffie-Hellman schemes for key exchange. If an attacker has copies of an entire set of encrypted payloads, including the TLS setup, it could employ CRQCs to potentially decrypt the payload by determining the private key.

For data confidentiality, we are concerned with the so-called "Harvest Now, Decrypt Later" attack where a malicious actor with adequate resources can launch an attack to store encrypted data today that can be decrypted once a CRQC is available. This implies that, even today, encrypted data is susceptible to the attack by not implementing quantum-safe strategies, as it corresponds to data being deciphered in the future. The storage time and effective security lifetime of this encrypted data might vary from seconds to decades.

For client/server certificate based authentication, it is often the case that the certificate's signature in the handshake has a very short lifetime, which means that the time between the certificate signing the CertificateVerify message and its verification by the peer during the TLS handshake is limited. However, we could question the security lifetime of the digital signatures on the X.509 certificates themselves, including the root CAs, which can have lifetimes of 20 years or more, root CRLs which can have lifetimes of a year or more, and delegated credentials such as CRL Signing Certificates or OCSP response signing certificates which can have lifetimes anywhere in between.

# Data Confidentiality {#confident}

The migration to PQC is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues (when certified implementations will be commercially available), unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there is a desire or a requirement for protocols that use both algorithm types. The primary goal of a hybrid key exchange mechanism is to facilitate
the establishment of a shared secret which remains secure as long as as one of the component key exchange mechanisms remains unbroken.

{{!I-D.ietf-tls-hybrid-design}} provides a construction for hybrid key exchange in TLS 1.3. It fulfills the primary goal of hybrid key exchange, with additional objectives discussed in Section 1.5 of the same document.

Applications MUST migrate to TLS 1.3 and support the hybrid key exchange, as defined in {{!I-D.ietf-tls-hybrid-design}}. In the future, we anticipate a shift away from traditional cryptographic algorithms in favor of post-quantum algorithms. This transition is expected to provide benefits in terms of CPU efficiency and reduced data transmission overhead compared to hybrid key exchange.

The client initiates the TLS handshake by sending a list of key agreement methods it supports in the key_share extension. One of the challenges during the PQC migration is that the client may not know whether the server supports the Hybrid key exchange. To address this uncertainty, the client can adopt one of two strategies:

1. Send Both Traditional and Hybrid Key Exchange Algorithms: In the first ClientHello message, the client can send both traditional and hybrid key exchange algorithm key shares to the server, avoiding the need for multiple round trips. However, this approach requires the client to perform additional computations, results in a larger amount of data transmitted over the network, and may cause the ClientHello message to be fragmented.

2. Indicate Support for Hybrid Key Exchange: Alternatively, the client may initially indicate support for hybrid key exchange and send a traditional key exchange algorithm key share in the first ClientHello message. If the server supports hybrid key exchange, it will use the HelloRetryRequest to request a hybrid key exchange algorithm key share from the client. The client can then send the hybrid key exchange algorithm key share in the second ClientHello message.

# Authentication

While CRQCs could decrypt previous TLS sessions, client/server authentication based on certificates cannot be retroactively broken. However, given the multi-year lead-time required to establish, certify, and embed new root CAs, it would be difficult to react in a timely manner if CRQCs come online sooner than anticipated. So while PQ migration of X.509 certificates has more time than key exchanges, we should not delay this work for too long.

The Quantum-Ready authentication property can be utilized in scenarios where an on-path attacker possesses network devices equipped with CRQCs, capable of breaking traditional authentication protocols. If an attacker uses CRQC to determine the private key of a server certificate before the certificate expiry, the attacker can create a fake server, and then every user will think that their connection is legitimate. The server impersonation leads to various security threats, including impersonation, data disclosure, and the interception of user data and communications.

The Quantum-Ready authentication property ensures authentication through either a pure Post-Quantum or a PQ/T hybrid Certificate. A Post-Quantum X.509 Certificate using Module-Lattice Digital Signature Algorithm (ML-DSA), also called Dilithium, is defined in {{?I-D.ietf-lamps-dilithium-certificates}}. The PQ/T Hybrid Authentication property is currently still under active exploration and discussion in the LAMPS WG, and consensus may evolve over time regarding its adoption.

To decide whether and when to support a Post-Quantum Certificate (PQC) or a PQ/T hybrid scheme for client and server authentication, it is important to consider factors such as the frequency and duration of system upgrades, as well as the anticipated availability of CRQCs. For example, applications that have extremely short key lifetimes -- for example less than an hour -- may decide that it is an acceptable risk to leave those on Traditional algorithms for the foreseeable future under the assumption that quantum key factoring attacks take longer to run than the key lifetimes. It may be advantageous to explore heterogeneous PKI architectures where the long-lived CAs are using Post-Quantum algorithms but the server and client certificates are not.

# Application Protocols

## Encrypted DNS

The privacy risks for end users exchanging DNS messages in clear text are discussed in {{!RFC7518}}. Transport Layer Security (TLS) is employed to ensure privacy for DNS. DNS encryption provided by TLS (e.g., DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC) eliminates opportunities for eavesdropping and on-path tampering while in transit through the network.

Encrypted DNS messages transmitted using Transport Layer Security (TLS) may be vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the TLS key exchange. If an attacker possesses copies of an entire set of encrypted DNS messages, including the TLS setup, it could use a CRQC to potentially decrypt the message content by determining the ephemeral key exchange private key.

Encrypted DNS protocols will have to support the Quantum-Ready usage profile discussed in {#confident}.

## Hybrid public-key encryption (HPKE)

Hybrid public-key encryption (HPKE) is a scheme that provides public key encryption of arbitrary-sized plaintexts given a recipient's public key. HPKE utilizes a non-interactive ephemeral-static Diffie-Hellman exchange to establish a shared secret.  The motivation for standardizing a public key encryption scheme is explained in the introduction of {{!RFC9180}}.

HPKE can be extended to support hybrid post-quantum Key Encapsulation Mechanisms (KEMs) as defined in {{?I-D.westerbaan-cfrg-hpke-xyber768d00-02}}. Kyber, which is a KEM does not support the static-ephemeral key exchange that allows HPKE based on DH based KEMs.

### Interaction with Encrypted Client Hello {#ech}

Client TLS libraries and applications can use Encrypted Client Hello (ECH) {{?I-D.ietf-tls-esni}} to prevent passive observation of the intended server identity in the TLS handshake which requires also deploying encrypted DNS (DNS over TLS), otherwise a passive listener can observe DNS queries (or responses) and infer same server identity that was being protected with ECH. ECH uses HPKE for public key encryption.

ECH MUST incorporate support for hybrid post-quantum KEMs to protect against the 'Harvest Now, Decrypt Later' attack.

### Oblivious HTTP

Oblivious HTTP {{?I-D.ietf-ohai-ohttp}} allows clients to encrypt messages exchanged with an Oblivious Target Resource (target). The messages are encapsulated in encrypted messages to an Oblivious Gateway Resource (gateway), which offers Oblivious HTTP access to the target. The gateway is accessed via an Oblivious Relay Resource (relay), which proxies the encapsulated messages to hide the identity of the client. Overall, this architecture is designed in such a way that the relay cannot inspect the contents of messages, and the gateway and target cannot learn the client's identity from a single transaction. Oblivious HTTP uses HPKE for encapsulating binary HTTP messages to protect their contents.

Oblivious HTTP is vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the HPKE. If an attacker possesses copies of an entire set of encapsulated HTTP messages, it could use CRQC to potentially decrypt the message content by determining the private key. The attacker can potentially be the Oblivious Relay Resource.

The "ohttp" SvcParamKey defined in {{?I-D.ietf-ohai-svcb-config}} is used to indicate that a service described in an SVCB RR can be accessed as a target using an associated gateway. For the "dns" scheme, as defined in {{!I-D.draft-ietf-add-svcb-dns}}, the presence of the "ohttp" parameter means that the DNS server being described has a DNS over HTTP (DoH) {{!RFC8484}} service that can be accessed using Oblivious HTTP.

Oblivious HTTP and DNS over Oblivious HTTP MUST incorporate support for hybrid post-quantum KEMs to protect against the 'Harvest Now, Decrypt Later' attack.

## WebRTC

In WebRTC, secure channels are setup via DTLS and DTLS-SRTP {{!RFC5763}} keying for SRTP {{!RFC3711}} for media channels and the Stream Control Transmission Protocol (SCTP) over DTLS {{!RFC8261}} for data channels.

Secure channels may be vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the DTLS key exchange. If an attacker possesses copies of an entire set of encrypted media, including the DTLS setup, it could use CRQC to potentially decrypt the media by determining the private key.

WebRTC media and data channels MUST support the Quantum-Ready usage profile discussed in {#confident}.

The other challenge with WebRTC is that PQC KEMs often come with large public keys and PQC Signature schemes come with large signatures in comparison with traditional algorithms (as discussed in Section 12 and 13 of {{?I-D.ietf-pquip-pqc-engineers}}). In many cases, UDP datagrams are restricted to sizes smaller than 1500 bytes. If IP fragmentation needs to be avoided, each DTLS handshake message must be fragmented over several DTLS records, with each record intended to fit within a single UDP datagram. This approach could potentially lead to increased time to complete the DTLS handshake and involve multiple round-trips in lossy networks. It may also extend the time required to set up secure WebRTC channels. One potential mitigation strategy to avoid the delay is to prevent the duplication of key shares, as discussed in Section 4 of {{!I-D.ietf-tls-hybrid-design}}.

## HTTPS

HTTPS (Hypertext Transfer Protocol Secure) is the secure version of HTTP used for secure data exchange over the web. HTTPS primarily relies on the TLS (Transport Layer Security) protocol to provide encryption, integrity, and authenticity for data in transit. 

HTTP messages transmitted using Transport Layer Security (TLS) may be vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the TLS key exchange. If an attacker possesses copies of an entire set of encrypted HTTP messages, including the TLS setup, it could use CRQC to potentially decrypt the message content by determining the private key. This traffic can include sensitive information, such as login credentials, personal data, or financial details, depending on the nature of the communication. 

If an attacker can decrypt the message content before the expiry of the login credentails, the attacker can steal the credentails. The theft of login credentials is a serious security concern that can have a wide range of consequences for individuals and organizations. The most immediate and obvious challenge is that the attacker gains unauthorized access to the victim's accounts, systems, or data. This can lead to data breaches, privacy violations, and various forms of cybercrime.

Applications using HTTPS to exchange sensitive data MUST support the Quantum-Ready usage profile discussed in {#confident}. If the data is genuinely non-sensitive and has no privacy or security implications, the motivation for an attacker to invest resources in capturing and later decrypting it would likely be very low. In such cases, the "Harvest Now, Decrypt Later" attack may not be relevant. In similar lines, reverse proxies operated between clients and origin servers will also have to support {#confident}. 

## Email Submission

TLS support for Email Submission/Access is described in {{Section 3.3 of 
?RFC8314}}.  There are no specific recommendations for SUBMISSION beyond {{ech}}.

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

Implementing hybrid modes improperly can introduce security issues at the cryptographic layer, for example how the Traditional and PQ schemes are combined; at the algorithm selection layer, mismatched security levels for example if 192-bit KEM is used with a 128-bit secure combiner; or at the protocol layer in how the upgrade/downgrade mechanism works. Hybrid mechanisms should be implemented carefully and all relevant specifications implemented correctly.

# Acknowledgements
{:numbered="false"}

Thanks to Dan Wing for suggesting wider document scope. Thanks to Mike Ounsworth for early review and feedback.


