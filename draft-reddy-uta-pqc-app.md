---
title: "Post-Quantum Cryptography Recommendations for Applications"
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
 - PQ/T Hybrid

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
---

--- abstract

Post-quantum cryptography introduces new challenges for applications, end users, and system administrators. This document outlines characteristics unique to application protocols and provides best practices for deploying Quantum-Ready usage profiles in applications utilizing TLS.

--- middle

# Introduction

The visible face of the Internet largely consists of services that employ a client-server architecture in which a client communicates with an application service.  When a client communicates with an application service using protocols such as TLS 1.3 {{?RFC8446}}, DTLS 1.3 {{?RFC9147}}, or a protocol built on those (QUIC {{?RFC9001}} being a notable example), the client and server can perform ephemeral public-key exchange mechanism, such as ECDH, to derive the shared secret for forward secrecy. They can validate each other's identity using X.509 certificates to establish secure communication.

The presence of a Cryptographically Relevant Quantum Computer (CRQC) would render state-of-the-art, traditional public-key algorithms deployed today obsolete and insecure, since the assumptions about the intractability of the mathematical problems for these algorithms that offer confident levels of security today no longer apply in the presence of a CRQC. This means there is a requirement to update protocols and infrastructure to use post-quantum algorithms, which are public-key algorithms designed to be secure against CRQCs as well as classical computers. The traditional cryptographic primitives that need to be replaced by PQC are discussed in {{?I-D.ietf-pquip-pqc-engineers}}.

The industry has successfully upgraded TLS versions while deprecating old versions (e.g., SSLv2), and many
protocols have transitioned from RSA to Elliptic Curve Cryptography (ECC) improving security while also reducing key sizes. The transition to post-quantum crypto brings different challenges, most significantly, the new Post-Quantum algorithms:

   1. Algorithm Maturity: While NIST has finalized the selection of certain post-quantum algorithms, the correctness and security of implementations remain critical, as bugs in implementations can introduce vulnerabilities, regardless of the strength of the underlying algorithm. 

   2. Key and Signature Sizes: Post-quantum algorithms often require larger key and signature sizes, which can significantly increase handshake packet sizes and impact network performance. For example: The public key sizes of ML-KEM are much larger than ECDH (see Table 5 in {{?I-D.ietf-pquip-pqc-engineers}}), and the public key sizes of SLH-DSA and ML-DSA are much larger than P256 (see Table 6 in {{?I-D.ietf-pquip-pqc-engineers}}). Similarly, the signature sizes of post-quantum algorithms like SLH-DSA and ML-DSA are considerably larger than those of traditional algorithms like Ed25519 or ECDSA-P256. Larger signatures can pose challenges in constrained environments (e.g., IoT) or increase handshake times over high-latency and lossy networks.

   3. Performance Trade-Offs: While some PQ algorithms exhibit slower operations compared to their traditional counterparts, others demonstrate specific advantages. For example: ML-KEM utilizes less CPU than X25519. ML-DSA features faster signature verification times than Ed25519 but are slower in signature generation.

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

"Post-Quantum Algorithm": An asymmetric cryptographic algorithm that is believed to be secure against attacks 
using quantum computers as well as classical computers. Examples of PQC key exchange algorithms include the 
Module-Lattice Key Encapsulation Mechanism (ML-KEM).

"Hybrid" key exchange, in this context, means the use of two component
key exchange algorithms -- one traditional algorithm and one
Post-Quantum algorithm.  The final shared secret key is secure when at
least one of the component key exchange algorithms remains
unbroken. It is referred to as PQ/T Hybrid Scheme in
{{?I-D.ietf-pquip-pqt-hybrid-terminology}}.

PQ/T Hybrid Digital Signature*:  A multi-algorithm digital signature
scheme made up of two or more component digital signature
algorithms where at least one is a post-quantum algorithm and at
least one is a traditional algorithm.

Digital signature algorithms are used in X.509 certificates, Certificate Transparency SCTs, OCSP statements, 
Remote Attestations, and any other mechanism that contributes signatures to a TLS handshake.


# Timeline for transition {#timeline}

The timeline and driving motivation for Quantum-Ready transition differ between data confidentiality and data authentication (e.g., signature). Digital signatures are used within X.509 certificates, Certificate Revocation Lists (CRLs), and to sign the TLS handshake transcript.

Encrypted payloads transmitted via Transport Layer Security (TLS) can be susceptible to decryption if an attacker equipped with a CRQC gains access to the traditional asymmetric public keys used in the TLS key exchange and the transmitted ciphertext. TLS implementations commonly utilize Diffie-Hellman schemes for key exchange. If an attacker has copies of an entire set of encrypted payloads, including the TLS setup, it could employ CRQCs to potentially decrypt the payload by determining the private key.

For data confidentiality, we are concerned with the so-called "Harvest Now, Decrypt Later" attack where a malicious actor with adequate resources can launch an attack to store encrypted data today that can be decrypted once a CRQC is available. This implies that, even today, encrypted data is susceptible to the attack by not implementing quantum-safe strategies, as it corresponds to data being deciphered in the future. The storage time and effective security lifetime of this encrypted data might vary from seconds to decades.

For data authentication, our concern lies with an on-path attacker who possesses devices equipped with CRQCs capable of breaking traditional authentication protocols. For instance, the attacker can fake the identity of the target, leading victims to connect to the attacker's device instead of connecting to the actual target, resulting in an impersonation attack. While not an immediate threat, it is still a concern when compared to the 'Harvest Now, Decrypt Later' attack.

In client/server certificate-based authentication, the time between the generation of the signature in the CertificateVerify message and its verification by the peer during the TLS handshake is short. However, it's worth questioning the security lifetime of the digital signatures on X.509 certificates, including those issued by root Certificate Authorities (CAs). Root CAs can have lifetimes of 20 years or more. Additionally, root Certificate Revocation Lists (CRLs) may have validity periods of a year or more, while delegated credentials like CRL Signing Certificates or OCSP response signing certificates often have shorter validity periods that fall somewhere in between.

# Data Confidentiality {#confident}

Data in transit may need protection for years. The potential development of CRQCs necessitates a shift away from traditional algorithms. However, uncertainty about the security of post-quantum algorithm implementations, regulatory requirements, and the maturity of cryptanalysis may justify the continued use of well-established traditional algorithms alongside new post-quantum primitives for a transitional period.

The primary goal of a hybrid key exchange mechanism is to facilitate the establishment of a shared secret which remains secure as long as one of the component key exchange mechanisms remains unbroken.

{{!I-D.ietf-tls-hybrid-design}} specifies a construction for hybrid key exchange in TLS 1.3. This construction achieves the primary goal of hybrid key exchange, ensuring security even if one of the key exchange algorithms is later compromised, while also addressing additional objectives discussed in Section 1.5 of the same document.

Implementations of (D)TLS that are vulnerable to "Harvest Now, Decrypt Later" attacks MUST migrate to (D)TLS 1.3 and implement support for hybrid key exchange as defined in {{!I-D.ietf-tls-hybrid-design}}. For TLS 1.3 implementations, {{!I-D.kwiatkowski-tls-ecdhe-mlkem}} introduces hybrid post-quantum key exchange groups:

* X25519MLKEM768: Combines the classical X25519 key exchange with the ML-KEM-768 post-quantum key encapsulation mechanism.
* SecP256r1MLKEM768: Combines the classical SecP256r1 key exchange with the ML-KEM-768 post-quantum key encapsulation mechanism.

In addition, For deployments requiring pure post-quantum key exchange, {{!I-D.kwiatkowski-tls-ecdhe-mlkem}} defines ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as standalone NamedGroups for achieving post-quantum key agreement in TLS 1.3.

{{!I-D.ietf-tls-hybrid-design}} specifies a construction for hybrid key exchange in TLS 1.3. This construction achieves the primary goal of hybrid key exchange, ensuring security even if one of the key exchange algorithms is later compromised, while also addressing additional objectives discussed in Section 1.5 of the same document.

Applications using (D)TLS that are vulnerable to "Harvest Now, Decrypt Later" attacks MUST migrate to (D)TLS 1.3 and support one of the following approaches:

* Hybrid Key Exchange: This approach combines traditional and post-quantum key exchange algorithms, providing resilience even if one     
  algorithm is compromised. As defined in {{!I-D.ietf-tls-hybrid-design}}, hybrid key exchange ensures continued security during the transition to post-quantum cryptography. For TLS 1.3, {{!I-D.kwiatkowski-tls-ecdhe-mlkem}} introduces hybrid post-quantum key exchange groups:

  1. X25519MLKEM768: Combines the classical X25519 key exchange with the ML-KEM-768 post-quantum key encapsulation mechanism.
  2. SecP256r1MLKEM768: Combines the classical SecP256r1 key exchange with the ML-KEM-768 post-quantum key encapsulation mechanism.

* Pure Post-Quantum Key Exchange: For deployments requiring a purely post-quantum key exchange, {{!I-D.kwiatkowski-tls-ecdhe-mlkem}}  
  defines ML-KEM-512, ML-KEM-768, and ML-KEM-1024 as standalone NamedGroups for achieving post-quantum key agreement in TLS 1.3.

## Optimizing ClientHello for Hybrid Key Exchange in TLS Handshake

The client initiates the TLS handshake by sending a list of key agreement methods it supports in the key_share extension. One of the challenges during the PQC migration is that the client may not know whether the server supports the Hybrid key exchange. To address this uncertainty, the client can adopt one of three strategies:

1. Sending Both Traditional and Hybrid Key Exchange Algorithms: In the initial ClientHello message, the client has the option to send both traditional and hybrid key exchange algorithm key shares to the server, eliminating the need for multiple round trips. It's important to note that the size of the hybrid key exchange algorithm key share may exceed the MTU, leading to the possibility of splitting the ClientHello message across multiple packets. However, this approach necessitates additional computations on the client side and results in increased handshake traffic. During the TLS handshake, the server responds to the ClientHello by providing its public key and ciphertext. If the combined size of these components exceeds the MTU, there's a chance that the ServerHello message may be fragmented across multiple TCP packets. This fragmentation raises the risk of lost packets and potential delays due to retransmission. However, this approach has a disadvantage that a faulty middlebox may drop the split ClientHello message since it's uncommon for a ClientHello message to be split.

2. Indicate Support for Hybrid Key Exchange: Alternatively, the client may initially indicate support for hybrid key exchange and send a traditional key exchange algorithm key share in the first ClientHello message. If the server supports hybrid key exchange, it will use the HelloRetryRequest to request a hybrid key exchange algorithm key share from the client. The client can then send the hybrid key exchange algorithm key share in the second ClientHello message. However, this approach has a disadvantage in that the roundtrip would introduce additional delay compared to the previous technique of sending both traditional and hybrid key exchange algorithm key shares to the server in the initial ClientHello message.

3. {{!I-D.ietf-tls-key-share-prediction}} defines a mechanism for servers to communicate key share preferences in DNS responses. TLS clients can use this information to reduce TLS handshake round-trips.

Clients MAY use information from completed handshakes to cache the server's preferences for key exchange algorithms ({{!RFC8446}}, section 4.2.7). In order to avoid multiple packets to send ClientHello message, the client would have to prevent the duplication of PQC KEM public key shares in the ClientHello, avoiding duplication of key shares is discussed in Section 4 of {{!I-D.ietf-tls-hybrid-design}}.

# Authentication

Although CRQCs could potentially decrypt previous TLS sessions, client/server authentication based on certificates cannot be retroactively compromised. However, due to the multi-year process involved in establishing, certifying, and embedding new root CAs, responding quickly to the emergence of CRQCs, should they arrive earlier than expected, would be challenging. While the migration to post-quantum X.509 certificates has more time compared to key exchanges, delaying this work for too long should be avoided.

The Quantum-Ready authentication property can be utilized in scenarios where an on-path attacker possesses network devices equipped with CRQCs, capable of breaking traditional authentication protocols. If an attacker uses CRQC to determine the private key of a server certificate before the certificate expiry, the attacker can create a fake server, and then every user will think that their connection is legitimate. The server impersonation leads to various security threats, including impersonation, data disclosure, and the interception of user data and communications.

The Quantum-Ready authentication property ensures authentication through either a pure Post-Quantum or a PQ/T hybrid Certificate.

   *  A Post-Quantum X.509 Certificate using the Module-Lattice Digital Signature Algorithm (ML-DSA) is defined in 
   {{?I-D.ietf-lamps-dilithium-certificates}}, and one using SLH-DSA is defined in {{?I-D.ietf-lamps-x509-slhdsa}}. {{?I-D.tls-westerbaan-mldsa}} discusses how ML-DSA is used for authentication in TLS 1.3, while {{?I-D.reddy-tls-slhdsa}} explains how 
   SLH-DSA is used for authentication in TLS 1.3.

   *  A composite X.509 certificate is defined in {{?I-D.ietf-lamps-pq-composite-sigs}}. It defines Composite ML-DSA that is applicable to any application that would otherwise use ML-DSA, but wants the protection against breaks or catastrophic bugs in ML-DSA. {{!I-D.reddy-tls-composite-mldsa}} specifies how the post-quantum signature scheme ML-DSA, in combination with traditional algorithms RSA-PKCS#1v1.5,RSA-PSS, ECDSA, Ed25519, and Ed448 can be used for authentication in TLS 1.3.      

To decide whether and when to support a Post-Quantum Certificate (PQC) or a PQ/T hybrid scheme for client and server authentication, it is important to consider factors such as the frequency and duration of system upgrades, as well as the anticipated availability of CRQCs. Deployments that lack flexibility in enabling or disabling algorithms benefit from hybrid signatures combining a PQC algorithm with a traditional one. This approach avoids risks associated with fallback strategies, where delays in transitioning to PQC leave systems vulnerable to attacks. Hybrid signatures offer immediate protection against zero-day vulnerabilities and ensure resilience during the adoption of PQC, reducing exposure to unforeseen threats.

# Informing Users of PQC Security Compatibility Issues

When the server detects that the client doesn't support PQC or hybrid key exchange, it can send an 'insufficient_security' fatal alert to the client. The client can inform the end-users that the server they are trying to access requires a level of security that the client cannot provide due to the lack of PQC support. Furthermore, the client may log the event for diagnostic and security auditing purposes and report the security-related issue to the client development team.

Similarly, when the client detects that the server doesn't support PQC or hybrid key exchange, it can send an alert or error page to the client. The message can inform the end-user that the server is not compatible with the PQC security features offered by the client.

# Application Protocols

## Encrypted DNS

The privacy risks for end users exchanging DNS messages in clear text are discussed in {{!RFC7518}}. Transport Layer Security (TLS) is employed to ensure privacy for DNS. DNS encryption provided by TLS (e.g., DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC) eliminates opportunities for eavesdropping and on-path tampering while in transit through the network.

Encrypted DNS messages transmitted using Transport Layer Security (TLS) may be vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the TLS key exchange. If an attacker possesses copies of an entire set of encrypted DNS messages, including the TLS setup, it could use a CRQC to potentially decrypt the message content by determining the ephemeral key exchange private key.

Encrypted DNS protocols MUST support the Quantum-Ready usage profile discussed in {#confident}.

Note that post-quantum security of DNSSEC {{?RFC9364}}, which provides authenticity for DNS records, is a separate issue from the requirements for encrypted DNS transports.

## Hybrid public-key encryption (HPKE)

Hybrid public-key encryption (HPKE) is a scheme that provides public key encryption of arbitrary-sized plaintexts given a recipient's public key. HPKE utilizes a non-interactive ephemeral-static Diffie-Hellman exchange to establish a shared secret.  The motivation for standardizing a public key encryption scheme is explained in the introduction of {{?RFC9180}}.

HPKE can be extended to support PQ/T Hybrid post-quantum Key Encapsulation Mechanisms (KEMs) as defined in {{?I-D.connolly-cfrg-xwing-kem}}. 

### Interaction with Encrypted Client Hello {#ech}

Client TLS libraries and applications can use Encrypted Client Hello (ECH) {{?I-D.ietf-tls-esni}} to prevent passive observation of the intended server identity in the TLS handshake which requires also deploying Encrypted DNS (e.g, DNS-over-TLS), otherwise a passive listener can observe DNS queries (or responses) and infer same server identity that was being protected with ECH. ECH uses HPKE for public key encryption.

ECH uses HPKE for public key encryption. ECH deployments will have to incorporate support for PQ/T Hybrid post-quantum KEMs to protect against the 'Harvest Now, Decrypt Later' attack. The public_key in HpkeKeyConfig structure would have to carry the concatenation of traditional and PQC KEM public keys.

## WebRTC

In WebRTC, secure channels are set up via DTLS and DTLS-SRTP {{!RFC5763}} keying for SRTP {{!RFC3711}} for media channels and the Stream Control Transmission Protocol (SCTP) over DTLS {{!RFC8261}} for data channels.

Secure channels may be vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the DTLS key exchange. If an attacker possesses copies of an entire set of encrypted media, including the DTLS setup, it could use CRQC to potentially decrypt the media by determining the private key.

WebRTC media and data channels MUST support the Quantum-Ready usage profile discussed in {#confident}.

The other challenge with WebRTC is that PQC KEMs often come with large public keys and PQC Signature schemes come with large signatures in comparison with traditional algorithms (as discussed in Section 12 and 13 of {{?I-D.ietf-pquip-pqc-engineers}}). In many cases, UDP datagrams are restricted to sizes smaller than 1500 bytes. If IP fragmentation needs to be avoided, each DTLS handshake message must be fragmented over several DTLS records, with each record intended to fit within a single UDP datagram. This approach could potentially lead to increased time to complete the DTLS handshake and involve multiple round-trips in lossy networks. It may also extend the time required to set up secure WebRTC channels.

## HTTPS

HTTPS (Hypertext Transfer Protocol Secure) is the secure version of HTTP used for secure data exchange over the web. HTTPS primarily relies on the TLS (Transport Layer Security) protocol to provide encryption, integrity, and authenticity for data in transit.

HTTP messages transmitted using Transport Layer Security (TLS) may be vulnerable to decryption if an attacker gains access to the traditional asymmetric public keys used in the TLS key exchange. If an attacker possesses copies of an entire set of encrypted HTTP messages, including the TLS setup, it could use CRQC to potentially decrypt the message content by determining the private key. This traffic can include sensitive information, such as login credentials, personal data, or financial details, depending on the nature of the communication.

If an attacker can decrypt the message content before the expiry of the login credentials, the attacker can steal the credentials. The theft of login credentials is a serious security concern that can have a wide range of consequences for individuals and organizations. The most immediate and obvious challenge is that the attacker gains unauthorized access to the victim's accounts, systems, or data. This can lead to data breaches, privacy violations, and various forms of cybercrime.

Applications using HTTPS to exchange sensitive data MUST support the Quantum-Ready usage profile discussed in {#confident}. In similar lines, reverse proxies operated between clients and origin servers will also have to support {#confident}.

# Security Considerations

Post-quantum algorithms selected for standardization are relatively new, and PQC implementations are also new, making them more prone to implementation bugs compared to the battle-tested cryptographic implementations in use today. Additionally, certain deployments may need to retain traditional algorithms due to regulatory requirements, such as FIPS {{SP-800-56C}} or PCI compliance. Hybrid key exchange offers a practical solution, providing protection against "Harvest Now, Decrypt Later" attacks while allowing time to respond to a catastrophic vulnerability in any single algorithm, without fully abandoning traditional cryptosystems.

# Acknowledgements
{:numbered="false"}

Thanks to Dan Wing for suggesting wider document scope. Thanks to Mike Ounsworth, Scott Fluhrer, Bas Westerbaan and Thom Wiggers for review and feedback.


