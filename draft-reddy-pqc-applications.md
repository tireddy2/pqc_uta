---
title: "Post-Quantum Cryptography Recommendations for Internet Applications"
abbrev: "PQC Recommendations"
category: std

docname: draft-reddy-pqc-applications-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "ADD"
keyword:
 - PQC
 - DNS


venue:
  group: "pquip"
  type: "Working Group"
  mail: "pqc@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/pquip/"


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

Post-quantum cryptography brings some new challenges to applications,
end users, and system administrators.  This document describes
characteristics unique to application protocols and best practices for
deploying support


--- middle

# Introduction

All applications are subject to active or passive attack by adversaries, each
to a different degree of importance to the user and to the underlying system.

For data confidentiality of all application protocols, we are
concerned with the so-called "Harvest Now, Decrypt Later" attack where
a malicious actor with adequate resources can launch an attack to
store encrypted DNS data today that can be decrypted once a CRQC is
available. This implies that, every day, data encrypted with legacy
cryptography is susceptible to the attack by not implementing
quantum-safe strategies, as it corresponds to data being deciphered in
the future.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional Algorithm":  An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms or elliptic curve discrete logarithms. In the context of TLS, examples of traditional key exchange algorithms include Elliptic Curve Diffie-Hellman.

"Post-Quantum Algorithm":  An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Examples of PQC key exchange algorithms include Kyber.

"Hybrid" key exchange, in this context, means the use of two key exchange algorithms based on different cryptographic assumptions, e.g., one traditional algorithm and one Post-Quantum algorithm, with the purpose of the final shared secret key being secure as long as at least one of the component key exchange algorithms remains unbroken. It is referred to as PQ/T Hybrid Scheme in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}.

# Timeline for Encrypted DNS transition {#timeline}

The timeline and driving motivation for Quantum-Ready Encrypted DNS transition differ between DNS message confidentiality and DNS server authentication.

Encrypted DNS messages transmitted using Transport Layer Security (TLS) may be vulnerable to decryption if an attacker gains access to the traditional asymmetric keys used in the TLS key exchange. TLS implementations commonly employ Diffie-Hellman schemes for key exchange. If an attacker possesses copies of an entire set of encrypted DNS messages, including the TLS setup, it could use CRQC to potentially decrypt the message content by determining the private key.


For DNS server certificate authentication, it is often the case that the certificate's signature has a very short lifetime, which means that the time between the certificate being signed and its verification during the TLS handshake is limited.

# Application Protocols

> Note: probably want these in alphabetical order or something.

## DNS

### DNS Message Confidentiality

The migration to PQC is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there is a desire or a requirement for protocols that use both algorithm types. The primary goal of a hybrid key exchange mechanism is to facilitate
the establishment of a shared secret which remains secure as long as as one of the component key exchange mechanisms remains unbroken.

{{!I-D.ietf-tls-hybrid-design}} provides a construction for hybrid key exchange in TLS 1.3 version. It meets the the primary goal of hybrid key exchange and other additional goals are discussed in Section 1.5 of {{!I-D.ietf-tls-hybrid-design}}.

Encrypted DNS implementations MUST migrate to TLS 1.3 and support hybrid key exchange defined in {{!I-D.ietf-tls-hybrid-design}}.

### DNS Server Authentication

While CRQCs could retroactively decrypt previous TLS sessions, DNS server authentication cannot be retroactively broken. The Quantum-Ready authentication property can be utilized in scenarios where an on-path attacker possesses network devices equipped with CRQCs, capable of breaking traditional authentication protocols.

The Quantum-Ready authentication property ensures authentication through either a Post-Quantum Certificate or a PQ/T hybrid scheme. A Post-Quantum X.509 Certificate using Dilithium is defined in {{?I-D.ietf-lamps-dilithium-certificates}}. The PQ/T Hybrid Authentication property is currently still under active exploration and discussion in the LAMPS WG, and consensus may evolve over time regarding its adoption.

To decide whether and when to support a Post-Quantum Certificate (PQC) or a PQ/T hybrid scheme for encrypted DNS server authentication, it is important to consider factors such as the frequency and duration of system upgrades, as well as the anticipated availability of CRQCs.

### DNS over Oblivious HTTP

Oblivious HTTP {{?I-D.ietf-ohai-ohttp}} allows clients to encrypt messages exchanged with an Oblivious Target Resource (target). The messages are encapsulated in encrypted messages to an Oblivious Gateway Resource (gateway), which offers Oblivious HTTP access to the target. The gateway is accessed via an Oblivious Relay Resource (relay), which proxies the encapsulated messages to hide the identity of the client. Overall, this architecture is designed in such a way that the relay cannot inspect the contents of messages, and the gateway and target cannot learn the client's identity from a single transaction.

The "ohttp" SvcParamKey defined in {{?I-D.ietf-ohai-svcb-config}} is used to indicate that a service described in an SVCB RR can be accessed as a target using an associated gateway. For the "dns" scheme, as defined in {{!I-D.draft-ietf-add-svcb-dns}}, the presence of the "ohttp" parameter means that the DNS server being described has a DNS over HTTP (DoH) {{!RFC8484}} service that can be accessed using Oblivious HTTP.

Oblivious HTTP uses HPKE {{!RFC9180}} for encapsulating binary HTTP messages to protect their contents. Hybrid public-key encryption (HPKE) is a scheme that provides public key encryption of arbitrary-sized plaintexts given a recipient's public key. DNS over Oblivious HTTP may be vulnerable to decryption if an attacker gains access to the traditional asymmetric keys used in the HPKE. HPKE utilizes a non-interactive ephemeral-static Diffie-Hellman exchange to establish a shared secret. If an attacker possesses copies of an entire set of encapsulated HTTP messages, it could use CRQC to potentially decrypt the message content by determining the private key. The attacker can potentially be the Oblivious Relay Resource.

HPKE can be extended to support hybrid post-quantum Key Encapsulation Mechanisms (KEMs) as defined in {{?I-D.westerbaan-cfrg-hpke-xyber768d00-02}}. Kyber, which is a KEM does not support the static-ephemeral key exchange that allows HPKE based on DH based KEMs. The DNS over Oblivious HTTP protocol MUST incorporate support for hybrid post-quantum KEMs to protect against the 'Harvest Now, Decrypt Later' attack.


## HTTP

## NFS

NFS can use TLS, but prefers using it opportunistically {{!RFC9289}}.  Discuss.

## NTP

NTP can run over TLS {{!RFC8915}}.  Compromise of NTP can cause a system's clock to advance backwards
or forwards from real time, causing either success or failure to use a certificate or other time-based
authenticator.

## SMTP

## IMAP

## FTP

# Security Considerations

Post-quantum algorithms selected for standardization are relatively new and they they have not been subject to the same depth of study as traditional algorithms. PQC implementations will also be new and therefore more likely to contain implementation bugs than the battle-tested crypto implementations that we rely on today. In addition, certain deployments may need to retain traditional algorithms due to regulatory constraints, for example FIPS
{{SP-800-56C}} or PCI compliance. Hybrid key exchange enables potential security against "Harvest Now, Decrypt Later" attack provide for time to react in the case of the announcement of a devastating attack agaist any one algorithm, while not fully abandoning traditional cryptosystems.

# Acknowledgements
{:numbered="false"}

TODO.
