---
title: "Post-Quantum Cryptography Usage Profile for Encrypted DNS"
abbrev: "PQC Usage Profile for Encrypted DNS"
category: std

docname: draft-reddy-add-pqc-dns
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Internet"
workgroup: "ADD"
keyword:
 - PQC
 - DNS
 

venue:
  group: "add"
  type: "Working Group"
  mail: "add@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/add/"
  

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

This document discusses Quantum-Ready usage profiles for encrypted DNS (e.g., DNS-over-HTTPS, DNS-over-
TLS, DNS-over-QUIC). 

--- middle

# Introduction

The privacy risks for end users exchanging DNS messages in clear text are discussed in {{!RFC7518}}. Transport Layer Security (TLS) is employed to ensure privacy for DNS. DNS encryption provided by TLS eliminates opportunities for eavesdropping and on-path tampering while in transit through the network.

The presence of a Cryptographically Relevant Quantum Computer (CRQC) would render state-of-the-art, traditional public-key algorithms deployed today obsolete, since the assumptions about the intractability of the mathematical problems for these algorithms that offer confident levels of security today no longer apply in the presence of a CRQC.

This document discusses Quantum-Ready usage profiles for encrypted DNS (e.g., DNS-over-HTTPS, DNS-over-
TLS, DNS-over-QUIC) to protect from passive and on-path attacks using CRQCs. 

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional Algorithm":  An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms or elliptic curve discrete logarithms. In the context of TLS, examples of traditional key exchange algorithms include Elliptic Curve Diffie-Hellman. 

"Post-Quantum Algorithm":  An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Examples of PQC key exchange algorithms include Kyber.

"Hybrid" key exchange, in this context, means the use of two key exchange algorithms based on different cryptographic assumptions, e.g., one traditional algorithm and one Post-Quantum algorithm, with the purpose of the final shared secret key being secure as long as at least one of the component key exchange algorithms remains unbroken. It is referred to as PQ/T Hybrid Scheme in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. 

# Timeline for Encrypted DNS transition {#timeline}

The timeline and driving motivation for Quantum-Ready Encrypted DNS transition differ between DNS message confidentiality and DNS server authentication.

Encrypted DNS messages transmitted using Transport Layer Security (TLS) may be vulnerable to decryption if an attacker gains access to the traditional asymmetric keys used in the TLS key exchange. TLS implementations commonly employ Diffie-Hellman schemes for key exchange. If an attacker possesses copies of an entire set of encrypted DNS messages, including the TLS setup, they could use CRQC to potentially decrypt the message content by determining the private key.

For data confidentiality of encrypted DNS, we are concerned with the so-called "Harvest Now, Decrypt Later" attack where a malicious actor with adequate resources can launch an attack to store encrypted DNS data today that can be decrypted once a CRQC is available. This implies that, every day, encrypted DNS data is susceptible to the attack by not implementing quantum-safe strategies, as it corresponds to data being deciphered in the future.  

For DNS server certificate authentication, it is often the case that the certificate's signature has a very short lifetime, which means that the time between the certificate being signed and its verification during the TLS handshake is limited.

# DNS Message Confidentiality

The migration to PQC is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there is a desire or a requirement for protocols that use both algorithm types. The primary goal of a hybrid key exchange mechanism is to facilitate
the establishment of a shared secret which remains secure as long as as one of the component key exchange mechanisms remains unbroken. 

{{!I-D.ietf-tls-hybrid-design}} provides a construction for hybrid key exchange in TLS 1.3 version. It meets the the primary goal of hybrid key exchange and other additional goals are discussed in Section 1.5 of {{!I-D.ietf-tls-hybrid-design}}. 

Encrypted DNS implementations MUST migrate to TLS 1.3 and support hybrid key exchange defined in {{!I-D.ietf-tls-hybrid-design}}.

# DNS Server Authentication

While CRQCs could retroactively decrypt previous TLS sessions, DNS server authentication cannot be retroactively broken. The Quantum-Ready authentication property can be utilized in scenarios where an on-path attacker possesses network devices equipped with CRQCs, capable of breaking traditional authentication protocols. 

The Quantum-Ready authentication property ensures authentication through either a Post-Quantum Certificate or a PQ/T hybrid scheme. A Post-Quantum X.509 Certificate using Dilithium is defined in {{?I-D.lamps-dilithium-certificates}}. The PQ/T Hybrid Authentication property is currently still under active exploration and discussion in the LAMPS WG, and consensus may evolve over time regarding its adoption.

To decide whether and when to support a Post-Quantum Certificate (PQC) or a PQ/T hybrid scheme for encrypted DNS server authentication, it is important to consider factors such as the frequency and duration of system upgrades, as well as the anticipated availability of CRQCs.

# Security Considerations

Post-quantum algorithms selected for standardization are relatively new and they they have not been subject to the same depth of study as traditional algorithms. PQC implementations will also be new and therefore more likely to contain implementation bugs than the battle-tested crypto implementations that we rely on today. In addition, certain deployments may need to retain traditional algorithms due to regulatory constraints, for example FIPS 
{{SP-800-56C}} or PCI compliance. Hybrid key exchange enables potential security against "Harvest Now, Decrypt Later" attack provide for time to react in the case of the announcement of a devastating attack agaist any one algorithm, while not fully abandoning traditional cryptosystems.

# Acknowledgements
{:numbered="false"}

TODO.