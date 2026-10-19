# Staff Security Engineering: Networking & Protocol Security Study Guide

Each section covers mechanics first, then a **Staff lens** on attack surface, detection impact and design trade-offs.

## Contents

1. [OSI encapsulation: what happens when you `curl`](#1-osi-encapsulation-what-happens-when-you-curl-httpsexamplecom)
2. [ARP and DHCP DORA](#2-arp-and-dhcp-dora)
3. [DNS](#3-dns)
4. [TCP state machine vs UDP](#4-tcp-state-machine-vs-udp)
5. [TTL fingerprinting](#5-ttl-fingerprinting)
6. [HTTP](#6-http)
7. [TLS 1.2 vs TLS 1.3](#7-tls-12-vs-tls-13)
8. [Certificate validation and Certificate Transparency](#8-certificate-validation-and-certificate-transparency)
9. [NAT, BGP and hijacks, VPN/Tor exposure model](#9-nat-bgp-and-hijacks-vpntor-exposure-model)
10. [QUIC and HTTP/3](#10-quic-and-http3)
11. [Encrypted Client Hello (ECH)](#11-encrypted-client-hello-ech)
12. [DoH/DoT and network-level detection](#12-doh-and-dot-and-what-they-do-to-network-level-detection)
13. [BeyondCorp: the trust model shift](#13-beyondcorp-how-it-changes-the-trust-model)
14. [Tying it together](#tying-it-together)

---

## 1. OSI encapsulation: what happens when you `curl https://example.com`

Interviewers use this one to see whether you can trace a request through the whole stack without hand-waving.

**Step 0: Name resolution (before any packet to the target).**
`curl` calls `getaddrinfo()`. On Linux, glibc reads `/etc/nsswitch.conf` to decide the order of sources, usually `files` (`/etc/hosts`) and then `dns`. On modern distros that often means `systemd-resolved` on 127.0.0.53. The stub sends a DNS query, usually UDP/53, to the configured resolver. The DNS query goes through the same L2/L3/L4 steps described below. Its result can be cached by the OS, the browser (not `curl`) or nscd.

**Step 1: Socket and route lookup (L4/L3 setup).**
`curl` calls `socket(AF_INET, SOCK_STREAM)` and `connect()`. The kernel:
- Picks an ephemeral source port. On Linux the range is `net.ipv4.ip_local_port_range`, default 32768–60999.
- Looks up the routing table (`ip route get <dst>`) to choose the egress interface, source IP and next hop. If the destination is off-subnet, the next hop is the default gateway.

**Step 2: L2 resolution.**
To build an Ethernet frame, the kernel needs the next hop's MAC address. That is the gateway's MAC, never the remote server's. It checks the neighbor cache (`ip neigh`). On a miss it ARPs (IPv4) or uses NDP (IPv6). The SYN waits in a queue until resolution completes.

**Step 3: TCP handshake.** SYN, SYN-ACK, ACK. Each segment is encapsulated like this:

```
| Ethernet hdr (14B: dst MAC, src MAC, EtherType 0x0800) |
|   IPv4 hdr (20B+: ver, IHL, DSCP, len, ID, flags/frag, TTL, proto=6, csum, src IP, dst IP) |
|     TCP hdr (20B+ options: src/dst port, seq, ack, flags, window, MSS, SACK, wscale, timestamps) |
|       payload |
| Ethernet FCS (4B) |
```

The SYN carries the **MSS** option, typically 1460 = 1500 MTU − 20 IP − 20 TCP. That matters for PMTUD, for tunnels (VPN, GRE) that shrink the MTU, and for black-holing when ICMP "fragmentation needed" is filtered.

**Step 4: TLS handshake** over the TCP byte stream (see §7). The ClientHello carries SNI, ALPN (`h2`, `http/1.1`) and key shares.

**Step 5: HTTP.** The request goes out as TLS records over TCP: an HTTP/2 HEADERS frame if ALPN chose `h2`, otherwise `GET / HTTP/1.1\r\nHost: example.com\r\n...`.

**What changes hop-by-hop:**
- At each router, the L2 header is stripped and rebuilt with new source and destination MACs.
- TTL is decremented and the IP checksum recomputed.
- With NAT, the source IP and port are rewritten and the L4 checksum fixed, since it covers a pseudo-header that includes the IPs.
- L3 addresses stay constant end to end (except NAT); L2 addresses are link-local.

**What a passive observer sees:**
- **On your LAN:** MACs, IPs, ports, DNS queries (unless DoH/DoT), TLS SNI (unless ECH), the certificate (TLS 1.2 only), timing and size metadata.
- **On the internet path:** everything except your MAC.

> **Staff lens.** Every layer is a trust boundary with its own spoofing problem:
> - L2: ARP spoofing
> - L3: IP spoofing, BGP hijacks
> - L4: RST injection
> - L7: DNS poisoning
>
> Most of the "staff additions" (DoH, ECH, QUIC) are the industry steadily encrypting the metadata that network defenders relied on, which pushes visibility to the endpoint and the proxy.

---

## 2. ARP and DHCP DORA

### ARP (RFC 826)

ARP maps IPv4 addresses to MAC addresses on a broadcast domain.
- **Request:** to broadcast `ff:ff:ff:ff:ff:ff`, EtherType 0x0806: "Who has 10.0.0.1? Tell 10.0.0.23."
- **Reply:** unicast, "10.0.0.1 is at aa:bb:cc:...".
- **Cache:** entries move through states (REACHABLE, STALE, etc.), with timeouts of tens of seconds to minutes on Linux.
- **Gratuitous ARP:** an unsolicited announcement for your own IP. Used for duplicate-address detection, failover (VRRP/HSRP, VIP moves), and updating peers after a NIC change.

**The core flaw: zero authentication.** Hosts accept unsolicited replies and overwrite cache entries. That enables:
- **ARP spoofing/poisoning:** tell the victim "the gateway is at my MAC" and the gateway "the victim is at my MAC". Full on-path (MITM) position. Tools: `arpspoof`, `bettercap`, Ettercap.
- **DoS:** poisoning with a nonexistent MAC black-holes traffic.
- **CAM table flooding** (related): exhausting the switch's MAC table makes it fail open and flood frames like a hub.

**Defenses:**
- **Dynamic ARP Inspection (DAI)**, validating ARP against the DHCP snooping binding table
- **Port security** (limit MACs per port)
- **802.1X**
- **Private VLANs**
- Static ARP entries for critical hosts (doesn't scale)
- Detection with `arpwatch` (alerts on MAC-to-IP flips)
- Ultimately, **don't trust L2**: encrypt above it with TLS or IPsec

**IPv6 equivalent:** NDP (ICMPv6 Neighbor Solicitation/Advertisement) has the same trust problem, plus **rogue Router Advertisements** (announcing yourself as default router, SLAAC attacks). Defenses: RA Guard, SEND (rarely deployed). Classic pentest trick: **mitm6**, abusing DHCPv6 and RAs on IPv4-only Windows networks (Windows prefers IPv6) to become the DNS server and relay NTLM.

### DHCP DORA (RFC 2131)

UDP, server port 67, client port 68. The client has no IP yet.

1. **Discover:** client broadcasts from `0.0.0.0` to `255.255.255.255`, with its MAC (`chaddr`) and requested options.
2. **Offer:** one or more servers offer an IP (`yiaddr`) plus options.
3. **Request:** client broadcasts which offer it accepts, so the other servers know they lost.
4. **Ack:** server confirms the lease. A NAK forces a restart.

**Renewal:** at **T1** (50% of lease) the client unicasts a Request to its server; at **T2** (87.5%) it broadcasts to any server. **Relays** (`ip helper-address`) forward broadcasts across subnets using `giaddr` and can insert **Option 82** (circuit/remote ID).

**Security-relevant options:**

| Option | Meaning |
|---|---|
| 3 | Router |
| 6 | DNS servers |
| 15 | Domain name |
| 42 | NTP |
| **121** | Classless static routes |
| **252** | WPAD URL (proxy autoconfig; historically abused to MITM web traffic) |

**Attacks:**
- **Rogue DHCP server:** hand out the attacker as gateway and DNS: full MITM of every client.
- **DHCP starvation:** exhaust the pool with spoofed MACs, often followed by a rogue server.
- **TunnelVision (CVE-2024-3661):** a rogue DHCP server pushes option 121 routes *more specific* than the VPN's routes. Traffic leaves the physical interface outside the tunnel while the VPN client still shows "connected". Shows why "VPN on hostile Wi-Fi" isn't a complete answer. Android ignores option 121 and was immune. Mitigations: network namespaces, or firewall rules enforcing kill-switch behavior.

**Defenses:**
- **DHCP snooping:** trusted ports only can send Offers/Acks. Snooping builds the binding table used by DAI and IP Source Guard.
- 802.1X
- Monitoring for unexpected DHCP servers

---

## 3. DNS

### Roles and resolution flow

- **Stub resolver:** the OS library. Sends a *recursive* query (RD bit set) and expects a final answer.
- **Recursive resolver:** ISP, 8.8.8.8, 1.1.1.1, or corporate. Does the work and caches.
- **Authoritative servers:** root, TLD, and the domain's own. Answer only for their zones; otherwise return **referrals**.

**Recursive vs iterative:**
- *Recursive:* "get me the final answer." The stub asks the resolver this way.
- *Iterative:* "tell me the best you know." The resolver walks the tree this way and gets referrals.

Iterative walk for `www.example.com`:
1. Resolver asks a root server (known from root hints) → referral: `.com` NS records plus **glue** A/AAAA.
2. Asks a `.com` TLD server → referral to `example.com` NS plus glue.
3. Asks the authoritative server → answer with AA bit set.

Each step is cached for its TTL. **Negative caching** (RFC 2308): NXDOMAIN is cached for the minimum of the SOA minimum field and the SOA record's TTL.

**Glue** exists because if `example.com`'s nameserver is `ns1.example.com`, you'd need to resolve it to reach it, a circular dependency. The parent zone serves its address directly.

**Transport:** UDP/53 by default. TCP/53 for large responses (TC bit), zone transfers (AXFR/IXFR) and DNSSEC-heavy answers. **EDNS0** raises the UDP payload limit; 1232 bytes is the current recommendation to avoid fragmentation.

### Record types

| Type | Purpose | Security note |
|---|---|---|
| A / AAAA | IPv4 / IPv6 address | |
| CNAME | Alias | Can't coexist with other records at the same name. **Dangling CNAMEs** to deprovisioned cloud resources → subdomain takeover. |
| NS | Delegation | Lame or dangling delegations → zone takeover. |
| SOA | Zone metadata (serial, refresh, negative TTL) | |
| MX | Mail exchangers, with priority | |
| TXT | Free-form text | Carries SPF, DKIM (`selector._domainkey`), DMARC (`_dmarc`), verification tokens. Common DNS tunneling channel. |
| SRV | Service location (`_ldap._tcp`, `_kerberos._udp`) | Active Directory depends on it. Useful for recon. |
| PTR | Reverse mapping | See below. |
| CAA | Which CAs may issue for the domain | CAs must check at issuance. Browsers don't check it. |
| HTTPS / SVCB | Service binding (RFC 9460): ALPN, port, IP hints, **ECH config** | Lets clients discover HTTP/3 and ECH before connecting. |
| TLSA | DANE: pins a cert or key in DNS (requires DNSSEC) | Used in SMTP; not supported by browsers. |
| DNSKEY, DS, RRSIG, NSEC, NSEC3 | DNSSEC | |

### PTR and reverse DNS

- IPv4 `203.0.113.7` → `7.113.0.203.in-addr.arpa`. IPv6 uses nibble format under `ip6.arpa`.
- **Who controls PTR:** the owner of the *IP block* (delegated RIR → ISP/cloud), not the forward domain owner. An attacker with their own IP space can set PTR to `mail.google.com`.
- **Never trust PTR alone.** Use **forward-confirmed reverse DNS (FCrDNS)**: resolve PTR, resolve that name's A record, check it matches the original IP. Used as a spam signal by mail servers and to verify claimed crawlers (Googlebot).
- Reverse zones leak naming conventions useful for recon (`vpn-gw-01.corp...`).

### DNS attack landscape

- **Cache poisoning:**
  - **Kaminsky (2008):** query random nonexistent subdomains so each is a fresh race, flood forged responses carrying malicious authority records. Original entropy was only the 16-bit TXID.
  - **Mitigations:** source port randomization (~32 bits combined with TXID), 0x20 encoding (random case in query name), DNSSEC.
  - **SAD DNS (2020):** ICMP rate-limit side channel to infer source port, undoing randomization.
- **Amplification DDoS:** small spoofed query, large response (ANY, DNSSEC answers).
- **Tunneling/exfiltration:** data in subdomain labels and TXT responses (iodine, dnscat2). Detect via label entropy, query volume per domain, unusual record types, long names.
- **DGAs and fast flux** for C2 resilience. Detect via NXDOMAIN spikes, newly observed domains.
- **Registrar/account compromise:** the biggest real-world risk (Sea Turtle, DNSpionage). DNSSEC doesn't help: the attacker changes the DS record or re-signs.

### DNSSEC: mechanism and limits

**Mechanism:**
- Each zone signs RRsets (→ RRSIG) with a **ZSK**.
- The ZSK is signed by the **KSK**, published in DNSKEY.
- The parent publishes a **DS** record (hash of child's KSK), itself signed. The chain runs up to the root KSK trust anchor (rolled in 2018).
- Authenticated denial of existence: **NSEC** ("no names between X and Y") or **NSEC3** (same, with hashed names).

**What it gives you:** data-origin authentication and integrity for DNS answers.

**Limits (high-value for interviews):**
1. **No confidentiality.** Queries and answers stay cleartext. That's DoH/DoT's job; orthogonal.
2. **Last-mile gap.** Most stubs don't validate; they trust the resolver's AD bit. An on-path attacker between stub and resolver can still forge answers unless that link is protected or the stub validates locally.
3. **Doesn't stop registrar, registry or DNS-provider compromise.** Attacker updates DS or controls signing keys.
4. **Zone enumeration.** NSEC allows zone walking. NSEC3 hashes crack offline for guessable names. Mitigated by NSEC3 "white lies" and compact denial.
5. **Amplification.** Large signed responses make better DDoS reflectors.
6. **Operational fragility.** Botched rollovers or expired signatures cause hard outages for every validating resolver (several TLD-level incidents). Many orgs judge availability risk higher than the integrity benefit.
7. **Validator DoS.** **KeyTrap (CVE-2023-50387)**: crafted zones with many keys/signatures forced combinatorial validation work, stalling major resolvers. NSEC3 iteration costs abusable similarly.
8. **Low adoption** in some sectors (many large .com sites); many resolvers don't validate.
9. **Doesn't authenticate the endpoint you connect to**, only the DNS mapping. TLS/certs still do endpoint auth; DANE would bind them but browsers never adopted it.

---

## 4. TCP state machine vs UDP

### TCP connection lifecycle (RFC 9293, obsoletes 793)

```
Client                         Server
CLOSED                         LISTEN
  SYN (seq=x)         ───────►  SYN_RCVD
SYN_SENT ◄─────── SYN-ACK (seq=y, ack=x+1)
  ACK (ack=y+1)       ───────►
ESTABLISHED                    ESTABLISHED
```

Four-way teardown (each direction closes independently, enabling half-close):

```
Active closer                  Passive closer
FIN                 ───────►   CLOSE_WAIT  (app must call close())
FIN_WAIT_1 ◄──────── ACK
FIN_WAIT_2
           ◄──────── FIN       LAST_ACK
ACK                 ───────►   CLOSED
TIME_WAIT (2×MSL) → CLOSED
```

**Key states:**
- **SYN_RCVD:** half-open connection in the SYN backlog. Target of **SYN floods**.
- **CLOSE_WAIT:** peer closed, *your application* hasn't called close. Many of these = app bug (socket/FD leak).
- **TIME_WAIT:** held by the *active closer* for 2×MSL (60s on Linux). Two jobs:
  - Retransmit the final ACK if lost.
  - Prevent delayed segments from an old connection being accepted by a new one with the same 4-tuple.

  Busy clients making many outbound connections can exhaust ephemeral ports this way.
- Simultaneous open/close exist but are rare.

**Reliability machinery:**
- Sequence/ACK numbers, cumulative ACKs plus SACK
- RTO timers, fast retransmit after three duplicate ACKs
- **Flow control** via receive window (with window scaling)
- **Congestion control:** slow start, AIMD, Reno, CUBIC, BBR
- Nagle's algorithm, delayed ACK

**Security-relevant TCP mechanics:**
- **ISN randomization** (RFC 6528). Predictable ISNs enabled blind spoofing (Mitnick, 1994).
- **SYN cookies.** Under SYN flood the server keeps no state; it encodes connection parameters (MSS, timestamp, hash of 4-tuple and secret) into its ISN and reconstructs from the returned ACK. Some options are lost (partly recovered via timestamps).
- **RST injection.** An attacker who knows the 4-tuple and an in-window sequence number can kill the connection. Used by:
  - The Great Firewall (censorship)
  - Comcast against BitTorrent (2007)

  RFC 5961 requires an *exact* sequence match for RST, otherwise a "challenge ACK". That produced **CVE-2016-5696**: the challenge-ACK global rate limit became an off-path side channel to infer sequence numbers. Linux fixed it by randomizing the limit.
- **Session hijacking** is mostly historical given TLS, but explains why "TCP isn't authentication."
- **Scanning signatures:**
  - SYN scan: SYN-ACK = open, RST = closed, nothing = filtered.
  - FIN/NULL/Xmas scans exploit RFC behavior differences; unreliable against Windows (RSTs regardless).
- **Stateful firewalls** track this state machine. Asymmetric routing breaks them; conntrack exhaustion is a DoS vector.

### UDP (RFC 768)

- 8-byte header: src port, dst port, length, checksum (optional in IPv4, mandatory in IPv6).
- No handshake, ordering, retransmission, flow or congestion control.
- Message-oriented: datagram boundaries preserved (vs TCP's byte stream).

**Security implications:**
- **Trivially spoofable source.** No handshake proves return reachability, the basis of **reflection/amplification**: DNS, NTP `monlist` (~500×), memcached (>10,000×), SSDP, CLDAP. Mitigations: BCP 38 ingress filtering, response rate limiting.
- **Firewalls fake state:** "pseudo-connections" with idle timeouts. NAT bindings for UDP expire quickly (often 30–120s), so QUIC, WireGuard and VoIP send keepalives.
- **UDP scanning is slow and ambiguous.** Open ports often don't reply; closed ones return ICMP port unreachable (rate-limited).
- **Protocols needing reliability/security over UDP build their own:** DTLS, QUIC, WireGuard. Each solves **address validation** separately (QUIC's 3× limit and Retry tokens, DTLS cookies).

---

## 5. TTL fingerprinting

**Basis.** Every OS sets a default initial TTL (IPv4) / Hop Limit (IPv6). Each router decrements it. The observed value reveals the likely initial value and hop distance.

| Initial TTL | Typical OS/device |
|---|---|
| 64 | Linux, Android, macOS/iOS, *BSD |
| 128 | Windows |
| 255 | Network gear (Cisco IOS), Solaris, some Unix |

Observed TTL 117 → most likely started at 128: Windows, 11 hops away. Paths rarely exceed ~30 hops, so rounding up to the next common value is reliable.

**TTL is one signal among several** in passive OS fingerprinting (p0f, Zeek, Satori):
- TCP window size and scaling factor
- MSS value; non-1460 suggests a tunnel, VPN or PPPoE (1452)
- TCP options *order* (Linux: MSS, SACK_PERM, TS, NOP, WS; Windows differs)
- DF bit, IP ID behavior (incrementing, random, zero)
- Timestamps (also estimate uptime, clock skew)
- Responses to malformed probes (active fingerprinting, `nmap -O`)

**Practical security uses:**
- **Spoofing/anomaly detection.** Hop-count filtering: a packet claiming to be from a nearby host but arriving with a far TTL is suspicious.
- **Detecting injected packets.** Censorship middleboxes and off-path injectors often get TTL wrong. A forged RST with a different TTL from the rest of the flow is a known detection (used to study the Great Firewall).
- **NAT, tethering and proxy detection.** TTL 63 instead of 64 = an extra hop (phone hotspot). Mixed initial TTLs behind one IP = multiple OSes behind NAT. Carriers have used this to detect tethering.
- **Fraud and bot detection.** TCP/IP fingerprint (Linux, TTL 64) vs User-Agent (claims Windows Chrome) mismatch is a strong bot/proxy signal. Anti-bot vendors combine with **TLS fingerprints**: **JA3** (largely broken once Chrome randomized extension order), **JA4/JA4+**, and HTTP/2 SETTINGS fingerprints.
- **Traceroute** is built on TTL expiry and ICMP Time Exceeded.
- **Evasion.** TTL is trivially configurable (`sysctl net.ipv4.ip_default_ttl`). TTL-based IDS evasion (Ptacek & Newsham, 1998): send packets whose TTL reaches the IDS but expires before the target, desynchronizing reassembly. Mitigation: normalization at the sensor.

> **Staff lens.** Fingerprints are probabilistic evidence, never identity. Use them as features in a scoring model; adversaries who know about them will spoof them.

---

## 6. HTTP

### Versions

- **HTTP/1.0:** one request per TCP connection by default.
- **HTTP/1.1** (RFC 9112):
  - Persistent connections (keep-alive) by default
  - Mandatory `Host` header (enabled virtual hosting)
  - Chunked transfer encoding, caching semantics, range requests
  - Pipelining effectively dead (head-of-line blocking, broken intermediaries); browsers opened ~6 parallel connections per origin instead
- **HTTP/2** (RFC 9113):
  - Binary framing (HEADERS, DATA, SETTINGS, WINDOW_UPDATE, RST_STREAM, GOAWAY, PING, PUSH_PROMISE)
  - Multiplexed streams over **one** TCP connection
  - **HPACK** header compression (static and dynamic tables), designed to resist **CRIME**-style compression oracles
  - Stream prioritization (later deprecated for RFC 9218)
  - Server push (removed from browsers)
  - Still suffers **TCP-level head-of-line blocking**: one lost packet stalls all streams
- **HTTP/3:** HTTP semantics over QUIC (§10).

**Semantics** (RFC 9110):
- Methods: safe (GET, HEAD, OPTIONS), idempotent (also PUT, DELETE), others (POST, PATCH)
- Status classes 1xx–5xx
- Headers case-insensitive; hop-by-hop headers (`Connection`, `Keep-Alive`, `TE`, `Upgrade`) must not be forwarded

### Security-critical HTTP topics

- **Request smuggling.** Front end (CDN/LB) and back end disagree on where a request ends:
  - **CL.TE / TE.CL:** conflicting `Content-Length` and `Transfer-Encoding: chunked`
  - **TE.TE:** obfuscated TE headers one parser honors and the other ignores
  - **H2 downgrade smuggling:** front end speaks HTTP/2, rewrites to HTTP/1.1, and injected CRLF or Content-Length survives
  - **Impact:** request hijacking, cache poisoning, bypassing front-end auth
  - **Defense:** HTTP/2 end to end, strict parsing, reject ambiguous messages, normalize at the edge
- **HTTP/2 protocol DoS:**
  - **Rapid Reset (CVE-2023-44487):** open streams and immediately RST them, bypassing concurrent-stream limits. Record-size DDoS.
  - **CONTINUATION flood (2024):** unbounded header continuation frames
  - HPACK bombs
- **Web cache poisoning and deception:** unkeyed headers (`X-Forwarded-Host`) reflected into cached responses; path-confusion tricks that cache private pages.
- **Host header attacks:** password-reset poisoning, routing to internal vhosts.
- **Cookie security:**
  - `Secure`, `HttpOnly`, `SameSite` (Lax is browser default)
  - `__Host-` and `__Secure-` prefixes
  - Cookies scope by domain and path, *not* port or scheme (classic model): weaker than the same-origin policy
- **Security headers:**
  - **HSTS** (plus preload list) defeats SSL stripping
  - **CSP**, `X-Content-Type-Options: nosniff`, `frame-ancestors`
  - **COOP/COEP/CORP** for cross-origin isolation (post-Spectre)
- **CORS** is a *relaxation* of same-origin policy, not a protection. Reflecting `Origin` while allowing credentials is a critical bug.
- **Proxy-related:** `CONNECT` tunneling; `X-Forwarded-For` is client-controlled unless the edge overwrites it; SSRF via proxies and cloud metadata (IMDSv2 requires PUT plus token with hop limit 1 precisely to defeat SSRF and forwarding).

---

## 7. TLS 1.2 vs TLS 1.3

### TLS 1.2 (RFC 5246): 2-RTT full handshake

```
Client                                    Server
ClientHello (versions, random, ciphers, ext: SNI, ALPN, groups, sig_algs)  →
                     ← ServerHello (chosen suite, random, session id)
                     ← Certificate            (cleartext!)
                     ← ServerKeyExchange      (ECDHE params, signed by cert key)
                     ← ServerHelloDone
ClientKeyExchange (ECDHE pubkey, or RSA-encrypted premaster)
ChangeCipherSpec
Finished (encrypted, MAC over transcript)  →
                     ← ChangeCipherSpec
                     ← Finished
Application Data  ⇄
```

**Key exchange modes:**
- **RSA key transport:** client encrypts the premaster to the server's RSA key. **No forward secrecy**: a later key compromise decrypts recorded traffic. This is exactly how enterprise passive-decryption appliances worked.
- **(EC)DHE:** ephemeral Diffie-Hellman, signed by the cert key. Forward secrecy.

**Other mechanics:**
- Master secret derived via PRF from premaster plus both randoms.
- Resumption via session IDs (server cache) or **session tickets** (state encrypted with a ticket key). Poor ticket-key rotation undermines forward secrecy.
- Renegotiation existed, was attackable (2009, fixed by RFC 5746), used for client-cert step-up.

**1.2-era weaknesses to name:**
- **CBC MAC-then-encrypt:** padding oracles (Lucky13; POODLE on SSLv3)
- **BEAST:** TLS 1.0 IV issue
- **RC4 biases**
- **Compression:** CRIME (and BREACH at HTTP level)
- **Export-grade downgrades:** FREAK, Logjam
- **Triple Handshake**
- **ROBOT / Bleichenbacher:** RSA padding oracles
- **SLOTH:** weak transcript hashes
- **Metadata:** server certificate in cleartext

### TLS 1.3 (RFC 8446): 1-RTT, optional 0-RTT

```
Client                                    Server
ClientHello + key_share (e.g., X25519MLKEM768 + X25519 guesses),
  supported_versions, SNI, ALPN, psk (optional)  →
           ← ServerHello + key_share        (handshake keys derived NOW)
           ← {EncryptedExtensions}          (ALPN, etc. — encrypted)
           ← {CertificateRequest}           (optional)
           ← {Certificate}                  (encrypted)
           ← {CertificateVerify}            (signature over transcript)
           ← {Finished}
           ← [Application Data]             (server can send at 0.5-RTT)
{Finished}                                  →
[Application Data] ⇄
```

**What changed and why:**
- **1-RTT.** Client *guesses* the group and sends key shares upfront. A wrong guess → **HelloRetryRequest** (extra RTT).
- **Encryption right after ServerHello.** Certificate, extensions and CertificateVerify are encrypted; passive observers no longer see the server cert.
  - **Still leaks:** SNI and ALPN in the ClientHello (ECH's job).
- **Massive pruning:**
  - Removed: RSA key transport, static (EC)DH, CBC, RC4, SHA-1/MD5 signatures, compression, renegotiation, custom DH groups.
  - Only AEAD (AES-GCM, ChaCha20-Poly1305, AES-CCM). Five cipher suites, no longer encoding key exchange or auth.
- **Forward secrecy mandatory** for full handshakes. PSK-only resumption without (EC)DHE gives it up for that session, so `psk_dhe_ke` is the usual mode.
- **HKDF key schedule:** Early Secret → Handshake Secret → Master Secret, transcript hashes bound in at each stage. Separate keys per direction and phase; KeyUpdate supported.
- **Downgrade protection:** a 1.3-capable server negotiating ≤1.2 puts a sentinel (`DOWNGRD\x01` / `\x00`) in the last 8 bytes of ServerRandom; client aborts. The random is signed in (EC)DHE, so it can't be stripped.
- **Middlebox compatibility mode.** Disguises as 1.2 resumption: legacy_version 0x0303, real version in `supported_versions`, fake ChangeCipherSpec. Middleboxes broke deployment badly enough to force this.
- **Resumption** via PSK (tickets).
- **0-RTT early data:** client sends app data in its first flight, encrypted under the PSK. **Not replay-protected** at the protocol level.
  - Servers must restrict to idempotent requests or use anti-replay.
  - No forward secrecy with respect to the ticket key.
  - Many deployments disable it or allow GET only.
- **Post-quantum:** hybrid `X25519MLKEM768` is now default in Chrome, Firefox, Cloudflare and others, defending against harvest-now-decrypt-later. Larger key shares (>1 KB) push the ClientHello past one packet and broke some middleboxes.

> **Staff lens: the visibility shift.**
> - Passive decryption with the server private key is impossible (mandatory forward secrecy).
> - The certificate isn't visible on the wire.
> - Inspection now needs an **active terminating proxy** (enterprise interception with an internal CA on endpoints) or endpoint telemetry.
>
> Interception has its own risks. Studies (Durumeric et al., 2017) found many interception products *weakened* security: poor validation, downgraded ciphers. Pinned apps break under it, and it creates a single high-value decryption point. Articulate this trade-off rather than simply recommending "decrypt everything."

---

## 8. Certificate validation and Certificate Transparency

### Path validation (RFC 5280, as browsers implement it)

Given the leaf plus intermediates (sent by server, or fetched via AIA):
1. **Chain building** to a trust anchor in the root store (Mozilla NSS, Chrome Root Store, Apple, Microsoft). Cross-signs create multiple valid paths; path-building bugs cause outages (Let's Encrypt root expiry, 2021).
2. **Signature verification** at each link.
3. **Validity period** (notBefore/notAfter) for every cert in the chain.
4. **Name matching** against **subjectAltName** (dNSName/iPAddress). CN ignored by modern clients. Wildcards match exactly one leftmost label (`*.example.com` ≠ `a.b.example.com` or `example.com`).
5. **Basic Constraints:** intermediates need `CA:TRUE`; pathLen enforced. Bugs here are catastrophic (Moxie's 2002 IE flaw: any leaf could act as a CA).
6. **Key Usage / Extended Key Usage:** `serverAuth` required; EKU constraints on intermediates enforced by browsers.
7. **Name Constraints:** technically constrained intermediates limited to permitted subtrees.
8. **Policy:** EV and Baseline Requirements mostly enforced via root-program policy, not client logic.
9. **Revocation.**
10. **CT policy compliance** (browsers).

**Revocation is a weak link:**
- **CRLs:** large, infrequently fetched.
- **OCSP:** real-time query, leaks browsing to the CA, slow, usually **soft-fail**. An attacker who can MITM can block OCSP, so soft-fail provides little protection.
- **OCSP stapling:** server attaches a fresh response. **Must-Staple** made it mandatory but saw little use.
- **Industry direction:**
  - Chrome never did online OCSP; uses **CRLSets** (curated push list).
  - Firefox uses **CRLite** (compressed filters covering all revocations, built from CT plus CRLs).
  - Let's Encrypt shut down OCSP in 2025 and moved to CRLs; the CA/Browser Forum made OCSP optional.
- **Real mitigation: short lifetimes.** CA/B Forum ballot SC-081 (2025) phases max TLS cert lifetime down:
  - 200 days from March 2026 (current limit)
  - 100 days in 2027
  - 47 days in 2029

  Domain-validation reuse periods shrink in parallel. Forces automation (ACME) everywhere; a big operational topic for Staff roles.

**Issuance-side controls:**
- **CAA records**
- **Multi-perspective issuance corroboration (MPIC):** CAs validate domain control from multiple network vantage points (now required by the Baseline Requirements), because **BGP hijacks have been used to obtain DV certs** (Princeton research).
- DV methods: HTTP-01, DNS-01, TLS-ALPN-01

**Pinning:**
- **HPKP** deprecated (foot-gun and ransom risk).
- Apps still pin, ideally to SPKI hashes with backup pins.
- A few high-value sites keep static pins in browsers.

### Certificate Transparency (RFC 6962; v2 is RFC 9162)

**Problem:** any trusted CA can issue for any domain. Misissuance (DigiNotar 2011, Symantec test certs, others) was undetectable until abused.

**Mechanism:**
- CAs submit certs (or **precertificates**, which carry a poison extension so they're unusable) to multiple independent, append-only **logs**.
- Logs are **Merkle trees**:
  - **Signed Tree Head (STH)** commits to full contents.
  - **Inclusion proofs:** a cert is in the tree.
  - **Consistency proofs:** a newer tree extends an older one; history can't be rewritten.
- Log returns a **Signed Certificate Timestamp (SCT)**: a promise to incorporate within the **Maximum Merge Delay** (24h).
- SCT delivery:
  - Embedded in the certificate (most common)
  - TLS extension
  - Stapled OCSP response
- **Browser enforcement:** Chrome and Safari require SCTs from multiple distinct log operators (count depends on cert lifetime); missing SCTs = failure. Firefox also enforces.
- **Monitors** (crt.sh, Censys, Facebook CT monitor, Cert Spotter) watch logs and alert domain owners to unexpected issuance.
- **Log infrastructure** is migrating to **static/tiled CT logs** (Sunlight, Static CT API), cheaper than RFC 6962 dynamic logs.

**Limits:**
- **Detects, doesn't prevent.** A misissued cert works until noticed and revoked (and revocation is weak).
- Gossip/auditing to catch split-view logs never fully deployed; trust relies on log-operator policy and distrust actions.
- **Privacy and recon leakage.** Every public cert reveals hostnames. Attackers mine CT for subdomains (`jenkins-staging.corp.example.com`) and new phishing domains; defenders mine it for lookalikes. Mitigation: wildcards (with key-compromise blast-radius trade-off) or a private CA for internal names.
- Private/enterprise CAs aren't covered.

---

## 9. NAT, BGP and hijacks, VPN/Tor exposure model

### NAT

- **SNAT/PAT (NAPT):** many private hosts share one public IP. The router tracks (internal IP, internal port, external port, destination) in **conntrack**, rewrites headers and fixes checksums.
- **DNAT / port forwarding:** inbound mapping to an internal host.
- **NAT types** (RFC 4787): endpoint-independent mapping ("full cone") vs address/port-dependent ("symmetric"). Determines whether P2P hole punching works.
- **NAT traversal:** STUN (discover public mapping), TURN (relay), ICE (try candidates). Used by WebRTC, Tailscale, VoIP.

**Security truths:**
- **NAT is not a firewall**, though it produces de facto default-deny for unsolicited inbound.
- **Holes can be punched from inside:**
  - UPnP IGD: malware asks the router to open ports.
  - **NAT Slipstreaming** (Kamkar, 2020): a webpage tricks the router's SIP/H.323 ALG into opening inbound ports to an internal host.
- **IPv6 removes NAT.** Hosts may be globally reachable without a stateful IPv6 firewall. Common gap: IPv4 policy mirrored poorly or not at all for IPv6.
- **CGNAT breaks attribution.** One public IP = thousands of subscribers. Abuse reports and IP reputation suffer collateral damage; investigations need source port plus precise timestamp. Log both.
- **Conntrack exhaustion** is a DoS vector.

### BGP

- Inter-domain routing between Autonomous Systems (ASNs). **Path-vector** protocol over TCP/179.
- **eBGP** between ASes; **iBGP** within one. Policy-driven by business relationships (customer, peer, provider) and **Gao-Rexford** export rules.
- **Best-path selection** (simplified):
  1. Highest LOCAL_PREF
  2. Shortest AS_PATH
  3. Lowest origin type
  4. Lowest MED
  5. eBGP over iBGP
  6. Lowest IGP cost
  7. Tie-breakers
- **Longest-prefix match at forwarding time trumps everything.** A /24 beats a /16 regardless of attributes.
- **Trust model:** historically "believe your neighbors." No built-in authentication of who may originate a prefix or whether a path is real.

**Hijack types:**
- **Origin hijack:** announcing someone else's prefix.
- **More-specific (sub-prefix) hijack:** announce /24s inside a victim's /16; longest-prefix match sends traffic to the attacker globally.
- **Path manipulation / interception:** forged path, or keep a clean return route so traffic is forwarded after inspection. Victim sees only slightly higher latency.
- **Route leaks:** valley-free violations (customer re-announces provider routes to another provider). Usually accidental, devastating.

**Famous incidents:**
- **Pakistan Telecom / YouTube (2008):** more-specific announcement for domestic blocking leaked globally.
- **China Telecom (2010):** ~15% of global routes briefly attracted.
- **MyEtherWallet (2018):** hijack of Amazon Route 53 IP space via eNet; fake DNS for myetherwallet.com; crypto stolen. Users clicked through a cert warning.
- **Verizon / DQE optimizer leak (2019):** took down Cloudflare and others.
- **Facebook (Oct 2021):** not a hijack; self-inflicted **withdrawal** of BGP routes for its DNS prefixes. Showed DNS/BGP dependency and the danger of out-of-band management depending on the same infrastructure.
- **Crypto-targeted hijacks** (KLAYswap 2022, Celer Bridge 2022): BGP hijack → malicious JS or DNS → stolen funds.

**Defenses and gaps:**
- **RPKI:** owners publish signed **ROAs** (prefix, max-length, authorized origin ASN). Routers do **Route Origin Validation** and drop *invalid* routes. Coverage and enforcement have grown substantially among major networks.
  - **Limitation:** validates *origin* only. Forged-origin path attacks (prepending the legitimate ASN) still pass.
  - Loose max-length re-enables sub-prefix hijacks. Best practice: ROA for exactly what you announce.
- **ASPA:** emerging standard letting ASes attest their upstream providers, enabling detection of leaks and forged paths. Early deployment.
- **BGPsec:** full path signing. Essentially undeployed (cost, incremental adoption problem).
- **IRR-based prefix filtering** on customer sessions, peer locking, max-prefix limits, **MANRS** norms.
- **Monitoring:** RIPE RIS, RouteViews, BGPStream, Cloudflare Radar, commercial monitors. Alert on new origins or more-specifics for your prefixes.
- **Application layer:** TLS plus HSTS contains much of the impact (hijacker can't present a valid cert), which is why hijack-to-get-a-DV-cert matters and why MPIC exists.

### VPN and Tor exposure model

Frame it as **"who can see what, and whom must you trust."**

| Observer | No VPN | Commercial/corp VPN | Tor |
|---|---|---|---|
| Local network / ISP | Destination IPs, DNS (unless DoH), SNI, timing/sizes | Only that you talk to the VPN endpoint, plus timing/volume | That you use Tor (guard or bridge IP); obfuscated with pluggable transports |
| VPN provider | n/a | **Everything the ISP used to see**, plus your real IP. Trust has *moved*, not disappeared. | n/a |
| Destination | Your IP | VPN egress IP | Exit relay IP (or nothing, for onion services) |
| Single relay | n/a | n/a | Guard knows you not the destination; exit knows the destination not you; middle knows neither |
| Exit relay | n/a | n/a | Plaintext if app traffic isn't TLS-protected |

**VPN failure modes:**
- DNS leaks (resolver outside the tunnel)
- IPv6 leaks (IPv4-only tunnel)
- WebRTC exposing local/public IPs
- Split-tunnel misconfiguration
- **TunnelVision** (§2)
- **TunnelCrack** (2023): LocalNet and ServerIP attacks abusing routing exceptions
- Kill-switch gaps during reconnect
- **Corporate VPN as a threat surface:** concentrators (Ivanti, Fortinet, Citrix, Palo Alto) are among the most exploited edge devices in recent years. VPNs also grant *network-level* access, the root of BeyondCorp's critique (§13).

**Tor:**
- Three-hop onion routing, layered encryption; each relay peels one layer.
- Circuits rotate ~every 10 minutes for new streams.
- **Guards** are long-lived (months) to limit eventually picking a malicious entry.
- **Threats:**
  - **End-to-end traffic correlation** by an adversary seeing both ends (global passive adversary, or controlling guard and exit, or observing those ASes). AS-level adversaries plus BGP manipulation (RAPTOR) increase risk.
  - Website fingerprinting from traffic shape.
  - Malicious exits (SSL stripping, injection); Sybil relay campaigns have run.
  - Application leaks (browser exploits, plugins, DNS outside Tor, documents that phone home).
  - OPSEC failures are the most common real-world deanonymizer.
- **Onion services** keep traffic inside Tor (no exit); rendezvous circuits on both sides; address is the service's public key.
- **Defender angle:** relay lists are public (consensus, exit lists), so enterprises can detect/block Tor. Bridges and pluggable transports (obfs4, Snowflake, WebTunnel) exist to defeat that.

---

## 10. QUIC and HTTP/3

**What it is** (RFC 9000/9001/9002; HTTP/3 is RFC 9114): a transport over **UDP** (usually 443) implementing reliability, congestion control, streams and **TLS 1.3 integrated into the transport**, mostly in user space.

**Key properties:**
- **Combined handshake:** transport and crypto in 1-RTT, 0-RTT on resumption (same replay caveats as TLS 1.3). TCP+TLS 1.3 needs 2 RTT.
- **Independent streams:** a lost packet stalls only its own stream, removing TCP head-of-line blocking. **QPACK** replaces HPACK (which assumed in-order delivery).
- **Connection IDs and migration:** connections identified by CID, not 4-tuple. Wi-Fi → cellular keeps the connection. Clients rotate CIDs on migration to resist linkability.
- **Almost everything encrypted:** packet numbers (header protection), ACKs, stream frames. Visible: header form, version (long headers), CIDs, optional **spin bit** for passive RTT measurement.
- **Anti-ossification by design:** denies middleboxes visibility so they can't calcify the protocol (lesson from TCP). Versions and GREASE keep extension points alive.
- **Discovery:** via `Alt-Svc` header or **DNS HTTPS records** (alpn=h3). Clients race TCP and QUIC ("happy eyeballs").

**Security mechanics:**
- **Initial packets are encrypted with keys derived from the client's Destination Connection ID and a version-specific public salt.** Anyone on-path can decrypt Initials, so **the ClientHello (and SNI) is readable** by QUIC-aware middleboxes. This encryption only prevents ossification and casual tampering; ECH is needed to hide SNI.
- **Amplification limit:** before address validation, a server sends at most 3× bytes received. Hence clients pad Initials to ≥1200 bytes.
- **Retry tokens:** stateless address validation, like SYN cookies.
- **Stateless reset** tokens.
- **Version Negotiation** and anti-downgrade.

**Defender/enterprise implications:**
- Legacy firewalls, IDS and proxies often can't parse QUIC; TLS-interception proxies don't intercept UDP 443.
- **Common control: block UDP 443.** Browsers fall back to TCP+TLS, which the proxy can inspect. Chrome/Edge have policies to disable QUIC.
- Next-generation firewalls increasingly decrypt Initials to read SNI for policy.
- Logging: Zeek has QUIC analyzers. Less flow fidelity: no SYN/FIN, and migration complicates 5-tuple flow records.
- **DDoS:** UDP floods to 443 look legitimate. Retry tokens and rate limits defend.
- **C2:** frameworks can tunnel C2 over QUIC to evade TCP-centric inspection.

---

## 11. Encrypted Client Hello (ECH)

**Problem.** Even with TLS 1.3 and DoH, the **SNI** in the ClientHello reveals the destination hostname. Used by:
- Censors (SNI filtering is extremely common)
- ISPs (analytics)
- Enterprise web filters
- Passive surveillance

**History.** ESNI (~2018) encrypted only the SNI extension and was abandoned. ECH encrypts the **entire inner ClientHello**. Supported by Firefox, Chrome and Cloudflare.

**Mechanism:**
1. **Config discovery:** operator publishes an **ECHConfig** (HPKE public key, `public_name`, cipher options) in the **DNS HTTPS/SVCB record**.
2. **ClientHelloOuter:** SNI is the innocuous `public_name` (e.g. `cloudflare-ech.com`). Inside an `encrypted_client_hello` extension is the **ClientHelloInner** (real SNI, ALPN, etc.), HPKE-encrypted to the config key. Shared extensions are compressed to save bytes.
3. **Client-facing server** (CDN front end) decrypts and completes the handshake for the real backend: itself ("shared mode") or a backend ("split mode").
4. **Fallback:** if decryption fails (stale config), the server completes the handshake *as* `public_name` and returns **retry_configs**. The client retries securely; it never falls back to cleartext SNI for the real name.
5. **GREASE ECH:** clients without a config send random fake ECH extensions, so presence of ECH isn't a distinguishing signal.

**Dependencies and limits:**
- **Needs DNS privacy.** If the HTTPS record lookup is cleartext, the observer already saw the hostname. In practice **ECH is coupled with DoH**; browsers enable it primarily with secure DNS.
- **Anonymity set = the provider.** ECH hides *which* site among those behind the same client-facing server (and IP). Works well behind large CDNs; poorly for single-tenant servers where the IP reveals the site.
- **Censors can block it:** block the public_name, drop ECH connections, strip HTTPS records. Russia blocked Cloudflare ECH in 2024; China blocks ECH and ESNI.
- Traffic analysis (sizes, timing) still applies.

**Enterprise/detection impact:**
- SNI-based URL filtering, SNI logging, and "decrypt or bypass" policies keyed on SNI break for ECH flows. You see only the IP and the public_name.
- **Options:**
  1. **Disable ECH via managed browser policy.**
  2. **Control DNS:** internal resolver strips the `ech` SvcParam from HTTPS records, combined with blocking external DoH.
  3. **Full TLS-interception proxy:** browsers don't use ECH with a detected intercepting proxy, or the proxy terminates the connection.
  4. **Move policy to the endpoint:** browser extension/agent, EDR, or secure web gateway agent seeing the URL before encryption.
- **Malware angle:** C2 fronted through ECH-enabled CDNs hides SNI-based IOCs. The modern evolution of **domain fronting** (which CDNs mostly blocked by enforcing SNI/Host consistency).

---

## 12. DoH and DoT, and what they do to network-level detection

**Protocols:**
- **DoT** (RFC 7858): TCP/853. Dedicated port; easy to identify and block.
- **DoH** (RFC 8484): DNS wire format over HTTPS on 443, POST or GET (`?dns=` base64url). **Blends into web traffic**, especially when the resolver shares IPs/domains with other services.
- **DoQ** (RFC 9250): DNS over QUIC.
- **ODoH** (Oblivious DoH): splits trust between proxy and target so no single party sees both client IP and query.
- **DDR** (RFC 9462): lets a network advertise an encrypted version of its own resolver. The cooperative path for enterprises and ISPs.

**What they protect:**
- Confidentiality and integrity of the stub-to-resolver hop against on-path observers and tampering (hotel Wi-Fi, ISP injection, ISP-level DNS censorship).
- **Not** resolver-to-authoritative traffic (still mostly cleartext).
- **Not** the resolver's visibility. Trust moves to the DoH provider (same shift as a VPN).

**What breaks for defenders when clients use external DoH:**
1. **DNS logging/visibility.** Passive DNS from network sensors (Zeek `dns.log`, firewall DNS logs) goes dark. Loses one of the highest-value, cheapest data sources: DGA detection, newly-observed-domain alerts, beaconing to rare domains, tunneling detection.
2. **Protective DNS policy.** RPZ, sinkholing, malware blocking and content filtering at the corporate resolver are bypassed.
3. **Split-horizon DNS.** Internal names fail via public DoH, breaking things and leaking internal names to third parties.
4. **Malware using DoH.** Godlua, PsiXBot and others resolved C2 over DoH; DoH to an attacker endpoint can itself *be* the C2 channel.
5. **Combined with ECH and QUIC**, the network may see only an IP and opaque UDP/TCP.

**Mitigations (layered):**
- **Policy:** enterprise browser policies (Chrome `DnsOverHttpsMode`, Firefox TRR policies, Windows DoH via GPO). Firefox checks the **canary domain** `use-application-dns.net`: NXDOMAIN from the corporate resolver disables default DoH rollout. It governs default enablement only, not user or malware choice.
- **Sanctioned encrypted resolver:** run internal DoH/DoT and advertise it (DDR, DHCP/RA encrypted-DNS options). Keeps logging and filtering while protecting the local link.
- **Egress controls:**
  - Block TCP/853.
  - Block known public DoH endpoints by IP/domain lists (imperfect: anyone can run DoH on any HTTPS host).
  - Force all DNS (UDP/TCP 53) to internal resolvers.
  - Default-deny egress for servers where an allowlist is feasible (harder for workstations).
- **TLS inspection** at the proxy identifies `application/dns-message` content type and DoH URL patterns.
- **Move detection to the endpoint** (the strategic answer):
  - Windows DNS Client ETW, or Sysmon Event ID 22 (DnsQuery), logs lookups before encryption regardless of transport, for apps using the OS resolver. Browsers or malware with their own DoH stack bypass it.
  - EDR process-to-network correlation.
  - Browser telemetry and extensions.
- **Behavioral network analytics** without payload: JA4 fingerprints of unusual TLS clients, beacon periodicity, long-lived low-volume flows, non-browser processes connecting to DoH providers.

> **Staff synthesis.** DoH, ECH, QUIC and TLS 1.3 together turn the network into a source of *flow metadata*, not content. A mature program assumes this: invest in endpoint telemetry, identity-aware proxies and managed browsers; keep network sensors for metadata, reachability enforcement and the unmanaged-device blind spot.

---

## 13. BeyondCorp: how it changes the trust model

**Origin.** After **Operation Aurora** (2009), nation-state attackers compromised Google's corporate network. Google concluded castle-and-moat was fundamentally broken: once inside the perimeter (phishing, compromised VPN user, vulnerable edge device), attackers moved laterally because "internal" implied "trusted." BeyondCorp papers published from 2014. Generalized as **Zero Trust**, formalized in NIST SP 800-207 (2020).

**Core principles:**
1. **Network location confers no trust.** The corporate LAN is treated like the internet; Google moved users onto an "unprivileged network."
2. **Access decisions combine user identity, device identity/posture, and context**, evaluated **per request**.
3. **All access is authenticated, authorized and encrypted**, same path from office or café. VPN eliminated for most apps.
4. **Access is dynamic and least-privilege**, changeable mid-session as posture changes.

**Components** (BeyondCorp names / NIST equivalents):
- **Device inventory database:** source of truth for every managed device, aggregated from multiple systems.
- **Device identity:** per-device certificate, ideally hardware-bound (TPM, Secure Enclave), proving "this request comes from managed device X." Posture: OS patch level, disk encryption, EDR health, screen lock, management status.
- **User identity:** SSO via the IdP with strong MFA. Phishing-resistant FIDO2/WebAuthn keys are critical; Google famously eliminated successful employee phishing with them.
- **Access proxy** (Policy Enforcement Point): internet-facing reverse proxy (e.g. Google's Identity-Aware Proxy) in front of every internal app. Terminates TLS, authenticates user and device, forwards only if policy passes.
- **Access control engine / trust inference** (Policy Decision Point): computes a **trust tier** from signals, matched against per-app requirements (HR systems need a fully managed, patched device; the lunch menu allows any authenticated device).
- **Pipeline:** continuously feeds posture changes into decisions.

**"Trust the host, not the network": the nuance to raise.** More precisely: *derive trust from verified identity (user and device) and current posture, never from network position, and continuously re-evaluate it.*
- The host isn't trusted unconditionally. It earns a tier by *proving* identity (hardware-bound cert) and posture.
- Trust is revocable in near real time: unpatched, EDR alert, lost device.

The shift is from *implicit, location-based* trust to *explicit, attested, per-request* trust.

**What it improves:**
- Lateral movement shrinks: a compromised laptop gets only the apps its tier allows, through a proxy that logs everything.
- Removes the VPN concentrator as a crown-jewel attack surface and SPOF (very relevant given recent VPN appliance exploitation waves).
- Uniform, centralized, app-aware logging and policy at the proxy, ironically restoring the L7 visibility that encrypted transport took from network sensors.
- Better UX and remote-work readiness.

**What it shifts or creates (the Staff-level critique):**
- **The IdP and device-trust system become the crown jewels.** IdP compromise, SSO misconfig and device-enrollment abuse can bypass everything (Okta-related incidents illustrate this).
- **Session/token theft becomes the primary attack.** Infostealers lift session cookies; AiTM phishing kits (Evilginx-style) proxy logins. Countermeasures:
  - Phishing-resistant MFA (WebAuthn is origin-bound, defeating AiTM)
  - **Device-bound session credentials** (Chrome's DBSC binds cookies to a TPM key)
  - Short session lifetimes, continuous access evaluation (CAEP)
  - Token binding to device certificates
- **Posture signals can be spoofed** if self-reported by a compromised host. Prefer attested signals (TPM health attestation), corroborate with EDR.
- **Non-HTTP protocols** (SSH, RDP, databases, legacy thick clients, OT) are harder to proxy. Need TCP-forwarding proxies/tunnels (IAP TCP forwarding), per-app connectors, or identity-aware microsegmentation; some legacy systems keep a "VPN island."
- **Unmanaged devices, contractors, BYOD** need a lower-trust path: browser isolation, VDI, restricted tiers.
- **East-west service-to-service traffic.** BeyondCorp is primarily *user-to-app*. Machine equivalent: workload identity (SPIFFE IDs, mTLS service meshes, Google's BeyondProd/ALTS).
- **Migration is the hard part.** Google's papers describe multi-year incremental migration: inventory first, then traffic simulation ("would this request be allowed?"), then per-app cutover. Expect *how would you roll this out in a brownfield org*, not just *what is it*.

**Detection implications:** primary telemetry moves to:
- Access-proxy logs (who, which device, which tier, which app, which decision)
- IdP logs (impossible travel, MFA fatigue, new device enrollment, token anomalies)
- EDR (posture and compromise signal)

Network detection stays useful for unmanaged-device discovery, egress anomalies and infrastructure, but stops being the security boundary.

---

## Tying it together

The common thread is a **migration of trust and visibility**:
- **Integrity and confidentiality** moved up the stack. L2/L3 trust (ARP, DHCP, BGP, DNS) is unauthenticated or weakly authenticated, so we encrypt and authenticate at L4–L7 (TLS 1.3, QUIC, DoH, ECH) and at identity (WebPKI, CT, FIDO2).
- **Metadata** is progressively removed from the wire: certificate (TLS 1.3), DNS (DoH), SNI (ECH), transport headers (QUIC). The network becomes a flow-metadata and enforcement layer.
- **Access control** moved from network location (perimeter, VPN) to attested identity plus device posture at an app-aware proxy (BeyondCorp).
- So **detection** must move to the endpoint, IdP and proxy, keeping network controls for egress restriction, segmentation and unmanaged blind spots.

If you can explain each technology *and* where it sits on that arc, including the trade-offs (privacy vs enterprise visibility, availability vs integrity with DNSSEC, interception vs end-to-end security), that's the Staff-level answer.
