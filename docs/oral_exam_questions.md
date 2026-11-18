# Possible Oral-Exam Questions — CoAP Amplification Project × 34371 Course

Format: individual oral exam after the group presentation (Dec 2). Questions
typically **start from your project and pull toward the wider course** (L1–L8),
and probe whether you *personally* understand the mechanisms, not just the demo.

Course note: the teacher said **"we are not interested in encryption/cryptography"**
— so questions about DTLS/OSCORE will be about the *handshake / address-validation
mechanism and overhead*, not cipher internals.

---

## A. Project core — CoAP & the amplification mechanism

1. What is CoAP and why was it designed? Who uses it and why not just use HTTP?
2. Walk me through the CoAP message format (header, token, options, payload). How big is the smallest request?
3. What exactly is an amplification attack? Define the amplification factor.
4. Why is CoAP vulnerable to this when HTTP (over TCP) largely is not?
5. What is "NoSec" mode and why does it enable the attack?
6. Draw the attack: who sends what to whom, and where does the spoofing happen?
7. You measured amplification at the UDP layer and the IP layer and got different numbers — why? Which layer "counts" and why?
8. Which CoAP feature gives the *largest* factor, and why? (Observe → c·n, multicast → c·m, combined → c·n·m)
9. What is the CoAP Observe option? Why does one request produce many responses?
10. What is a multicast/group request, and why does it give c·m from a *single* packet?
11. In your tests, which attack had the highest factor and what was the number? Explain it.
12. What limits the amplification in practice? (saturation, constrained-link bandwidth — tie to the Oliveira paper)

## B. L1 — OSI model & IoT context

13. Place your attack on the OSI model. Which layers are involved, and at which layer is the *victim* under attack?
14. Why are IoT/constrained devices especially relevant to this attack? (resources, numbers, exposure)
15. Your attack uses UDP at L4, CoAP at L7, spoofing at L3 and tools at L2 — explain how one attack spans the stack.

## C. L2 — Sniffing & Spoofing (Scapy / Wireshark / attack phases)

16. The course defines cyber-attack phases (recon, scanning, accessing, …). Map your attack onto them. Where does discovery/`/.well-known/core` fit?
17. What is spoofing? What is sniffing? Which does your attack rely on, and which did you use to *measure* it?
18. How would you use Wireshark to demonstrate and measure this attack? What would you filter on?
19. The course teaches Scapy for spoofing — you used raw sockets instead. What's the difference, and how do you forge a source IP?
20. How do you *prove* amplification happened with a packet capture? What two numbers do you need and where do you capture them?
21. Could an IDS detect this? What signature would it look for?

## D. L3 — MAC layer / ARP

22. Your attacker is on the same subnet as the reflector. If the victim were on a *different* L2 segment, would the attack still work? What changes?
23. Multicast/group CoAP requests "have to be sent by a node on the local network." Why? How does ARP / L2 broadcast relate?
24. Could ARP cache poisoning (L3 lecture) turn a unicast attacker into a MITM amplifier? How does that relate to the draft's MITM attacks?
25. In your lab you hit a bug where responses went to a stale MAC. Explain what happened in ARP/neighbor-table terms.

## E. L4 — IP layer (fragmentation, ICMP)

26. Your amplification factor depends on IP packet size. What is the MTU, and what happens if a CoAP response exceeds it?
27. How does IP fragmentation interact with amplification? Could an attacker exploit fragmentation to amplify further, or does Block-wise transfer prevent it?
28. The RFC suggests Block2 slicing as a mitigation. Explain how capping response size caps the factor — tie to MTU/fragmentation.
29. UDP has no handshake, so the server can't verify the source. Contrast with how ICMP-based attacks (L4) also abuse spoofed sources.
30. Why can't the server just send an ICMP error back to stop the attack? (it would hit the victim too)

## F. L5 — Transport layer (THE core lecture for your project)

31. UDP vs TCP: list the differences. Which properties of UDP make reflection possible?
32. The course covered UDP DRDoS (Distributed Reflection DoS) with DNS amplification. Compare CoAP amplification to DNS amplification — same mechanism? Different factor?
33. Why can't you do a classic reflection attack over TCP? (3-way handshake, SYN, sequence numbers)
34. Compare CoAP amplification to the TCP SYN-flood attack from the course. Both are DoS — how do they differ (resource exhausted, spoofing role, amplification vs flooding)?
35. SYN cookies defend SYN floods by not allocating state until the client proves reachability. Is CoAP's Echo option the same idea? Explain the analogy.
36. What's the difference between a *flooding* DoS and an *amplification* DoS? Is your attack both?
37. The draft cites QUIC's "3× rule." What is it, and why is it considered best practice? Why is it hard to apply to CoAP multicast?
38. Why does the attacker spoof the *victim's* IP as the source? Walk through the packet addresses.

## G. L6 — Application layer (CoAP vs MQTT)

39. The course taught MQTT and CoAP side by side. Why is MQTT *not* a good reflection/amplification vector but CoAP is? (TCP + broker + pub/sub vs UDP + request/response)
40. MQTT uses a broker (pub/sub); CoAP is client/server REST. How does that architectural difference affect the attack surface?
41. What are CoAP's security modes (NoSec, PreSharedKey, RawPublicKey, Certificate)? Which stops amplification and how?
42. If you were defending an MQTT deployment vs a CoAP deployment, what would differ?
43. CoAP has QoS-like reliability (CON/NON/ACK/RST). How do confirmable vs non-confirmable messages matter for the attack and for spoofing ACKs?

## H. L7 / L8 — Wireless & long-range IoT

44. Your lab used wired Docker containers. Real IoT uses WiFi/BLE/LoRa. How would the constrained radio change your amplification results? (tie to Oliveira's saturation)
45. Could this amplification attack be launched over LoRaWAN or NB-IoT? What limits it there (duty cycle, bandwidth, downlink constraints)?
46. On a constrained 6LoWPAN network (the Oliveira setup), why did the measured factor collapse far below the theoretical c·m?
47. Compare the "victim" in your attack (an Internet host) vs the constrained network itself becoming the victim. Which is more realistic and why?
48. WiFi deauth (L7) is also a DoS. Contrast a jamming/deauth DoS with an amplification DoS in terms of attacker capability and reach.

## I. Mitigations / "act as a defender" (required report section)

49. List every mitigation you considered and say which attack each one stops.
50. How does the **Echo option (RFC 9175)** work? Why does it defeat unicast spoofing but *not* multicast?
51. Why is rate-limiting per server insufficient against multicast amplification? (unknown number of servers m)
52. The RFC uses "SHOULD" not "MUST" for most mitigations. Why is that a problem, per the draft? What does "a large amplification factor" even mean?
53. How does DTLS/OSCORE stop the attack — specifically, what does address validation do? (not the crypto — the reachability binding)
54. What's the trade-off of each mitigation for a constrained device? (handshake cost, state, battery)
55. If you ran the same attacks against your *hardened* server, what results do you predict and why?
56. Can you fully mitigate multicast amplification? If not, what's the residual risk?

## J. Methodology, measurement & your testbed design

57. Why did you build two testbeds (aiocoap and libcoap)? What does using two implementations prove?
58. How did you measure the amplification factor, and how do you know your numbers are correct?
59. You found that reusing the CoAP Message-ID got your requests silently dropped. Explain (dedup, RFC 7252 §4.5). Why is varying it part of a *working* attack?
60. How did you ensure the lab was safe/contained? Why does that matter ethically and legally?
61. What are the limitations of your testbed vs a real deployment? (no radio, no real constrained CPU, L2-local)
62. If a reviewer said "your 800× factor is unrealistic," how would you defend or qualify it?
63. Why did you choose Docker over a simulator like ns-3 or Cooja? What did you give up?

## K. Depth / "gotcha" questions (to separate a 10 from a 7)

64. At which protocol layer is the amplification factor highest, and why does it *increase* up the stack while bandwidth decreases?
65. The draft says even equal-size responses from m servers give factor m. Explain.
66. Could an attacker increase c without a big static resource? (POST/PUT a large resource first; grow `/.well-known/core`)
67. What is `pmax` and how does it worsen the Observe attack?
68. Cross-protocol attack (RFC 7252 §11.5): how could a CoAP reflector be abused to attack a *non-CoAP* UDP service? Why does the DNS/CoAP header overlap matter?
69. If the server sends notifications as Confirmable (CON) and the victim doesn't ACK, what happens on the server side? (retransmit, state, battery — a second-order DoS on the server)
70. Why is a constrained network *both* a potential amplifier *and* a likely victim?

## L. Individual-contribution questions (the exam explicitly asks these)

71. What did *you personally* read, implement, test and analyse? (be specific — not "I did section 3")
72. Explain a part of the project a teammate led, to show you understand the whole thing.
73. Which result surprised you, and what did you learn from debugging it?
74. If you had two more weeks, what would you add or measure next?

---

### Quick cross-reference: project ↔ lecture

| Lecture | Direct link to your project |
|---|---|
| L1 OSI / IoT | attack spans L3–L7; victim attacked at L3/L4 |
| L2 Sniffing/Spoofing | Scapy/raw-socket spoofing; Wireshark to measure; attack phases |
| L3 MAC/ARP | local-network requirement for multicast; MITM amplifier; your stale-neighbor bug |
| L4 IP | MTU/fragmentation vs Block2; ICMP spoofing parallel; IP-layer factor |
| **L5 Transport** | **UDP DRDoS & DNS amplification = your exact topic; vs SYN flood / SYN cookies ≈ Echo** |
| L6 App (MQTT/CoAP) | why CoAP amplifies but MQTT doesn't; CoAP security modes |
| L7 WiFi/BLE | radio constraints; deauth vs amplification DoS |
| L8 LoRa/NB-IoT | can it amplify on LPWAN? constrained-network victim; Oliveira saturation |
