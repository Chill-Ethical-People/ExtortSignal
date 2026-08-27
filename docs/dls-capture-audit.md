# DLS capture profile audit

Reviewed: 2026-08-27

This register records the presentation observed in retained evidence and the bounded,
read-only Playwright behavior used for each actor label. It intentionally omits onion
addresses. A `not ready` result is preserved as a failed capture, never as victim-list
evidence.

Catalogue discovery now reconciles the ransomware.live group catalogue with
RansomLook public group/mirror metadata for actors observed during the previous
120 days. Only clear-web APIs are queried during catalogue synchronization.
Cross-source availability or actor-label disagreements remain visible in source
health as review items; a partial provider failure does not retire last-known
targets from the other provider.

| Canonical actor | Retained presentation | Tailored behavior |
| --- | --- | --- |
| Akira | Tor SOCKS connection failure | Retry transient Tor navigation once, then require a visible card, article, table row, or victim element. |
| Chaos | Loading spinner or blank list | Wait for the busy state to clear and require both readable claim markers and at least one candidate card. |
| Cl0p | Forwarding queue/interstitial | Allow one bounded navigation retry and wait up to 180 seconds; reject the queue text as evidence. |
| Deadlock | Victim cards rendered | Require claim-state language and readable body content before capture. |
| Dire Wolf | 502 gateway response | Fail quickly and classify the gateway page as upstream error evidence, not a successful capture. |
| DragonForce | Enabled target was a recovery login; a separate blog target exists | Recovery, negotiation, support, and decryptor portals are excluded at catalog, manual queue, and scheduler boundaries. Only the public blog is eligible. |
| Gunra | Blank or loading presentation | Retry transient navigation once, wait for busy state clearance, and require at least one candidate element. |
| INC Ransom | Disclosure shell with spinner | Retry once, wait up to 90 seconds, and reject any page that remains busy or lacks readable claim content. |
| Kazu | Recent Posts list rendered | Capture the existing Recent Posts list directly; do not click an unnecessary Ransom navigation control. |
| LockBit 5 | Site shell with empty victim table | Perform the exact entry-screen click when present, then require at least one table-body row. |
| Lynx | Victim cards rendered | Use the read-only Leaks tab and require the publication-date marker before capture. |
| MedusaLocker | Browser-verification interstitial | Wait up to 90 seconds but reject verification text unless a real victim element subsequently renders. No bypass is attempted. |
| SafePay | Victim grid and pagination rendered | Require multiple cards and follow bounded same-origin pagination, up to ten pages. |
| ShinyHunters | Entry screen followed by forwarding queue | Use a trusted pointer click for the exact entry gate, allow one retry, then reject a persistent forwarding queue. |
| Space Bears | Company list rendered | Open the exact company-list view, stop before the Contact section, and capture the list as segmented review pages. |
| The Gentlemen | Verification application error | Wait for verification to clear, but treat the observed JavaScript digest error as a terminal upstream failure. |

All profiles retain the global controls: local Tor SOCKS preflight, exact-onion request
isolation, GET/HEAD only, blocked WebSockets/downloads/popups, denied permissions,
ephemeral browser contexts, bounded scrolling, same-origin pagination, and no typing,
forms, authentication, messages, or cross-origin navigation.
