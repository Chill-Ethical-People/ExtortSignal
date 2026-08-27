# DLS capture behavior audit

Audit date: 2026-07-26

This review used only retained screenshots, extracted DOM text, local OCR, capture-job metadata, and worker state. It did not initiate new DLS requests. Victim names shown in retained evidence remain unverified threat-actor claims.

## Actor-by-actor findings

| Actor | Retained result | Assessment | Bounded worker behavior |
| --- | --- | --- | --- |
| Akira | No completed evidence; two Tor/proxy failures | No presentation evidence exists to justify a site-specific interaction | Keep generic fail-closed routing; do not invent clicks or selectors |
| Chaos | Repeated dark loading spinner with effectively empty OCR | False-success capture; victim list never became ready | Wait up to 45 seconds for loading to clear and require an observed victim marker such as `Leaked size` or `View count` |
| Clop | Forwarding queue on every retained capture | Interstitial, not claim evidence | Wait for the queue text to clear for up to 60 seconds; otherwise fail the job without retaining it as evidence |
| Deadlock | Victim cards with `Published` and `Coming soon` states across three review pages | Reliable claim-list presentation | Require adequate text and a known state marker; retain bounded scrolling only |
| Dire Wolf | Repeated `502 Bad Gateway` page | Upstream service failure, not a browser interaction problem | Classify generic 502/503/504 pages as terminal presentation failures immediately |
| DragonForce | Recovery-session login form | Wrong presentation for public claim monitoring; typing or authentication is out of scope | Treat `Log in to recovery` as terminal and do not interact with the form |
| Gunra | Blank white page and empty extracted text | False-success capture; likely unavailable presentation or blocked dependency | Wait for readable content, then fail closed; do not relax same-origin network isolation |
| INC Ransom | Disclosure shell with a loading indicator and no announcement list | Incomplete client-side presentation | Require the loading indicator to clear and a minimum readable body before capture |
| Kazu | Public home page containing recent breach posts | Claim material exists; the older running worker had not loaded the new `Ransom` navigation profile | Make one exact same-origin `Ransom` navigation click when present, then require recent-post or data-breach markers |
| LockBit 5 | Entry gate followed by an empty victim table | False-success capture after partial presentation | Make one exact entry-gate click, wait, and require at least one table row before capture |
| Lynx | Populated leak cards across eight review pages | Reliable claim-list presentation | Make one exact `Leaks` navigation click when present and require a publication-date marker |
| MedusaLocker | Persistent `Verifying browser` screen | Verification interstitial, not claim evidence | Wait up to 60 seconds for it to clear and require victim cards; no bypass behavior |
| SafePay | Populated victim cards and visible pagination | Reliable claim-list presentation | Require at least three cards and retain bounded same-origin next-page handling |
| ShinyHunters | `Click anywhere to enter` followed by a forwarding queue | Entry action is known, but retained result is still an interstitial | Make one exact screen-entry click, wait for same-origin forwarding, and reject the queue if it persists |
| Space Bears | Valid company list across 25 review segments, followed by an unrelated contact form | Claim evidence is reliable; tail cropping did not recognize the non-semantic contact heading | Keep the exact `List of companies` navigation and crop at the first late-page exact `Contact` label, regardless of heading tag |
| The Gentlemen | Browser-verification screen ending in a JavaScript `digest` error | Terminal presentation failure, not claim evidence | Wait for ordinary verification states; fail immediately on the retained terminal JavaScript error |

## Shared quality controls

- A job can complete only after actor-specific readiness checks pass.
- Blank output, tiny unreadable output, generic gateway errors, and short-lived interstitial text are rejected even for an actor without a profile.
- Interactions remain read-only and deterministic: bounded scroll, exact same-origin navigation, exact load-more/next controls, read-only ARIA tabs, and one explicitly configured entry gate.
- Forms, typing, authentication, downloads, messages, mutation requests, popups, WebSockets, and cross-origin traffic remain blocked.
- The actor directory and time-based review-page filenames remain unchanged.

## Deployment note

The Kali worker process observed during this audit started at 2026-07-26 18:29:23 HKT, before the previously deployed profile file was updated. Captures made after that timestamp were therefore produced by the older in-memory worker. A worker restart is required before evaluating these tuned profiles.
