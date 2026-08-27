# Data sources and attribution

ExtortSignal is an independent defensive monitoring project. It is not
affiliated with, sponsored by, or endorsed by any upstream data provider. A
source label records where ExtortSignal observed an allegation; it does not
confirm that an intrusion, encryption event, data theft, or attribution is
true.

| Provider | Use in ExtortSignal | Attribution and reuse note |
| --- | --- | --- |
| [RansomFeed](https://ransomfeed.it/docs/) | Public victim-claim API and public full-dataset export | Credit RansomFeed on retained and exported observations. Its reviewed public API documentation did not state a dataset licence; do not redistribute a RansomFeed database snapshot without separately confirming permission and current terms. |
| [RansomLook](https://www.ransomlook.io/) | Public victim posts plus supplementary group and DLS mirror metadata for recently active actors | RansomLook states that its website, API responses, and datasets are available under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). ExtortSignal preserves `RansomLook` as the observation/catalogue source and links to the project. |
| [Ransomware.live](https://www.ransomware.live/) | Public victim API, group catalogue, and DLS mirror metadata | Credit Ransomware.live on retained and exported observations. The published API-server code is MIT licensed, but a software licence does not by itself establish rights in every upstream data item. Review current API terms before redistribution or commercial use. |

ExtortSignal reconciles independent DLS catalogues over their clear-web APIs.
It accepts only syntactically valid Tor v3 hosts labelled as public victim/leak
sites, excludes file servers, chat, administration, recovery, support and
negotiation portals, and never contacts a listed onion host from the application
process. RansomLook metadata is requested only for actors observed locally in a
bounded recent-activity window. Actual screenshot capture remains an optional,
separate, allowlisted Kali worker operation.

Runtime observations, screenshots, client profiles and derived databases are
not included in source releases. Anyone operating ExtortSignal is responsible
for reviewing provider terms, applicable database rights, privacy obligations,
rate limits and local law for their intended jurisdiction and use case.
