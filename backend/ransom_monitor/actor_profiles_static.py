from __future__ import annotations

import re
from copy import deepcopy
from typing import Any


REVIEWED_AT = "2026-08-19"


def normalize_actor(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _source(name: str, url: str) -> dict[str, str]:
    return {"name": name, "url": url}


def _profile(
    canonical_name: str,
    aliases: list[str],
    summary: str,
    motivation: str,
    targeting: str,
    capabilities: str,
    campaign_history: str,
    sources: list[dict[str, str]],
    confidence: str = "high",
    caveats: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "profile_schema": "ExtortSignal CTI Profile 1.0",
        "actor_class": "criminal_ransomware_extortion",
        "distribution": "TLP:CLEAR",
        "canonical_name": canonical_name,
        "aliases": aliases,
        "summary": summary,
        "motivation": motivation,
        "targeting": targeting,
        "capabilities": capabilities,
        "campaign_history": campaign_history,
        "sources": sources,
        "source_confidence": confidence,
        "analytic_confidence": 85 if confidence == "high" else 70,
        "reviewed_at": REVIEWED_AT,
        "caveats": caveats or [],
    }


# These compact dossiers are bundled so the console has a useful, attributable
# baseline without network access or an AI provider. They deliberately describe
# only behavior established by the linked primary government advisories or the
# originating vendor research. Local victim-list observations are kept separate.
_PROFILES: list[dict[str, Any]] = [
    _profile(
        "LockBit",
        ["lockbit", "lockbit2", "lockbit3", "lockbit 3.0", "lockbit5"],
        "LockBit is a financially motivated ransomware-as-a-service operation whose affiliates have conducted data theft, encryption and public-release extortion. Government reporting documents Windows, Linux and VMware-impacting variants and a broad affiliate ecosystem.",
        "Financial extortion through ransom demands and pressure associated with stolen-data publication.",
        "Government incident reporting describes broad, opportunistic targeting across businesses and critical-infrastructure organizations rather than a narrow sector mandate.",
        "Affiliates use multiple initial-access paths, exfiltrate data, encrypt Windows and Linux hosts and VMware environments, inhibit recovery and publish data through an extortion site.",
        "LockBit activity has been tracked through several named versions since 2019. The bundled profile covers the documented LockBit operation; a newer label does not by itself prove operational continuity.",
        [
            _source(
                "CISA joint advisory AA23-165A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a",
            )
        ],
        caveats=[
            "Affiliate behavior varies and a LockBit-branded listing is not proof of compromise or attribution.",
            "The LockBit5 label is treated as a possible brand continuation only, not a confirmed identity mapping.",
        ],
    ),
    _profile(
        "Cl0p",
        ["clop", "cl0p", "clop torrents"],
        "Cl0p is a financially motivated extortion operation known for exploiting internet-facing file-transfer products and using stolen data for pressure. Joint government reporting links Cl0p affiliates to large-scale exploitation of Accellion FTA, GoAnywhere MFT and MOVEit Transfer vulnerabilities.",
        "Financial extortion, frequently centered on threatened publication of exfiltrated information.",
        "Campaigns have affected organizations across many sectors through widely deployed managed file-transfer products, creating concentrated waves of downstream exposure.",
        "Documented capabilities include mass exploitation of public-facing managed file-transfer flaws, data exfiltration, victim notification and leak-site pressure; encryption is not required for every Cl0p campaign.",
        "Government advisories document recurring exploitation campaigns against Accellion FTA, GoAnywhere MFT and, in 2023, MOVEit Transfer.",
        [
            _source(
                "CISA joint advisory AA23-158A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a",
            )
        ],
    ),
    _profile(
        "Qilin",
        ["qilin", "agenda"],
        "Qilin, also reported as Agenda, is a ransomware and data-extortion operation tracked in public-sector cyber-threat reporting. The operation has used a victim-publication site and a ransomware-as-a-service model, while affiliate tradecraft may vary.",
        "Financial extortion through data-encryption and stolen-data pressure.",
        "Public-sector reporting describes activity against state, local, tribal and territorial organizations as well as private-sector victims; observed listings should not be interpreted as a fixed targeting policy.",
        "Reported behavior includes ransomware deployment, data theft and public leak pressure. Actor-wide initial-access claims are kept conservative because affiliate methods vary.",
        "Qilin emerged under the Agenda name and became a prominent ransomware operation during 2024-2025.",
        [
            _source(
                "Center for Internet Security CTI: Qilin",
                "https://portal.cisecurity.org/insights/articles/qilin-top-ransomware-threat-to-sltts-in-q2-2025",
            )
        ],
        confidence="moderate",
        caveats=[
            "The cited report emphasizes observed activity and victim listings; it does not validate every third-party claim."
        ],
    ),
    _profile(
        "Akira",
        ["akira"],
        "Akira is a ransomware operation observed since March 2023. Joint government reporting documents data theft, encryption and extortion affecting businesses and critical infrastructure, with Windows and Linux/ESXi variants observed.",
        "Financial extortion using encryption and threatened publication of stolen information.",
        "The operation has affected small and medium-sized businesses, larger enterprises and critical-infrastructure organizations across multiple regions and sectors.",
        "Observed access includes VPN services, particularly where multifactor authentication was absent, followed by credential abuse, discovery, data exfiltration and encryption of Windows or Linux/ESXi systems.",
        "Government partners began tracking Akira incidents in March 2023 and published a joint technical advisory in April 2024.",
        [
            _source(
                "CISA joint advisory AA24-109A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a",
            )
        ],
    ),
    _profile(
        "Play",
        ["play", "playcrypt"],
        "Play, also known as Playcrypt, is a financially motivated ransomware group using data theft, encryption and leak-site pressure. Joint government reporting describes a closed operation rather than an openly advertised affiliate program.",
        "Financial extortion through ransom demands, data-release threats and, in some incidents, direct telephone pressure.",
        "Play has affected a wide range of businesses and critical-infrastructure entities in North America, South America, Europe and Australia.",
        "Documented access includes valid accounts, external remote services and exploitation of public-facing applications. Post-compromise behavior includes Active Directory discovery, defense evasion, exfiltration, encryption and ESXi-specific impact.",
        "Activity has been observed since June 2022; the joint advisory was updated in June 2025 with newer investigation-derived TTPs.",
        [
            _source(
                "CISA joint advisory AA23-352A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a",
            )
        ],
    ),
    _profile(
        "RansomHub",
        ["ransomhub"],
        "RansomHub is a ransomware-as-a-service operation first observed in February 2024. Joint government reporting describes affiliates stealing data and encrypting systems across numerous critical-infrastructure sectors.",
        "Financial extortion using encrypted systems and threatened publication of exfiltrated data.",
        "Affiliates have affected organizations across critical-infrastructure sectors and multiple geographies; affiliate selection means no single victimology rule should be assumed.",
        "Reported tradecraft includes exploitation of known vulnerabilities, password spraying and phishing, followed by credential access, lateral movement, data exfiltration and encryption.",
        "Government partners published a joint advisory in August 2024 after observing rapid activity beginning in February 2024.",
        [
            _source(
                "CISA joint advisory AA24-242A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-242a",
            )
        ],
    ),
    _profile(
        "ALPHV/BlackCat",
        ["alphv", "blackcat", "alphv blackcat", "noberus"],
        "ALPHV/BlackCat is a ransomware-as-a-service operation whose affiliates used data theft, encryption and public leak pressure. Government reporting associates the operation with a Rust-based encryptor and a diverse affiliate ecosystem.",
        "Financial extortion through ransomware and stolen-data publication pressure.",
        "Affiliates affected organizations in multiple sectors, including critical infrastructure, with targeting varying by affiliate.",
        "Documented activity includes compromised credentials, public-facing application exploitation, privilege escalation, exfiltration and encryption across Windows and Linux/VMware environments.",
        "ALPHV emerged in late 2021 and was the subject of international law-enforcement disruption activity in 2023-2024.",
        [
            _source(
                "CISA joint advisory AA23-353A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a",
            )
        ],
        caveats=[
            "Successor or rebrand claims require independent evidence and are not inferred from a shared leak-site label."
        ],
    ),
    _profile(
        "DragonForce",
        ["dragonforce", "dragon force"],
        "DragonForce is a ransomware brand and affiliate platform with Windows and Linux-focused tooling reported in original vendor research. Public reporting also describes prominent cartel and coalition branding, but those statements should be treated separately from verified technical behavior.",
        "Financial extortion through file encryption, stolen-data pressure and affiliate-platform activity.",
        "Observed victim listings span countries and industries; available research does not establish a narrow, stable sector strategy.",
        "Microsoft identifies a Windows ransomware family that encrypts files and demands Bitcoin. Trend Micro reports customizable affiliate builds and a Linux variant.",
        "The brand became visible during 2023-2024 and expanded its affiliate-platform and cartel messaging during 2025.",
        [
            _source(
                "Microsoft Security Intelligence: DragonForce",
                "https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Ransom%3AWin32%2FDragonForce%21rfn&ThreatID=2147938865",
            ),
            _source(
                "Trend Micro ransomware spotlight: DragonForce",
                "https://www.trendaisecurity.com/en-us/resources-insights/research/ransomware-spotlight-dragonforce",
            ),
        ],
        confidence="moderate",
        caveats=[
            "Criminal-forum and cartel claims are not treated as verified organizational relationships without corroboration."
        ],
    ),
    _profile(
        "SafePay",
        ["safepay", "safe pay"],
        "SafePay is a ransomware and extortion operation that rose rapidly in late 2024 and 2025. Original malware research documents endpoint-defense impairment, shadow-copy deletion, log clearing, encryption and stolen-data pressure.",
        "Financial extortion through ransomware and threatened disclosure of stolen data.",
        "Research describes broad enterprise activity, with managed-service-provider exposure receiving particular attention; listings alone do not establish a durable sector preference.",
        "Analyzed samples attempt to disable security controls, delete recovery artifacts and logs, encrypt data and support double-extortion pressure.",
        "SafePay emerged in late 2024 and became a high-volume observed operation during 2025.",
        [
            _source(
                "Acronis Threat Research Unit: SafePay",
                "https://www.acronis.com/en-us/tru/posts/safepay-ransomware-the-fast-rising-threat-targeting-msps/",
            )
        ],
        confidence="moderate",
    ),
    _profile(
        "Medusa",
        ["medusa"],
        "Medusa is a ransomware-as-a-service operation observed since 2021. Joint government reporting documents affiliates conducting encryption, data theft and leak-site extortion.",
        "Financial extortion using ransom demands and threatened or staged publication of stolen data.",
        "Medusa affiliates have affected organizations across multiple critical-infrastructure sectors and other industries.",
        "Documented tradecraft includes phishing and exploitation of unpatched vulnerabilities, use of legitimate remote-management tooling, data exfiltration, encryption and leak-site pressure.",
        "Government partners published a joint Medusa advisory in March 2025 based on investigations and activity observed since June 2021.",
        [
            _source(
                "CISA joint advisory AA25-071A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a",
            )
        ],
    ),
    _profile(
        "BianLian",
        ["bianlian", "bian lian"],
        "BianLian is a financially motivated cyber-extortion group that initially used ransomware and later emphasized data-theft extortion. Joint government reporting documents a shift away from routine encryption while retaining stolen-data pressure.",
        "Financial extortion, primarily through threats to publish stolen information.",
        "The group has targeted U.S. and Australian critical-infrastructure and private-sector organizations across several sectors.",
        "Observed access and post-compromise behavior include exposed remote services, valid credentials, network discovery, remote tooling, data staging and exfiltration.",
        "BianLian activity has been tracked since at least 2022; the joint advisory was updated as its operating model evolved toward extortion-only activity.",
        [
            _source(
                "CISA joint advisory AA23-136A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-136a",
            )
        ],
    ),
    _profile(
        "Black Basta",
        ["blackbasta", "black basta"],
        "Black Basta is a ransomware-as-a-service operation active since April 2022. Joint government reporting documents data theft, encryption and extortion involving hundreds of organizations.",
        "Financial extortion through encryption and threatened publication of stolen data.",
        "Affiliates have affected businesses and critical-infrastructure organizations across North America, Europe and Australia, spanning many sectors.",
        "Documented tradecraft includes phishing, known-vulnerability exploitation, valid-account abuse, remote access, data exfiltration and encryption.",
        "The operation was first observed in April 2022; the May 2024 joint advisory summarized investigations across more than 500 affected organizations.",
        [
            _source(
                "CISA joint advisory AA24-131A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a",
            )
        ],
    ),
    _profile(
        "INC Ransom",
        ["inc ransom", "incransom", "gold ionic"],
        "INC Ransom is a ransomware-as-a-service operation reported since mid-2023. "
        "Original vendor and MITRE research document activity across multiple industries, "
        "using ransomware and stolen-data extortion.",
        "Financial extortion through encryption and threatened publication of stolen data.",
        "Reported incidents span industries and geographies; affiliate-led selection means the "
        "observed sample should not be treated as a fixed sector doctrine.",
        "MITRE documents the INC ransomware family, while vendor research tracks a RaaS operation. "
        "Intrusion paths vary and should be assessed from incident-specific evidence.",
        "INC Ransom emerged in 2023 and remained an active victim-list operation into 2025.",
        [
            _source(
                "MITRE ATT&CK software S1139",
                "https://attack.mitre.org/software/S1139/",
            ),
            _source(
                "FortiGuard Labs actor profile: INC Ransom",
                "https://fortiguard.fortinet.com/threat-actor/6333/inc-ransomware",
            ),
        ],
        confidence="moderate",
    ),
    _profile(
        "8Base",
        ["8base"],
        "8Base is a ransomware and data-extortion operation active since at least March 2022. "
        "Original VMware and FortiGuard research documented a sharp increase in public activity "
        "during 2023 and analyzed Phobos-related ransomware behavior.",
        "Financial extortion through encryption and public-release pressure.",
        "Vendor reporting describes broad activity with a concentration among smaller and "
        "mid-sized organizations; victim-list counts do not establish deliberate sector intent.",
        "Research links observed incidents to Phobos-family ransomware behavior, data theft and "
        "encryption. Operator identity and affiliate boundaries remain less certain.",
        "The group was active from 2022, surged during 2023 and was the subject of international "
        "law-enforcement disruption in 2025.",
        [
            _source(
                "VMware Carbon Black research: 8Base",
                "https://blogs.vmware.com/security/2023/06/8base-ransomware-a-heavy-hitting-player.html",
            ),
            _source(
                "FortiGuard Labs ransomware roundup: 8Base",
                "https://www.fortinet.com/blog/threat-research/ransomware-roundup-8base",
            ),
        ],
        confidence="moderate",
    ),
    _profile(
        "CACTUS",
        ["cactus"],
        "CACTUS is a ransomware operation identified by Kroll while targeting large commercial "
        "organizations from March 2023. The malware encrypts its own configuration and payload "
        "to reduce static exposure before execution.",
        "Financial extortion through ransomware and stolen-data pressure.",
        "Original incident-response research describes targeting of large commercial entities; "
        "retained listings should not be generalized into a fixed regional strategy.",
        "Kroll documents public-facing access, legitimate remote tooling, data exfiltration and "
        "an encryptor with a self-protecting execution workflow.",
        "CACTUS was first identified in incident activity beginning in March 2023.",
        [
            _source(
                "Kroll CTI: CACTUS ransomware",
                "https://www.kroll.com/en/publications/cyber/cactus-ransomware-prickly-new-variant-evades-detection",
            )
        ],
        confidence="moderate",
    ),
    _profile(
        "Hunters International",
        ["hunters", "hunters international"],
        "Hunters International was a ransomware and extortion operation first reported in late "
        "2023. Original research found technical lineage with Hive ransomware but did not treat "
        "that similarity as proof that both brands shared the same operators.",
        "Financial extortion through encryption and stolen-data publication pressure.",
        "Public claims affected organizations across sectors and countries; the collected sample "
        "does not establish a single targeting mandate.",
        "Research documents ransomware and data-extortion behavior based on Hive-derived code, "
        "while infrastructure relationships with other brands remain an analytic question.",
        "The brand operated from late 2023 and announced an end to its activity in 2025. Later "
        "successor or rebrand claims require independent corroboration.",
        [
            _source(
                "Group-IB research: Hunters International",
                "https://www.group-ib.com/blog/hunters-international-ransomware-group/",
            )
        ],
        confidence="moderate",
        caveats=[
            "Code and infrastructure similarities do not by themselves prove common operators."
        ],
    ),
    _profile(
        "Fog",
        ["fog"],
        "Fog is a ransomware operation first highlighted by Kroll after incident-response "
        "activity increased in 2024. Early research emphasized impact on education, while later "
        "victim observations should be reviewed before inferring a fixed sector strategy.",
        "Financial extortion through encryption and related pressure against affected organizations.",
        "Kroll's initial reporting highlighted higher-education and recreation targets; that early "
        "sample is not sufficient to define permanent victimology.",
        "Incident research documents credential and remote-access abuse followed by ransomware "
        "deployment; exact behavior can vary between intrusions.",
        "Fog became visible in early 2024 and was reported as increasingly active during the "
        "second quarter of that year.",
        [
            _source(
                "Kroll CTI: Fog ransomware",
                "https://www.kroll.com/en/publications/cyber/fog-ransomware-targets-higher-education",
            )
        ],
        confidence="moderate",
    ),
    _profile(
        "Lynx",
        ["lynx"],
        "Lynx is a ransomware and data-extortion operation first observed in 2024. Original technical research identifies substantial code similarity with INC ransomware while stopping short of treating similarity alone as proof of common operators.",
        "Financial extortion through encryption and threatened publication of exfiltrated data.",
        "Observed public claims span multiple regions and industries; available evidence does not establish a narrow targeting mandate.",
        "Technical research documents Windows-focused ransomware behavior and similarities to INC ransomware; actor-level initial-access behavior remains less firmly established.",
        "The Lynx brand appeared in 2024 and expanded its victim-list activity into 2025.",
        [
            _source(
                "FortiGuard Labs ransomware roundup: Lynx",
                "https://www.fortinet.com/blog/threat-research/ransomware-roundup-lynx",
            )
        ],
        confidence="moderate",
        caveats=[
            "Code similarity with INC ransomware is not, by itself, proof of shared operators or infrastructure."
        ],
    ),
    _profile(
        "Rhysida",
        ["rhysida"],
        "Rhysida is a financially motivated ransomware operation observed since May 2023. Joint government reporting documents data theft, encryption and double-extortion activity.",
        "Financial extortion using encrypted systems and public-release threats.",
        "Reported victims include education, healthcare, manufacturing, information technology and government organizations.",
        "Observed access includes external-facing remote services and phishing, followed by credential access, lateral movement, data exfiltration and encryption.",
        "Rhysida emerged in May 2023; government partners issued a joint advisory in November 2023 based on incident-response findings.",
        [
            _source(
                "CISA joint advisory AA23-319A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-319a",
            )
        ],
    ),
    _profile(
        "Hive",
        ["hive"],
        "Hive was a ransomware-as-a-service operation whose affiliates used data theft, encryption and leak-site pressure. Government investigations documented broad impact before infrastructure disruption in January 2023.",
        "Financial extortion through ransom demands and threatened publication of stolen data.",
        "Affiliates targeted businesses and critical-infrastructure organizations, including healthcare and public-health entities.",
        "Documented tradecraft includes phishing, vulnerable remote services, valid credentials, remote administration, data exfiltration and encryption of Windows and Linux/ESXi systems.",
        "Hive activity was observed from 2021 until an FBI-led disruption announced in January 2023; later use of the name does not automatically establish continuity.",
        [
            _source(
                "CISA joint advisory AA22-321A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-321a",
            )
        ],
        caveats=[
            "Current listings using the Hive name require separate validation because the documented infrastructure was disrupted."
        ],
    ),
    _profile(
        "Royal/BlackSuit",
        ["royal", "black suit", "blacksuit"],
        "Royal and BlackSuit are ransomware labels addressed together in updated joint government reporting. The activity uses data theft, encryption and extortion, with BlackSuit assessed in public reporting as an evolution of Royal ransomware.",
        "Financial extortion through encryption, ransom demands and stolen-data release pressure.",
        "Activity has affected multiple critical-infrastructure sectors and private organizations, with no single exclusive victimology.",
        "Government reporting documents phishing, public-facing application exploitation, remote services, credential access, exfiltration and encryption.",
        "Royal activity became prominent in 2022; the government advisory was subsequently updated to include BlackSuit-related indicators and behavior.",
        [
            _source(
                "CISA joint advisory AA23-061A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a",
            )
        ],
        caveats=[
            "Lineage reporting does not prove that every Royal- or BlackSuit-branded claim involves the same operators."
        ],
    ),
    _profile(
        "Vice Society",
        ["vicesociety", "vice society"],
        "Vice Society is a ransomware and extortion group prominently associated with attacks on education. Joint government reporting documents use of multiple ransomware families rather than a single exclusive payload.",
        "Financial extortion using ransomware and stolen-data pressure.",
        "The group has disproportionately affected the education sector, while other victim types have also been observed.",
        "Documented behavior includes exploitation of internet-facing applications, compromised credentials, network discovery, data exfiltration and deployment of ransomware obtained from other ecosystems.",
        "Government partners highlighted Vice Society activity against the education sector in a September 2022 joint advisory.",
        [
            _source(
                "CISA joint advisory AA22-249A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-249a",
            )
        ],
    ),
    _profile(
        "Snatch",
        ["snatch"],
        "Snatch is a ransomware and data-extortion operation observed since 2018. Joint government reporting documents affiliates using stolen or brute-forced credentials and, in some incidents, Safe Mode to impair security controls before encryption.",
        "Financial extortion through encryption and publication threats.",
        "Reported victims span critical-infrastructure sectors and other organizations in multiple regions.",
        "Observed tradecraft includes Remote Desktop Protocol access, credential abuse, data exfiltration, security-control impairment and ransomware deployment.",
        "Snatch has been tracked since 2018; a September 2023 joint advisory summarized investigation-derived TTPs.",
        [
            _source(
                "CISA joint advisory AA23-263A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-263a",
            )
        ],
    ),
    _profile(
        "AvosLocker",
        ["avoslocker", "avos locker"],
        "AvosLocker is a ransomware-as-a-service operation whose affiliates have used data theft, encryption and leak-site pressure against critical-infrastructure and other organizations.",
        "Financial extortion through ransom demands and threatened disclosure of stolen data.",
        "Affiliate-driven targeting spans sectors and geographies; government reporting highlights critical-infrastructure impact.",
        "Documented behavior includes public-facing application exploitation, remote services, legitimate administration tools, data exfiltration and Windows or Linux/ESXi encryption.",
        "Government partners published and later updated a joint AvosLocker advisory based on incidents observed through 2023.",
        [
            _source(
                "CISA joint advisory AA23-284A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-284a",
            )
        ],
    ),
    _profile(
        "BlackByte",
        ["blackbyte", "black byte"],
        "BlackByte is a ransomware-as-a-service operation whose affiliates have targeted organizations in several U.S. critical-infrastructure sectors and other industries.",
        "Financial extortion using encryption and public-release pressure.",
        "Affiliate activity spans multiple sectors; available government reporting should not be read as a fixed exclusive target list.",
        "Documented behavior includes exploitation of public-facing vulnerabilities, lateral movement, data exfiltration and file encryption.",
        "BlackByte became prominent in 2021 and was the subject of a joint FBI/USSS advisory in 2022.",
        [
            _source(
                "CISA joint advisory AA22-057A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-057a",
            )
        ],
    ),
    _profile(
        "Karakurt",
        ["karakurt"],
        "Karakurt is a data-extortion operation that has generally relied on stolen-data pressure rather than encrypting victim systems. Government reporting distinguishes this model from conventional encrypt-and-extort ransomware.",
        "Financial extortion through threats to auction or publish stolen information.",
        "Reported victims span small and large organizations across multiple industries and geographies.",
        "Observed behavior includes credential abuse, remote access, data staging and exfiltration; encryption is not a required component of the documented model.",
        "Government partners published a Karakurt data-extortion advisory in June 2022.",
        [
            _source(
                "CISA joint advisory AA22-152A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-152a",
            )
        ],
    ),
    _profile(
        "Cuba",
        ["cuba", "cuba ransomware"],
        "Cuba ransomware actors have used data theft, encryption and public-release extortion. Joint government reporting documents campaigns affecting U.S. critical-infrastructure and other organizations.",
        "Financial extortion through ransom demands and threatened release of stolen information.",
        "Observed victims span critical-infrastructure sectors and other businesses in multiple countries.",
        "Documented behavior includes exploitation of known vulnerabilities, credential access, remote tooling, data exfiltration and encryption.",
        "Cuba ransomware activity has been tracked since 2019; a joint advisory was updated in December 2022.",
        [
            _source(
                "CISA joint advisory AA22-335A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-335a",
            )
        ],
    ),
    _profile(
        "Conti",
        ["conti"],
        "Conti was a financially motivated ransomware operation associated with high-impact encryption and data-theft extortion. Government reporting described an affiliate model and significant targeting of healthcare and other critical services.",
        "Financial extortion through ransomware, data theft and public-release threats.",
        "The operation targeted organizations across sectors and geographies, including healthcare and critical infrastructure.",
        "Documented behavior includes spearphishing, malicious documents, remote services, credential theft, lateral movement, exfiltration and rapid network-wide encryption.",
        "Conti activity was prominent from 2020 through the operation's public fragmentation in 2022; later code or brand references do not prove operator continuity.",
        [
            _source(
                "CISA joint advisory AA21-265A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-265a",
            )
        ],
        caveats=[
            "Conti code and personnel reporting is historically important, but current actor labels require separate attribution evidence."
        ],
    ),
    _profile(
        "Phobos",
        ["phobos"],
        "Phobos is a ransomware-as-a-service family used by multiple affiliates. Joint government reporting describes sustained attacks on municipal and county governments, emergency services, education, public healthcare and critical infrastructure.",
        "Financial extortion through file encryption and ransom demands.",
        "Affiliates have repeatedly affected smaller public-sector and critical-service organizations as well as private entities.",
        "Observed behavior includes phishing, exposed Remote Desktop Protocol, credential abuse, remote tools, defense evasion and encryption.",
        "Phobos-related activity has been observed since 2019; government partners published investigation-derived TTPs in February 2024.",
        [
            _source(
                "CISA joint advisory AA24-060A",
                "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-060a",
            )
        ],
    ),
]


_BY_ALIAS: dict[str, dict[str, Any]] = {}
for _item in _PROFILES:
    for _name in [_item["canonical_name"], *_item["aliases"]]:
        _BY_ALIAS[normalize_actor(_name)] = _item


def lookup_static_profile(actor: str) -> dict[str, Any] | None:
    profile = _BY_ALIAS.get(normalize_actor(actor))
    return deepcopy(profile) if profile else None


def build_static_profile(
    *,
    actor: str,
    cti_profile: dict[str, Any] | None,
    catalog_profile: dict[str, Any] | None,
    claim_count: int,
    first_observed_at: str,
    last_observed_at: str,
    top_industries: list[dict[str, Any]],
    top_countries: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return a useful offline dossier for every actor label without inventing facts."""
    curated = lookup_static_profile(actor)
    if curated:
        return {**curated, "source_kind": "static_local_curated"}

    industries = ", ".join(item["name"] for item in top_industries) or "no reliable industry values"
    countries = ", ".join(item["name"] for item in top_countries) or "no reliable geography values"
    if cti_profile:
        baseline = str(cti_profile.get("description", "")).strip()
        sources = [_source("MITRE ATT&CK", str(cti_profile.get("attack_url", "")))]
        aliases = list(cti_profile.get("aliases", []))
        canonical_name = str(cti_profile.get("canonical_name", actor))
        confidence = str(cti_profile.get("match_confidence", "moderate"))
        capabilities = (
            f"MITRE ATT&CK documents {len(cti_profile.get('techniques', []))} technique mappings, "
            f"{len(cti_profile.get('software', []))} software entries and "
            f"{len(cti_profile.get('campaigns', []))} campaigns for the exact name or alias match. "
            "The detailed ATT&CK panel is authoritative for those mappings; no broader capability is inferred."
        )
        source_kind = "static_local_framework"
    else:
        baseline = str(catalog_profile.get("description", "")).strip() if catalog_profile else ""
        sources = (
            [_source("Ransomware.live group catalogue", "https://www.ransomware.live/groups")]
            if catalog_profile
            else [_source("ExtortSignal local actor-label registry", "")]
        )
        aliases = []
        canonical_name = actor
        confidence = "moderate" if catalog_profile else "low"
        capabilities = (
            "A public victim-list or extortion-channel association is present in the bundled catalogue. "
            "Actor-specific malware, intrusion methods, affiliate structure and access paths are not established "
            "by the bundled evidence."
            if catalog_profile
            else "The retained actor label is associated with public victim claims, but actor-specific malware, "
            "intrusion methods, affiliate structure and access paths are not established by bundled evidence."
        )
        source_kind = "static_local_catalog" if catalog_profile else "static_local_label"

    summary_prefix = baseline or (
        f"{actor} is retained as an extortion-linked actor label. No independent identity or technical dossier "
        "is currently bundled for this exact label."
    )
    summary = (
        f"{summary_prefix} This offline baseline separates the actor label from {claim_count} locally retained, "
        "unverified public claim observations."
    )
    return {
        "profile_schema": "ExtortSignal CTI Profile 1.0",
        "actor_class": (
            "documented_activity_cluster"
            if cti_profile
            else "catalogued_extortion_label"
            if catalog_profile
            else "unresolved_actor_label"
        ),
        "distribution": "TLP:CLEAR",
        "canonical_name": canonical_name,
        "aliases": aliases,
        "summary": summary,
        "motivation": (
            "Financial extortion is the leading analytic hypothesis because the label is associated with a "
            "public extortion or victim-list context. Actor-specific motive is not independently established."
        ),
        "targeting": (
            f"No stable targeting doctrine is established. Local public-claim observations most often contain "
            f"{industries} and {countries}; this may reflect affiliate, collection and reporting bias."
        ),
        "capabilities": capabilities,
        "campaign_history": (
            f"ExtortSignal retained {claim_count} unverified public claim observation"
            f"{'s' if claim_count != 1 else ''} for this label between {first_observed_at[:10]} and "
            f"{last_observed_at[:10]}. This is an observation chronology, not incident confirmation."
        ),
        "sources": sources,
        "source_confidence": confidence if confidence in {"low", "moderate", "high"} else "low",
        "analytic_confidence": 70 if cti_profile else 55 if catalog_profile else 30,
        "reviewed_at": REVIEWED_AT,
        "source_kind": source_kind,
        "caveats": [
            "Victim-list claims are unverified allegations and do not establish compromise or attribution.",
            "Targeting language derived from local observations describes the collected sample, not intent.",
            "Use the optional sourced AI refresh only as an analyst-reviewable overlay.",
        ],
    }


def ai_refresh_is_usable(profile: dict[str, Any] | None, retained_evidence_ids: set[str]) -> bool:
    """Do not let uncited or failed AI research replace the bundled baseline."""
    if not profile:
        return False
    evidence = profile.get("field_evidence", {})
    if not isinstance(evidence, dict):
        return False
    cited_ids = {
        str(evidence_id)
        for values in evidence.values()
        if isinstance(values, list)
        for evidence_id in values
        if str(evidence_id).strip()
    }
    try:
        independent_sources = int(profile.get("independent_source_count", 0) or 0)
        confidence = int(profile.get("confidence", 0) or 0)
    except (TypeError, ValueError):
        return False
    return (
        bool(cited_ids)
        and cited_ids.issubset(retained_evidence_ids)
        and independent_sources >= 1
        and confidence >= 20
    )
