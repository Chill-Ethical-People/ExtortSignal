from __future__ import annotations

import re
import unicodedata


# Curated aliases are deliberately conservative. Formatting variants and aliases
# supported by the bundled CTI profiles are merged; uncertain affiliate,
# successor, and rebrand relationships remain separate actor labels.
CANONICAL_ACTOR_ALIASES: dict[str, tuple[str, ...]] = {
    "3AM": ("3am", "threeam"),
    "8Base": ("8base",),
    "Abyss": ("abyss", "abyss-data", "abyss data", "abyss locker"),
    "AiLock": ("ailock",),
    "Akira": ("akira",),
    "ALP-001": ("alp-001",),
    "ALPHV/BlackCat": ("alphv", "blackcat", "alphv blackcat", "noberus"),
    "Anubis": ("anubis",),
    "APT73": ("apt73", "apt73/bashe", "bashe", "eraleign", "eraleign (apt73)"),
    "Arcus Media": ("arcus media", "arcusmedia"),
    "Argonauts": ("argonauts", "argonauts group"),
    "Arkana": ("arkana", "arkana security"),
    "Audit Team": ("audit team", "auditteam"),
    "AvosLocker": ("avoslocker", "avos locker"),
    "Avaddon": ("avaddon",),
    "Babuk Locker": ("babuk", "babuk-locker", "babuklocker"),
    "Barracuda": ("barracuda",),
    "BianLian": ("bianlian", "bian lian"),
    "Black Basta": ("blackbasta", "black basta"),
    "Black Nevas": ("black nevas", "blacknevas"),
    "BlackSuit": ("black suit", "blacksuit"),
    "Black X": ("black x", "blackx"),
    "BlackByte": ("blackbyte", "black byte"),
    "BlueWhale": ("bluewhale", "blue whale"),
    "Booba Project": ("booba project", "booba team"),
    "Brain Cipher": ("brain cipher", "braincipher"),
    "BravoX": ("bravox",),
    "BravoX 2": ("bravox2", "bravox 2"),
    "CACTUS": ("cactus",),
    "Chaos": ("chaos",),
    "Cl0p": ("cl0p", "clop", "clop torrents"),
    "CMD Organization": ("cmd organization", "cmdorganization"),
    "Coinbase Cartel": ("coinbase cartel", "coinbasecartel"),
    "Conti": ("conti",),
    "Cloak": ("cloak",),
    "CRPxO": ("crpxo", "crpx0"),
    "CrazyHunter": ("crazyhunter", "crazyhunter team"),
    "Cuba": ("cuba", "cuba ransomware"),
    "Dark Project": ("dark project", "darkproject"),
    "Deadlock": ("deadlock",),
    "D1R": ("d1r",),
    "dAn0n": ("dan0n",),
    "Daixin": ("daixin", "daixin team"),
    "Doommageddon": ("doommageddon",),
    "DragonForce": ("dragonforce", "dragon force"),
    "Dark Power": ("dark power", "darkpower"),
    "DarkVault": ("darkvault", "dark vault"),
    "Dark Angels": ("dark angels", "dunghill", "dunghill leak", "dunghill_leak"),
    "Dire Wolf": ("direwolf", "dire wolf"),
    "Dispossessor": ("dispossessor",),
    "Ethics": ("ethics",),
    "Eclipse": ("eclipse",),
    "El Dorado": ("el dorado", "eldorado"),
    "Everest": ("everest",),
    "ExfilSquad": ("exfilsquad", "exfil squad"),
    "Fog": ("fog",),
    "FSociety": ("fsociety", "f society"),
    "FunkSec": ("funksec", "funk sec"),
    "Gammax": ("gammax",),
    "Global Secret Group": ("global secret group", "globalsecretgroup"),
    "GDLockerSec": ("gd lockersec", "gdlockersec"),
    "Genesis": ("genesis",),
    "Gunra": ("gunra",),
    "Handala": ("handala",),
    "Helix": ("helix",),
    "Hive": ("hive", "hiveleak", "hive leak"),
    "HelloGookie": ("hellogookie", "hello gookie", "gookie"),
    "Hunters International": ("hunters", "hunters international"),
    "Icarus": ("icarus",),
    "Insane": ("insane", "insane ransomware"),
    "IceFire": ("icefire", "ice fire"),
    "IMN Crew": ("imn crew", "imncrew"),
    "INC Ransom": ("inc ransom", "incransom", "gold ionic"),
    "Interlock": ("interlock",),
    "J Group": ("j", "j group"),
    "Karakurt": ("karakurt",),
    "Kairos": ("kairos",),
    "Knight": ("knight",),
    "KryBit": ("krybit",),
    "KillSec": ("killsec", "kill security", "kill security 2.0"),
    "KillSec 3": ("killsec3", "killsec 3", "killsec 3.0"),
    "LockBit 3": ("lockbit3", "lockbit 3", "lockbit 3.0"),
    "LockBit 5": ("lockbit5", "lockbit 5", "lockbit 5.0", "lockbit5.0"),
    "L Group": ("l group", "lgroup"),
    "LeakNet": ("leaknet", "leak net"),
    "Lorenz": ("lorenz",),
    "LostTrust": ("losttrust", "lost trust"),
    "Lynx": ("lynx",),
    "Mad Liberator": ("mad liberator", "madliberator"),
    "Malek Team": ("malek team", "malekteam"),
    "Mallox": ("mallox",),
    "Medusa": ("medusa",),
    "MedusaLocker": ("medusalocker", "medusa locker"),
    "Meow": ("meow",),
    "Monti": ("monti",),
    "Money Message": ("money message", "moneymessage"),
    "MS13-089": ("ms13-089", "ms13089"),
    "Nasir Security": ("nasir security", "nasirsecurity"),
    "NightSpire": ("nightspire", "night spire"),
    "NoEscape": ("noescape", "no escape"),
    "Nova": ("nova",),
    "Orova": ("orova",),
    "Panzer": ("panzer",),
    "Phobos": ("phobos",),
    "Pysa": ("pysa",),
    "Quantum": ("quantum",),
    "Play": ("play", "playcrypt"),
    "Prinz Eugen": ("prinz eugen", "prinzeugen"),
    "Qilin": ("qilin", "agenda"),
    "RA Group": ("ra group", "ragroup"),
    "Radiant": ("radiant", "radiant group"),
    "RagnarLocker": ("ragnarlocker", "ragnar locker"),
    "RansomHub": ("ransomhub", "ransom hub"),
    "RansomEXX": ("ransomexx", "ransom exx"),
    "RansomHouse": ("ransomhouse", "ransom house"),
    "Ransomed": ("ransomed",),
    "Redact": ("redact",),
    "Red Ransomware": ("red ransomware", "redransomware"),
    "Rhysida": ("rhysida",),
    "Royal": ("royal", "royal ransomware"),
    "RunSomeWares": ("run some wares", "runsomewares"),
    "SafePay": ("safepay", "safe pay"),
    "ShinyHunters": ("shinyhunters", "shiny hunters"),
    "Sarcoma": ("sarcoma",),
    "SecP0": ("secp0", "secpo"),
    "SenSayQ": ("sensayq",),
    "Settra": ("settra",),
    "ShadowByt3$": ("shadowbyt3$", "shadowbyt3"),
    "Silent Ransom Group": (
        "silentransomgroup",
        "silent ransom group",
        "silent ransom",
        "silent",
    ),
    "Snatch": ("snatch",),
    "Sinobi": ("sinobi",),
    "Securotrop": ("securotrop", "securotop", "qilin-securotrop"),
    "Skira": ("skira", "skira team"),
    "Sovcali": ("sovcali",),
    "Space Bears": ("space bears", "spacebears"),
    "Storm": ("storm",),
    "The Gentlemen": ("the gentlemen", "thegentlemen"),
    "TiMc": ("timc",),
    "Tengu": ("tengu",),
    "Toufan": ("toufan",),
    "Trigona": ("trigona",),
    "Triple X": ("triple x", "triplex"),
    "Unsafe": ("unsafe", "unsafeleak", "unsafe leak"),
    "Vice Society": ("vicesociety", "vice society"),
    "Valencia Leaks": ("valencia leaks", "valencialeaks"),
    "VanHelsing": ("vanhelsing", "van helsing"),
    "Vanir Group": ("vanir group", "vanirgroup"),
    "Wallstreet": ("wallstreet", "wall street"),
    "Warlock": ("warlock",),
    "World Leaks": ("worldleaks", "world leaks"),
    "ZeroTolerance": (
        "zerotolerance",
        "zero tolerance",
        "zero tolerance gang",
        "zero tolerance gang (ztg)",
    ),
}


# Reported lineage, affiliate, source-code, successor, and infrastructure
# relationships are not exact identity. Keeping them explicit prevents a future
# maintainer from turning an analytic association into a deduplication rule.
RELATED_BUT_DISTINCT_ACTORS: tuple[tuple[str, str, str], ...] = (
    ("LockBit 3", "LockBit 5", "version labels; operational continuity is not assumed"),
    ("Royal", "BlackSuit", "reported evolution/lineage; not exact claim identity"),
    ("INC Ransom", "Lynx", "reported code similarity; operator identity is not established"),
    (
        "Hive",
        "Hunters International",
        "reported code lineage; operator identity is not established",
    ),
    (
        "Hunters International",
        "World Leaks",
        "reported successor/rebrand; historical labels remain separate",
    ),
    (
        "Qilin",
        "Securotrop",
        "reported affiliate-network relationship; labels remain separate",
    ),
    ("Babuk Locker", "babuk-bjorka", "fork/affiliate relationship is insufficiently established"),
    ("KillSec", "KillSec 3", "version labels remain separate pending corroborated continuity"),
    ("BravoX", "BravoX 2", "version labels remain separate pending corroborated continuity"),
)


def actor_name_key(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return re.sub(r"[^a-z0-9]", "", normalized)


def _alias_index() -> dict[str, str]:
    index: dict[str, str] = {}
    for canonical, aliases in CANONICAL_ACTOR_ALIASES.items():
        for alias in (canonical, *aliases):
            key = actor_name_key(alias)
            existing = index.get(key)
            if existing is not None and existing != canonical:
                raise RuntimeError(
                    f"Actor alias collision: {alias!r} maps to both {existing!r} and {canonical!r}"
                )
            index[key] = canonical
    return index


_ALIAS_TO_CANONICAL = _alias_index()


def canonical_actor_name(value: str) -> str:
    """Return the preferred actor label without inferring uncertain relationships."""
    cleaned = " ".join(unicodedata.normalize("NFKC", str(value or "")).split())
    if not cleaned:
        return "Unknown"
    return _ALIAS_TO_CANONICAL.get(actor_name_key(cleaned), cleaned)


def actor_identity_key(value: str) -> str:
    """Return a stable key used for actor comparison and claim deduplication."""
    return actor_name_key(canonical_actor_name(value))


def known_actor_aliases(value: str) -> tuple[str, ...]:
    canonical = canonical_actor_name(value)
    aliases = CANONICAL_ACTOR_ALIASES.get(canonical, ())
    return tuple(dict.fromkeys((canonical, *aliases)))
