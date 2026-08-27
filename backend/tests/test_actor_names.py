from ransom_monitor.actor_names import (
    RELATED_BUT_DISTINCT_ACTORS,
    actor_identity_key,
    canonical_actor_name,
    known_actor_aliases,
)


def test_actor_aliases_use_a_stable_preferred_label():
    assert canonical_actor_name("  thegentlemen ") == "The Gentlemen"
    assert canonical_actor_name("The Gentlemen") == "The Gentlemen"
    assert canonical_actor_name("clop torrents") == "Cl0p"
    assert canonical_actor_name("INC-RANSOM") == "INC Ransom"
    assert canonical_actor_name("threeam") == "3AM"
    assert canonical_actor_name("BARRACUDA") == "Barracuda"
    assert canonical_actor_name("wall street") == "Wallstreet"
    assert canonical_actor_name("apt73/bashe") == "APT73"
    assert canonical_actor_name("eraleign (apt73)") == "APT73"
    assert canonical_actor_name("hunters") == "Hunters International"
    assert canonical_actor_name("black suit") == "BlackSuit"
    assert canonical_actor_name("abyss-data") == "Abyss"
    assert canonical_actor_name("booba team") == "Booba Project"
    assert canonical_actor_name("dunghill_leak") == "Dark Angels"
    assert canonical_actor_name("hiveleak") == "Hive"
    assert canonical_actor_name("j group") == "J Group"
    assert canonical_actor_name("secpo") == "SecP0"
    assert canonical_actor_name("silent") == "Silent Ransom Group"
    assert canonical_actor_name("securotop") == "Securotrop"
    assert canonical_actor_name("zero tolerance gang (ztg)") == "ZeroTolerance"
    assert actor_identity_key("space bears") == actor_identity_key("spacebears")


def test_uncertain_successor_labels_are_not_merged():
    assert actor_identity_key("devman") != actor_identity_key("devman2")
    assert actor_identity_key("qilin-securotrop") != actor_identity_key("qilin")
    assert actor_identity_key("blackbyte-crux") != actor_identity_key("blackbyte")
    assert actor_identity_key("lockbit3") != actor_identity_key("lockbit5")
    assert actor_identity_key("royal") != actor_identity_key("blacksuit")
    assert actor_identity_key("hunters") != actor_identity_key("worldleaks")
    assert canonical_actor_name("New Actor Label") == "New Actor Label"

    relationships = {(left, right) for left, right, _reason in RELATED_BUT_DISTINCT_ACTORS}
    assert ("Royal", "BlackSuit") in relationships
    assert ("Hunters International", "World Leaks") in relationships


def test_known_aliases_include_canonical_name():
    assert known_actor_aliases("clop")[:2] == ("Cl0p", "cl0p")
