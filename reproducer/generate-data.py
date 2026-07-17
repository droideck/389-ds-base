#!/usr/bin/env python3
"""Generate synthetic LDIF data for the large-filter reproducer.

Emits a flat tree under ou=people,dc=example,dc=com. Every entry is
inetOrgPerson + reproPerson (see schema/99reproducer.ldif). The same LDIF
loads into both 389-ds (dsconf backend import) and OpenLDAP (slapadd).

Cardinality design (all deterministic from --seed):
  uid            unique (user%07d)
  cn             unique-ish ("<given> <surname> <i>"); every non-golden entry
                 with i % 6 == 3 additionally carries the " Megaword" token
                 (one deliberately fat substring key, see FAT_TOKEN)
  reproTag       multi-valued (2 values); each pool value shared by 1-10 entries
  reproRegion    "emea" covers ~50% of entries; 5 other values ~10% each
  reproTitle     pool of ~2010 values -> ~50 entries per value
  reproDept      pool of ~504 values -> ~200 entries per value
  reproMailAlt   multi-valued (1-2), unique-ish
  reproHostname  unique (host%07d.example.com), case-exact IA5
  reproScore     uniform 0..999 (narrow-range target); values 500/501 are
                 reserved for the golden cohort (non-golden draws remap to
                 502/503), so the narrow range selects exactly the cohort.
                 The value space is deliberately coarse (~1000 distinct
                 keys): with ~100k distinct integer keys, OpenLDAP range
                 evaluation cost is dominated by index-key scans, which
                 swamps the filter-processing signal this reproducer is for
                 (measured in iteration 1).
  reproLevel     uniform 0..999 (wide-range target)
  reproManager   DN of one of the first 997 users
  reproFlag      TRUE/FALSE ~50/50 (unindexed NOT target)
  reproNote      pool of ~4000 values -> ~25 entries per value (unindexed NOT target)

Golden cohort: every stride-th entry (stride = entries // golden) is overridden
so it deterministically satisfies EVERY branch of the generated filter:
region=emea, flag=FALSE, score packed into a narrow window, level=250 (inside
the wide range), cn "Golden User NNNNN", tags/dept/title/note set to
golden-only values that no filter NOT component ever targets. This guarantees
an identical non-zero result set on both servers.

Also writes data-manifest.json, which generate-filter.py consumes so filter
values provably align with the data.
"""

import argparse
import json
import random
import sys

GIVEN_NAMES = [
    "Alice", "Bruno", "Carla", "Derek", "Elena", "Felix", "Grace", "Henrik",
    "Ivana", "Jonas", "Katya", "Liam", "Marta", "Nadia", "Oscar", "Priya",
    "Quinn", "Rosa", "Stefan", "Tara", "Ulrich", "Vera", "Wendy", "Xavier",
    "Yara", "Zoltan", "Amara", "Bianca", "Cedric", "Dmitri", "Estelle",
    "Farid", "Greta", "Hassan", "Ingrid", "Jorge", "Kirsten", "Laszlo",
    "Miriam", "Nikolai", "Odette", "Pavel", "Renata", "Sanjay", "Therese",
    "Umberto", "Valentina", "Wilhelm", "Ximena", "Yusuf",
]

SURNAMES = [
    "Andersson", "Bergstrom", "Carlsson", "Dahlberg", "Eriksson", "Forsberg",
    "Gustafsson", "Hansson", "Isaksson", "Johansson", "Karlsson", "Lindqvist",
    "Magnusson", "Nilsson", "Olofsson", "Persson", "Qvarnstrom", "Rosenberg",
    "Svensson", "Thorsen", "Ulvaeus", "Vikander", "Wallin", "Ahlgren",
    "Bjornsson", "Cederblad", "Dominguez", "Esposito", "Ferrari", "Giordano",
    "Hoffmann", "Ivanov", "Jankowski", "Kovacs", "Lombardi", "Moreau",
    "Novak", "Oliveira", "Petrov", "Quintero", "Rossi", "Schneider",
    "Takahashi", "Ueda", "Varga", "Weber", "Yamamoto", "Zielinski",
    "Fitzgerald", "Gallagher", "Harrington", "Kavanagh", "MacLeod",
    "OBrien", "Pemberton", "Radcliffe", "Sinclair", "Thackeray",
    "Underwood", "Whitfield",
]

TITLE_LEVELS = ["Junior", "Senior", "Staff", "Principal", "Lead", "Associate"]
TITLE_ROLES = ["Engineer", "Analyst", "Manager", "Consultant", "Architect"]
TITLE_MAX_N = 67  # 6 levels * 5 roles * 67 = 2010 distinct titles

DEPT_NAMES = [
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta",
    "iota", "kappa", "lambda", "mu", "nu", "xi", "omicron", "pi", "rho",
    "sigma", "tau", "upsilon", "phi", "chi", "psi", "omega",
]
DEPT_MAX_N = 21  # 24 names * 21 = 504 distinct depts

NOTE_WORDS = [
    "amber", "basalt", "cobalt", "dune", "ember", "fjord", "granite",
    "harbor", "indigo", "juniper", "krypton", "lagoon", "marble", "nectar",
    "onyx", "prairie", "quartz", "russet", "saffron", "topaz",
]

REGIONS_OTHER = ["amer", "apac", "anz", "latam", "nordics"]

SUFFIX = "dc=example,dc=com"
PEOPLE = "ou=people," + SUFFIX
MANAGER_MOD = 997
TAG_USE_MIN, TAG_USE_MAX = 1, 10
SCORE_MAX = 999
LEVEL_MAX = 999
LEVEL_WIDE = (0, 499)

GOLDEN_TAG_COUNT = 40
GOLDEN_LEVEL = 250
GOLDEN_REGION = "emea"
GOLDEN_FLAG = "FALSE"
GOLDEN_NOTE = "golden marker note"
GOLDEN_DEPT = "dept-golden-000"
GOLDEN_TITLE = "Golden Marker Title"
GOLDEN_SCORE_BASE = 500
GOLDEN_SCORE_SPAN = 2  # golden scores are 500/501; reserved for the cohort

# Fat substring key for the S6 benchmark shape: every non-golden entry with
# i % FAT_MOD == FAT_RESIDUE gets " Megaword" appended to its cn, so every
# substring-index key of the assertion (cn=*megaword*) holds ~entries/FAT_MOD
# IDs (~16.6k at the default 100k). S6 needs the keys to exceed 4x its
# ~3,900-entry bound (15,600), or the read cap under test never engages there.
FAT_TOKEN = "Megaword"
FAT_MOD = 6
FAT_RESIDUE = 3


def build_tag_assignments(rng, n_entries):
    """Pool of tag values, each used by 1-10 entries; 2 assignments per entry.

    Returns the truncated assignment list actually written to the data; any
    sample of "existing" tags must be drawn from THIS list, not from the full
    pool - the shuffle+truncate can drop every occurrence of a late pool
    value, so pool membership does not guarantee presence in the data."""
    need = 2 * n_entries
    assignments = []
    pool_size = 0
    while len(assignments) < need:
        value = "tag%06d" % pool_size
        pool_size += 1
        assignments.extend([value] * rng.randint(TAG_USE_MIN, TAG_USE_MAX))
    assert pool_size < 900000, "tag ids >= 900000 are reserved as guaranteed-missing"
    rng.shuffle(assignments)
    return assignments[:need], pool_size


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--entries", type=int, default=100000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--golden", type=int, default=120,
                    help="size of the planted always-matching cohort")
    ap.add_argument("--out", default="data.ldif")
    ap.add_argument("--manifest", default="data-manifest.json")
    args = ap.parse_args()

    n = args.entries
    if args.golden < 1 or args.golden > n:
        sys.exit("--golden must be within [1, --entries]")
    stride = n // args.golden
    rng = random.Random(args.seed)

    tag_assignments, tag_pool_size = build_tag_assignments(rng, n)
    golden_tags = ["taggolden%03d" % k for k in range(GOLDEN_TAG_COUNT)]
    golden_tags_b = ["taggoldenb%03d" % k for k in range(GOLDEN_TAG_COUNT)]

    titles = ["%s %s %d" % (lv, ro, k)
              for lv in TITLE_LEVELS for ro in TITLE_ROLES
              for k in range(TITLE_MAX_N)]
    depts = ["dept-%s-%03d" % (name, k)
             for name in DEPT_NAMES for k in range(DEPT_MAX_N)]
    notes = ["note %s %s %d" % (w1, w2, k)
             for w1 in NOTE_WORDS for w2 in NOTE_WORDS for k in range(10)]

    region_counts = {}
    golden_count = 0
    fat_count = 0
    out = open(args.out, "w")

    out.write("dn: %s\n" % SUFFIX)
    out.write("objectClass: top\n")
    out.write("objectClass: domain\n")
    out.write("dc: example\n\n")
    out.write("dn: %s\n" % PEOPLE)
    out.write("objectClass: top\n")
    out.write("objectClass: organizationalUnit\n")
    out.write("ou: people\n\n")

    for i in range(n):
        uid = "user%07d" % i
        # Draw every random field unconditionally so the stream of rng calls
        # (and therefore all non-golden entries) is independent of --golden.
        given = rng.choice(GIVEN_NAMES)
        sn = rng.choice(SURNAMES)
        title = rng.choice(titles)
        dept = rng.choice(depts)
        note = rng.choice(notes)
        region = GOLDEN_REGION if rng.random() < 0.5 else rng.choice(REGIONS_OTHER)
        score = rng.randint(0, SCORE_MAX)
        if GOLDEN_SCORE_BASE <= score < GOLDEN_SCORE_BASE + GOLDEN_SCORE_SPAN:
            score += GOLDEN_SCORE_SPAN  # keep the golden window golden-only
        level = rng.randint(0, LEVEL_MAX)
        flag = "TRUE" if rng.random() < 0.5 else "FALSE"
        n_mailalt = rng.randint(1, 2)
        tags = [tag_assignments[2 * i], tag_assignments[2 * i + 1]]

        is_golden = (i % stride == 0) and (i // stride) < args.golden
        if is_golden:
            g = i // stride
            given, sn = "Golden", "User"
            cn = "Golden User %05d" % g
            title = GOLDEN_TITLE
            dept = GOLDEN_DEPT
            note = GOLDEN_NOTE
            region = GOLDEN_REGION
            score = GOLDEN_SCORE_BASE + (g % GOLDEN_SCORE_SPAN)
            level = GOLDEN_LEVEL
            flag = GOLDEN_FLAG
            tags = [golden_tags[g % GOLDEN_TAG_COUNT],
                    golden_tags_b[g % GOLDEN_TAG_COUNT]]
            golden_count += 1
        else:
            cn = "%s %s %d" % (given, sn, i)
            if i % FAT_MOD == FAT_RESIDUE:
                cn += " " + FAT_TOKEN
                fat_count += 1

        region_counts[region] = region_counts.get(region, 0) + 1

        lines = [
            "dn: uid=%s,%s" % (uid, PEOPLE),
            "objectClass: top",
            "objectClass: person",
            "objectClass: organizationalPerson",
            "objectClass: inetOrgPerson",
            "objectClass: reproPerson",
            "uid: " + uid,
            "cn: " + cn,
            "sn: " + sn,
            "givenName: " + given,
            "mail: %s@example.com" % uid,
            "reproTitle: " + title,
            "reproDept: " + dept,
            "reproRegion: " + region,
            "reproHostname: host%07d.example.com" % i,
            "reproScore: %d" % score,
            "reproLevel: %d" % level,
            "reproManager: uid=user%07d,%s" % (i % MANAGER_MOD, PEOPLE),
            "reproFlag: " + flag,
            "reproNote: " + note,
        ]
        for t in dict.fromkeys(tags):
            lines.append("reproTag: " + t)
        for m in range(n_mailalt):
            lines.append("reproMailAlt: %s.alt%d@alt.example.net" % (uid, m))
        out.write("\n".join(lines))
        out.write("\n\n")
    out.close()

    surviving_tags = sorted(set(tag_assignments))
    existing_sample = rng.sample(surviving_tags, min(2500, len(surviving_tags)))

    manifest = {
        "entries": n,
        "seed": args.seed,
        "suffix": SUFFIX,
        "people_ou": PEOPLE,
        "golden": {
            "count": golden_count,
            "stride": stride,
            "tags": golden_tags,
            "score_min": GOLDEN_SCORE_BASE,
            "score_max": GOLDEN_SCORE_BASE + GOLDEN_SCORE_SPAN - 1,
            "level": GOLDEN_LEVEL,
            "region": GOLDEN_REGION,
            "flag": GOLDEN_FLAG,
            "note": GOLDEN_NOTE,
            "dept": GOLDEN_DEPT,
            "title": GOLDEN_TITLE,
            "cn_prefix": "Golden User",
        },
        "tag_pool_size": tag_pool_size,
        "tag_format": "tag%06d",
        "tag_missing_id_floor": 900000,
        "tag_use_range": [TAG_USE_MIN, TAG_USE_MAX],
        "existing_tag_sample": existing_sample,
        "fat_substring": {
            "token": FAT_TOKEN,
            "assertion": "(cn=*%s*)" % FAT_TOKEN.lower(),
            "count": fat_count,
            "mod": FAT_MOD,
            "residue": FAT_RESIDUE,
        },
        "regions": region_counts,
        "title_levels": TITLE_LEVELS,
        "title_roles": TITLE_ROLES,
        "title_max_n": TITLE_MAX_N,
        "dept_names": DEPT_NAMES,
        "dept_max_n": DEPT_MAX_N,
        "note_words": NOTE_WORDS,
        "notes_sample": rng.sample(notes, 60),
        "given_names": GIVEN_NAMES,
        "surnames": SURNAMES,
        "score_range": [0, SCORE_MAX],
        "level_range": [0, LEVEL_MAX],
        "level_wide": list(LEVEL_WIDE),
        "hostname_format": "host%07d.example.com",
        "manager_mod": MANAGER_MOD,
    }
    with open(args.manifest, "w") as f:
        json.dump(manifest, f, indent=2)

    print("wrote %s (%d entries, %d golden) and %s"
          % (args.out, n, golden_count, args.manifest))


if __name__ == "__main__":
    main()
