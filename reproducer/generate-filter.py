#!/usr/bin/env python3
"""Generate benchmark filters + independently computed expected result sets.

Reads data-manifest.json AND data.ldif (both written by generate-data.py).
Every shape is built as a small filter AST; the filter string and the
expected DN set are both derived from that one AST, so the expectation
cannot drift from the filter. Expected sets are computed by evaluating the
AST against the actual data.ldif contents - independent of either server.

Per shape, emits:
  filter-<shape>.txt        one-line LDAP filter
  expected-dns-<shape>.txt  sorted "dn: ..." lines, exactly the lines a
                            correct server returns (compare count + md5)
  shapes-manifest.json      one entry per shape: files, expected count/md5,
                            expect_cap tri-state, parameters

Shapes (see the design doc / README for provenance):
  s1        the accepted 600-substring mega-AND (the read-cap winning shape);
            legacy knobs --target-bytes/--big-or/--substr/... apply here
  s2-uid-N  all-live equality OR of N distinct uids (issue #6275's literal
            shape: N singleton ID lists), N in {125,250,500,1000}
  s2-tag-N  all-live equality OR of N existing reproTag values (member-like
            ID-list profile), same N ladder - the union-rewrite gate shapes
  s3        AND(eq, OR(substrings)) - compound costly component capped via
            pass-down
  s3b       OR of two bounded ANDs, each (eq ~100)(fat substring) - the
            composition shape; must NOT engage the cap (pure-AND ancestry)
  s4-N      SSSD-sudo analog AND(objectClass, OR(N reproTag eqs)), N in
            {10,400}; no substrings, cap never applies
  s5        issue #811 shape: broad objectClass-OR then selective equality
  s6        the cap's losing shape: score-OR bounding just under the floor,
            then one fat substring whose keys exceed 4x the bound
  s7-and-N  ISOLATION, AND only: one bounding reproScore equality plus N
            fat substring assertions (infix/suffix placements of the
            Megaword token), N in {1,4,16,64} - nothing else. Baseline
            cost grows with N (N fat reads); a capped build stays flat.
  s7-eqlast s7-and-16 with the equality written LAST (placement probe:
            the optimizer hoists it, so timing must match s7-and-16)
  s8-orsub-N ISOLATION, OR only: top-level OR of N substring assertions
            (3/4 fat Megaword forms, 1/4 absent), N in {4,16,64}; never
            capped (top-level OR), pins OR behavior under the series
  s9-not-M  s7-and-4 plus M no-op NOT components (absent substrings,
            absent tag equalities, absent unindexed notes), M in {8,32};
            result set identical to s7-and-4 by construction - measures
            whether NOTs change the AND-cap picture (they must not)
  s9-notfirst s7-and-4 with a NOT-of-equality as the FIRST component
            (the isnot f==f_head path, the double-free fix's path)

expect_cap in the manifest is the per-shape read-cap expectation on a
cap-capable build (true = the diagnostic line must appear, false = it must
not, null = not checked); run-benchmark.sh enforces it only when
REPRO_CAP_BUILD=1.
"""

import argparse
import hashlib
import json
import random
import sys

FORBIDDEN = set("()*\\\0")

S2_SIZES = [125, 250, 500, 1000]
S4_SIZES = [10, 400]
S7_SIZES = [1, 4, 16, 64]
S8_SIZES = [4, 16, 64]
S9_SIZES = [8, 32]
S10_SIZES = [32, 64, 128]  # member values per group class (m-guard bracket)


def esc_check(value):
    bad = FORBIDDEN.intersection(value)
    if bad:
        sys.exit("value %r needs LDAP filter escaping (%s) - not supported" % (value, bad))
    return value


# --------------------------------------------------------------------------
# Filter AST: one source for both the rendered string and the expected set.
#
# Nodes (tuples):
#   ("and", [n...]) ("or", [n...]) ("not", n)
#   ("eq", attr, value)        caseIgnore equality
#   ("eqexact", attr, value)   case-exact equality (IA5 attrs; renders like eq)
#   ("sub", attr, pattern)     caseIgnore substring; pattern contains '*'
#   ("pres", attr)
#   ("ge", attr, n) ("le", attr, n)   integer ordering
#   ("ext", attr, rule, value) extensible match; only caseExactMatch is used
# --------------------------------------------------------------------------

def render(node):
    kind = node[0]
    if kind == "and":
        return "(&%s)" % "".join(render(c) for c in node[1])
    if kind == "or":
        return "(|%s)" % "".join(render(c) for c in node[1])
    if kind == "not":
        return "(!%s)" % render(node[1])
    if kind in ("eq", "eqexact"):
        return "(%s=%s)" % (node[1], esc_check(str(node[2])))
    if kind == "sub":
        esc_check(node[2].replace("*", ""))
        return "(%s=%s)" % (node[1], node[2])
    if kind == "pres":
        return "(%s=*)" % node[1]
    if kind == "ge":
        return "(%s>=%d)" % (node[1], node[2])
    if kind == "le":
        return "(%s<=%d)" % (node[1], node[2])
    if kind == "ext":
        return "(%s:%s:=%s)" % (node[1], node[2], esc_check(node[3]))
    raise AssertionError("unknown node kind %r" % kind)


def match_substr(value, parts):
    """LDAP substring match (already case-folded); parts = pattern.split('*')."""
    if parts[0] and not value.startswith(parts[0]):
        return False
    if parts[-1] and not value.endswith(parts[-1]):
        return False
    pos = len(parts[0])
    limit = len(value) - len(parts[-1])
    for part in parts[1:-1]:
        if not part:
            continue
        i = value.find(part, pos)
        if i < 0 or i + len(part) > limit:
            return False
        pos = i + len(part)
    return True


class Data:
    """data.ldif parsed into per-entry attribute maps + equality indexes."""

    def __init__(self, path):
        self.dns = []
        self.attrs = []  # per entry: {attr_lower: [raw values]}
        cur_dn, cur = None, {}
        with open(path) as f:
            for line in f:
                line = line.rstrip("\n")
                if not line:
                    if cur_dn is not None:
                        self.dns.append(cur_dn)
                        self.attrs.append(cur)
                    cur_dn, cur = None, {}
                    continue
                key, _, val = line.partition(": ")
                if key == "dn":
                    cur_dn = val
                else:
                    cur.setdefault(key.lower(), []).append(val)
        if cur_dn is not None:
            self.dns.append(cur_dn)
            self.attrs.append(cur)
        self.all_ids = frozenset(range(len(self.dns)))
        self._eq_index = {}

    def eq_index(self, attr):
        a = attr.lower()
        if a not in self._eq_index:
            idx = {}
            for i, e in enumerate(self.attrs):
                for v in e.get(a, ()):
                    idx.setdefault(v.lower(), set()).add(i)
            self._eq_index[a] = idx
        return self._eq_index[a]

    def evaluate(self, node):
        kind = node[0]
        if kind == "and":
            sets = [self.evaluate(c) for c in node[1]]
            out = sets[0]
            for s in sets[1:]:
                out = out & s
            return out
        if kind == "or":
            out = set()
            for c in node[1]:
                out |= self.evaluate(c)
            return out
        if kind == "not":
            return self.all_ids - self.evaluate(node[1])
        if kind == "eq":
            return self.eq_index(node[1]).get(str(node[2]).lower(), set())
        if kind == "eqexact":
            a, want = node[1].lower(), str(node[2])
            return {i for i in self.eq_index(node[1]).get(want.lower(), set())
                    if want in self.attrs[i].get(a, ())}
        if kind == "sub":
            a = node[1].lower()
            parts = node[2].lower().split("*")
            return {i for i, e in enumerate(self.attrs)
                    if any(match_substr(v.lower(), parts) for v in e.get(a, ()))}
        if kind == "pres":
            a = node[1].lower()
            return {i for i, e in enumerate(self.attrs) if a in e}
        if kind in ("ge", "le"):
            a, bound = node[1].lower(), node[2]
            out = set()
            for i, e in enumerate(self.attrs):
                for v in e.get(a, ()):
                    try:
                        n = int(v)
                    except ValueError:
                        continue
                    if (n >= bound) if kind == "ge" else (n <= bound):
                        out.add(i)
                        break
            return out
        if kind == "ext":
            if node[2] != "caseExactMatch":
                sys.exit("unsupported extensible rule %r" % node[2])
            a, want = node[1].lower(), node[3]
            return {i for i, e in enumerate(self.attrs)
                    if want in e.get(a, ())}
        raise AssertionError("unknown node kind %r" % kind)


# --------------------------------------------------------------------------
# s1: the legacy mega-AND, AST-ified with identical component formats.
# --------------------------------------------------------------------------

def build_substr_components(rng, m, count):
    """Mix of prefix / infix / leading-wildcard substring assertions on cn
    and reproTitle, roughly half matching real data, half not."""
    comps = [("sub", "cn", "%s*" % m["golden"]["cn_prefix"])]  # golden anchor
    fake_fragments = ["Zzyq", "Qxev", "Vroth", "Klyx", "Wubb", "Jyxx"]
    while len(comps) < count:
        kind = len(comps) % 3          # 0 prefix, 1 infix, 2 suffix
        use_cn = rng.random() < 0.6
        matching = rng.random() < 0.5
        if use_cn:
            frag = (rng.choice(m["given_names"]) if kind == 0
                    else rng.choice(m["surnames"]))
            if not matching:
                frag = rng.choice(fake_fragments)
            if kind == 0:
                comps.append(("sub", "cn", "%s*" % frag))
            elif kind == 1:
                comps.append(("sub", "cn", "*%s*" % frag[1:5]))
            else:
                comps.append(("sub", "cn", "*%s" % frag[-4:]))
        else:
            level = rng.choice(m["title_levels"])
            role = rng.choice(m["title_roles"])
            if not matching:
                level = rng.choice(fake_fragments)
            if kind == 0:
                comps.append(("sub", "reproTitle", "%s*" % level))
            elif kind == 1:
                comps.append(("sub", "reproTitle", "*%s*" % role[:4]))
            else:
                comps.append(("sub", "reproTitle",
                              "*%s %d" % (role, rng.randint(0, m["title_max_n"] - 1))))
    return comps[:count]


def build_not_components(rng, m, count):
    """Three flavors of NOT, none of which can exclude a golden entry."""
    golden = m["golden"]
    regions = sorted(set(m["regions"]) - {golden["region"]})
    real_depts = ["dept-%s-%03d" % (rng.choice(m["dept_names"]),
                                    rng.randint(0, m["dept_max_n"] - 1))
                  for _ in range(count)]
    real_titles = ["%s %s %d" % (rng.choice(m["title_levels"]),
                                 rng.choice(m["title_roles"]),
                                 rng.randint(0, m["title_max_n"] - 1))
                   for _ in range(count)]
    regular_tags = [t for t in m["existing_tag_sample"]][:count]
    stride = golden["stride"]
    non_golden_idx = [i for i in range(1, count * stride) if i % stride != 0]
    rng.shuffle(non_golden_idx)
    notes = [v for v in m["notes_sample"] if v != golden["note"]]

    third = count // 3
    comps = []
    # flavor 1: simple NOT on indexed attributes
    for k in range(third):
        pick = k % 4
        if pick == 0:
            comps.append(("not", ("eq", "reproRegion", regions[k % len(regions)])))
        elif pick == 1:
            comps.append(("not", ("eq", "reproDept", real_depts[k])))
        elif pick == 2:
            comps.append(("not", ("eq", "reproTag", regular_tags[k])))
        else:
            comps.append(("not", ("eqexact", "reproHostname",
                                  m["hostname_format"] % non_golden_idx[k])))
    # flavor 2: NOT over a nested OR
    for k in range(third):
        comps.append(("not", ("or", [("eq", "reproDept", real_depts[third + k]),
                                     ("eq", "reproTitle", real_titles[k])])))
    # flavor 3: NOT on the two UNINDEXED attributes
    comps.append(("not", ("eq", "reproFlag", "TRUE")))  # golden cohort is FALSE
    k = 0
    while len(comps) < count:
        comps.append(("not", ("eq", "reproNote", notes[k % len(notes)])))
        k += 1
    return comps


def build_deep_chain(m, depth):
    """Alternating AND/OR chain, fan-out 2 per level; semantically reduces to
    (reproRegion=emea AND reproFlag=FALSE), both true for the golden cohort:
    the AND sibling (reproFlag=FALSE) matches every golden entry, the OR
    sibling never matches (tagabsent* values cannot exist - real tags are
    tagNNNNNN). The AND sibling is an equality, not an inequality: wide-open
    integer inequalities dominate OpenLDAP evaluation via index-key scans
    (iteration 1), drowning the filter-processing signal."""
    node = ("eq", "reproRegion", m["golden"]["region"])
    for k in range(1, depth + 1):
        if k % 2 == 1:
            node = ("and", [("eq", "reproFlag", m["golden"]["flag"]), node])
        else:
            node = ("or", [("eq", "reproTag", "tagabsent%03d" % k), node])
    return node


def build_extensible(m, count=5):
    """Five mutually exclusive case-exact cn assertions; ANDed at top level
    the shape is an always-empty probe (an entry has one cn value)."""
    return [("ext", "cn", "caseExactMatch",
             "%s %05d" % (m["golden"]["cn_prefix"], k))
            for k in range(count)]


def build_s1(rng, m, args):
    golden = m["golden"]
    substr = build_substr_components(rng, m, args.substr)
    nots = build_not_components(rng, m, args.nots)
    presence = [("pres", a) for a in ("cn", "objectClass", "reproTitle", "reproMailAlt")]
    narrow = ("and", [("ge", "reproScore", golden["score_min"]),
                      ("le", "reproScore", golden["score_max"])])
    wide = ("and", [("ge", "reproLevel", m["level_wide"][0]),
                    ("le", "reproLevel", m["level_wide"][1])])
    chain = build_deep_chain(m, args.depth)
    dups = [("eq", "reproRegion", golden["region"])] * args.dups
    ext = build_extensible(m) if args.extensible else []

    fixed_nodes = ([("or", substr)] if substr else []) + nots + presence \
        + [narrow, wide, chain] + dups + ext
    fixed_len = sum(len(render(nd)) for nd in fixed_nodes)

    golden_comps = [("eq", "reproTag", t) for t in golden["tags"]]
    golden_len = sum(len(render(c)) for c in golden_comps)
    regular_comp_len = len("(reproTag=tag000000)")
    overhead = len("(&") + len("(|)") + len(")")

    if args.big_or > 0:
        big_or_n = args.big_or
    else:
        budget = args.target_bytes - fixed_len - overhead - golden_len
        if budget <= 0:
            sys.exit("--target-bytes too small for the fixed components")
        big_or_n = len(golden_comps) + budget // regular_comp_len

    n_regular = big_or_n - len(golden_comps)
    if n_regular < 0:
        sys.exit("--big-or must be >= %d (golden tag count)" % len(golden_comps))
    n_existing = max(0, round(args.big_or_existing_frac * big_or_n) - len(golden_comps))
    if n_existing > len(m["existing_tag_sample"]):
        sys.exit("data manifest existing_tag_sample too small (%d < %d)"
                 % (len(m["existing_tag_sample"]), n_existing))
    n_missing = n_regular - n_existing

    existing_vals = rng.sample(m["existing_tag_sample"], n_existing)
    floor = m["tag_missing_id_floor"]
    missing_vals = ["tag%06d" % v for v in rng.sample(range(floor, floor + 99999),
                                                      n_missing)]
    regular_comps = [("eq", "reproTag", v) for v in existing_vals + missing_vals]
    rng.shuffle(regular_comps)
    big_or = ("or", golden_comps + regular_comps)

    ast = ("and", [big_or] + fixed_nodes)
    substr_strs = [render(c) for c in substr]
    not_strs = [render(c) for c in nots]
    params = {
        "target_bytes": args.target_bytes,
        "components": {
            "big_or_eq_total": big_or_n,
            "big_or_golden_tags": len(golden_comps),
            "big_or_existing_regular": n_existing,
            "big_or_missing": n_missing,
            "big_or_existing_fraction": round(
                (n_existing + len(golden_comps)) / big_or_n, 4),
            "substring_total": len(substr),
            "substring_prefix": sum(1 for c in substr_strs
                                    if c.endswith("*)") and "*" not in c[:-2]),
            "substring_infix": sum(1 for c in substr_strs if c.count("*") == 2),
            "substring_leading_wildcard": sum(1 for c in substr_strs
                                              if "=*" in c and c.count("*") == 1),
            "not_total": len(nots),
            "not_nested_or": sum(1 for c in not_strs if c.startswith("(!(|")),
            "not_unindexed": sum(1 for c in not_strs
                                 if "reproFlag" in c or "reproNote" in c),
            "presence": len(presence),
            "range_pairs": 2,
            "deep_chain_levels": args.depth,
            "verbatim_duplicates": args.dups,
            "extensible": len(ext),
        },
    }
    return ast, params


# --------------------------------------------------------------------------
# The other shapes.
# --------------------------------------------------------------------------

def build_s2_uid(rng, m, n):
    ids = rng.sample(range(m["entries"]), n)
    return ("or", [("eqexact", "uid", "user%07d" % i) for i in ids]), \
        {"or_values": n, "attr": "uid", "all_live": True}


def build_s2_tag(rng, m, n):
    if n > len(m["existing_tag_sample"]):
        sys.exit("s2-tag-%d: existing_tag_sample too small" % n)
    vals = rng.sample(m["existing_tag_sample"], n)
    return ("or", [("eq", "reproTag", v) for v in vals]), \
        {"or_values": n, "attr": "reproTag", "all_live": True}


def build_s3(rng, m):
    golden = m["golden"]
    fat = m["fat_substring"]
    inner = [("sub", "cn", "%s*" % golden["cn_prefix"]),
             ("sub", "cn", "*%s*" % fat["token"].lower()),
             ("sub", "cn", "*zzyq*"),
             ("sub", "reproTitle", "%s*" % golden["title"].rsplit(" ", 1)[0])]
    ast = ("and", [("eq", "reproDept", golden["dept"]), ("or", inner)])
    return ast, {"bound_attr": "reproDept", "inner_substrings": len(inner)}


def build_s3b(rng, m, data):
    """Two bounded ANDs under a top-level OR; each branch bound ~100-200 via
    one reproScore equality, each with the fat substring. On a build with
    pure-AND-ancestry gating neither branch may engage the cap."""
    fat = m["fat_substring"]
    scores = []
    for v in range(0, 1000):
        if v in (m["golden"]["score_min"], m["golden"]["score_max"]):
            continue
        cnt = len(data.eq_index("reproScore").get(str(v), ()))
        if 50 <= cnt <= 300:
            scores.append(v)
        if len(scores) == 2:
            break
    if len(scores) < 2:
        sys.exit("s3b: no suitable reproScore values found")
    branches = [("and", [("eq", "reproScore", str(v)),
                         ("sub", "cn", "*%s*" % fat["token"].lower())])
                for v in scores]
    return ("or", branches), {"branch_scores": scores,
                              "fat_key_ids": fat["count"]}


def build_s4(rng, m, n):
    if n > len(m["existing_tag_sample"]):
        sys.exit("s4-%d: existing_tag_sample too small" % n)
    vals = rng.sample(m["existing_tag_sample"], n)
    ast = ("and", [("eq", "objectClass", "reproPerson"),
                   ("or", [("eq", "reproTag", v) for v in vals])])
    return ast, {"or_values": n, "all_live": True}


def build_s10(m, msize):
    """OR of target_width member equalities against the group class whose
    entries hold msize member values each. The per-entry DN value-count
    guard of the OR-lookup fast path declines when msize exceeds the OR's
    component count, so the three classes bracket the crossover."""
    s10 = m.get("s10")
    if not s10:
        sys.exit("data-manifest.json has no s10 block - regenerate the data "
                 "with the current generate-data.py")
    ci = s10["classes"].index(msize)
    base = s10["target_bases"][ci]
    member_fmt = s10["member_format"]
    values = [member_fmt % (base + t) for t in range(s10["target_width"])]
    return ("or", [("eq", "member", v) for v in values]), \
        {"or_values": s10["target_width"], "attr": "member",
         "group_member_count": msize,
         "expected_groups": s10["expected_per_class"]}


def build_s5(rng, m):
    host = m["hostname_format"] % (m["entries"] // 2)
    ast = ("and", [("or", [("eq", "objectClass", "inetOrgPerson"),
                           ("eq", "objectClass", "organizationalPerson")]),
                   ("eqexact", "reproHostname", host)])
    return ast, {"broad_oc_or": 2, "selective_eq": host}


def build_s6(rng, m, data):
    """Bound just under the cap floor (target [3600, 3900]) via a reproScore
    OR, then one fat substring. The fat key must exceed 4x the bound or the
    cap never engages and the row silently measures baseline-vs-baseline."""
    fat = m["fat_substring"]
    idx = data.eq_index("reproScore")
    candidates = [v for v in range(0, 1000)
                  if v not in (m["golden"]["score_min"], m["golden"]["score_max"])]
    rng.shuffle(candidates)
    chosen, total = [], 0
    for v in candidates:
        cnt = len(idx.get(str(v), ()))
        if total + cnt > 3900:
            continue
        chosen.append(v)
        total += cnt
        if total >= 3600:
            break
    if not (3600 <= total <= 3900):
        sys.exit("s6: could not reach a bound in [3600, 3900] (got %d)" % total)
    if fat["count"] <= 4 * total + 200:
        sys.exit("s6: fat key %d IDs does not clear 4x bound %d with margin - "
                 "cap would not engage" % (fat["count"], total))
    chosen.sort()
    ast = ("and", [("or", [("eq", "reproScore", str(v)) for v in chosen]),
                   ("sub", "cn", "*%s*" % fat["token"].lower())])
    return ast, {"bound": total, "score_values": len(chosen),
                 "fat_key_ids": fat["count"], "dyn_at_bound": 4 * total}


# --------------------------------------------------------------------------
# Isolation shapes (s7/s8/s9): one variable per ladder, everything else
# fixed, so a timing change is attributable to exactly one mechanism.
# --------------------------------------------------------------------------

def fat_substring_forms(m):
    """Distinct substring assertions that all match exactly the Megaword
    cohort: every infix substring and every suffix of the fat token, of
    length >= 4 (3-grams like *wor* also match ordinary names, which
    would break the equal-results property of the s8 ladder). 20
    distinct forms at the default token."""
    token = m["fat_substring"]["token"].lower()
    infix = ["*%s*" % token[i:i + l]
             for l in range(4, len(token) + 1)
             for i in range(len(token) - l + 1)]
    suffix = ["*%s" % token[-l:] for l in range(4, len(token) + 1)]
    # dedupe while keeping order ("*megaword*" appears once)
    seen, forms = set(), []
    for p in infix + suffix:
        if p not in seen:
            seen.add(p)
            forms.append(p)
    return forms


def pick_bounding_score(m, data):
    """Deterministic reproScore value with a moderate ID count (the AND
    bound); excludes the golden-reserved window."""
    idx = data.eq_index("reproScore")
    for v in range(0, 1000):
        if v in (m["golden"]["score_min"], m["golden"]["score_max"]):
            continue
        if 80 <= len(idx.get(str(v), ())) <= 150:
            return v
    sys.exit("no reproScore value with 80..150 IDs found")


def build_s7(rng, m, data, n, eq_last=False):
    forms = fat_substring_forms(m)
    subs = [("sub", "cn", forms[k % len(forms)]) for k in range(n)]
    score = pick_bounding_score(m, data)
    eq = ("eq", "reproScore", str(score))
    ast = ("and", subs + [eq] if eq_last else [eq] + subs)
    return ast, {"substrings": n, "distinct_forms": min(n, len(forms)),
                 "bound_score": score, "eq_position": "last" if eq_last else "first",
                 "fat_key_ids": m["fat_substring"]["count"]}


def build_s8(rng, m, n):
    """Top-level OR: 3/4 fat Megaword forms, 1/4 absent fragments. The
    result set is the fat cohort at every ladder size, so growth along
    the ladder is attributable to per-component work only."""
    forms = fat_substring_forms(m)
    comps = []
    for k in range(n):
        if k % 4 == 3:
            comps.append(("sub", "cn", "*zzyqor%03d*" % k))
        else:
            comps.append(("sub", "cn", forms[k % len(forms)]))
    return ("or", comps), {"substrings": n, "absent": n // 4,
                           "fat_key_ids": m["fat_substring"]["count"]}


def build_s9_not(rng, m, data, n_nots):
    """s7-and-4 plus no-op NOT components in three flavors (absent
    substring, absent indexed equality, absent unindexed equality); the
    result set is identical to s7-and-4 by construction."""
    ast, params = build_s7(rng, m, data, 4)
    floor = m["tag_missing_id_floor"]
    nots = []
    for k in range(n_nots):
        flavor = k % 3
        if flavor == 0:
            nots.append(("not", ("sub", "cn", "*zzyqnot%03d*" % k)))
        elif flavor == 1:
            nots.append(("not", ("eq", "reproTag", "tag%06d" % (floor + 500 + k))))
        else:
            nots.append(("not", ("eq", "reproNote", "note zzyq zzyq %d" % k)))
    base = list(ast[1])
    params = dict(params, nots=n_nots)
    return ("and", base + nots), params


def build_s9_notfirst(rng, m):
    """NOT-of-equality written (and staying) FIRST: the AND has no plain
    equality for the optimizer to hoist ahead of it, so candidate
    generation takes the isnot f==f_head path (ALLIDS subtraction base -
    the path of the NOT-first double-free fix). The ALLIDS insert leaves
    idl_set->minimum unset, so the first fat substring is read in full
    and the second is waived by the floor ceiling: no capping here."""
    floor = m["tag_missing_id_floor"]
    forms = fat_substring_forms(m)
    ast = ("and", [("not", ("eq", "reproTag", "tag%06d" % (floor + 777))),
                   ("sub", "cn", forms[0]),
                   ("sub", "cn", forms[1])])
    return ast, {"fat_key_ids": m["fat_substring"]["count"]}


# --------------------------------------------------------------------------

def max_paren_depth(s):
    depth = best = 0
    for c in s:
        if c == "(":
            depth += 1
            best = max(best, depth)
        elif c == ")":
            depth -= 1
    if depth != 0:
        sys.exit("unbalanced parentheses in generated filter")
    return best


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data-manifest", default="data-manifest.json")
    ap.add_argument("--data", default="data.ldif")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--shapes", default="s1",
                    help="comma list of shapes, or 'all'")
    # s1 (legacy mega-AND) knobs; defaults are the accepted reproducer config.
    ap.add_argument("--target-bytes", type=int, default=44000)
    ap.add_argument("--big-or", type=int, default=0,
                    help="explicit s1 big-OR width; 0 = auto-tune to --target-bytes")
    ap.add_argument("--big-or-existing-frac", type=float, default=0.30)
    ap.add_argument("--substr", type=int, default=600)
    ap.add_argument("--nots", type=int, default=60)
    ap.add_argument("--dups", type=int, default=20)
    ap.add_argument("--depth", type=int, default=12)
    ap.add_argument("--extensible", action="store_true",
                    help="add extensible-match components to s1 (always-empty "
                         "AND probe; off for baseline)")
    ap.add_argument("--manifest-out", default="shapes-manifest.json")
    args = ap.parse_args()

    with open(args.data_manifest) as f:
        m = json.load(f)
    if "fat_substring" not in m:
        sys.exit("data-manifest.json has no fat_substring block - regenerate "
                 "the data with the current generate-data.py")

    all_shapes = (["s1"]
                  + ["s2-uid-%d" % n for n in S2_SIZES]
                  + ["s2-tag-%d" % n for n in S2_SIZES]
                  + ["s3", "s3b"]
                  + ["s4-%d" % n for n in S4_SIZES]
                  + ["s5", "s6"]
                  + ["s7-and-%d" % n for n in S7_SIZES]
                  + ["s7-eqlast"]
                  + ["s8-orsub-%d" % n for n in S8_SIZES]
                  + ["s9-not-%d" % n for n in S9_SIZES]
                  + ["s9-notfirst"]
                  + ["s10-member-%d" % n for n in S10_SIZES])
    wanted = all_shapes if args.shapes == "all" else args.shapes.split(",")
    unknown = [s for s in wanted if s not in all_shapes]
    if unknown:
        sys.exit("unknown shapes %s (known: %s)" % (unknown, ", ".join(all_shapes)))

    print("parsing %s ..." % args.data)
    data = Data(args.data)
    group_entries = m.get("group_entries", 0)
    parents = 2 + (1 if group_entries else 0)
    if len(data.dns) != m["entries"] + group_entries + parents:
        sys.exit("data.ldif has %d entries, manifest says %d users + %d groups "
                 "(+%d parents)"
                 % (len(data.dns), m["entries"], group_entries, parents))

    # expect_cap: tri-state read-cap expectation on a cap-capable build.
    expect_cap = {"s1": True, "s3": True, "s3b": False, "s5": False, "s6": True,
                  "s7-eqlast": True, "s9-notfirst": False}
    for n in S2_SIZES:
        expect_cap["s2-uid-%d" % n] = False
        expect_cap["s2-tag-%d" % n] = False
    for n in S4_SIZES:
        expect_cap["s4-%d" % n] = False
    for n in S7_SIZES:
        expect_cap["s7-and-%d" % n] = True
    for n in S8_SIZES:
        expect_cap["s8-orsub-%d" % n] = False
    for n in S9_SIZES:
        expect_cap["s9-not-%d" % n] = True
    for n in S10_SIZES:
        expect_cap["s10-member-%d" % n] = False

    manifest = {}
    for shape in wanted:
        rng = random.Random("%s/%d" % (shape, args.seed))
        if shape == "s1":
            ast, params = build_s1(rng, m, args)
        elif shape.startswith("s2-uid-"):
            ast, params = build_s2_uid(rng, m, int(shape.rsplit("-", 1)[1]))
        elif shape.startswith("s2-tag-"):
            ast, params = build_s2_tag(rng, m, int(shape.rsplit("-", 1)[1]))
        elif shape == "s3":
            ast, params = build_s3(rng, m)
        elif shape == "s3b":
            ast, params = build_s3b(rng, m, data)
        elif shape.startswith("s4-"):
            ast, params = build_s4(rng, m, int(shape.rsplit("-", 1)[1]))
        elif shape == "s5":
            ast, params = build_s5(rng, m)
        elif shape == "s6":
            ast, params = build_s6(rng, m, data)
        elif shape.startswith("s7-and-"):
            ast, params = build_s7(rng, m, data, int(shape.rsplit("-", 1)[1]))
        elif shape == "s7-eqlast":
            ast, params = build_s7(rng, m, data, 16, eq_last=True)
        elif shape.startswith("s8-orsub-"):
            ast, params = build_s8(rng, m, int(shape.rsplit("-", 1)[1]))
        elif shape.startswith("s9-not-"):
            ast, params = build_s9_not(rng, m, data, int(shape.rsplit("-", 1)[1]))
        elif shape == "s9-notfirst":
            ast, params = build_s9_notfirst(rng, m)
        elif shape.startswith("s10-member-"):
            ast, params = build_s10(m, int(shape.rsplit("-", 1)[1]))

        filt = render(ast)
        expected_ids = data.evaluate(ast)
        expected_lines = sorted("dn: %s" % data.dns[i] for i in expected_ids)
        expected_text = "".join(line + "\n" for line in expected_lines)
        md5 = hashlib.md5(expected_text.encode()).hexdigest()

        filter_file = "filter-%s.txt" % shape
        expected_file = "expected-dns-%s.txt" % shape
        with open(filter_file, "w") as f:
            f.write(filt + "\n")
        with open(expected_file, "w") as f:
            f.write(expected_text)

        manifest[shape] = {
            "filter_file": filter_file,
            "expected_file": expected_file,
            "expected_count": len(expected_ids),
            "expected_md5": md5,
            "expect_cap": expect_cap.get(shape),
            "filter_bytes": len(filt),
            "nesting_depth": max_paren_depth(filt),
            "params": params,
        }
        print("%-12s %7d bytes  expected %6d entries  md5 %s"
              % (shape, len(filt), len(expected_ids), md5))

    with open(args.manifest_out, "w") as f:
        json.dump({"seed": args.seed, "shapes": manifest}, f, indent=2)
    print("wrote %s (%d shapes)" % (args.manifest_out, len(manifest)))


if __name__ == "__main__":
    main()
