# Collected discussions: issues #2414, #841, and #811

Collected via GitHub's issue, comment, and timeline APIs. Dates below are the original Pagure timestamps embedded in the migration unless noted otherwise.

## Issue #2414 — “keep indexes for tombstones”

[Issue](https://github.com/389ds/389-ds-base/issues/2414) — closed WONTFIX.

Surface counts:

- 1 issue body.
- 8 issue comments: 6 substantive, 2 metadata-only.
- 1 inbound cross-reference, from issue #2431.
- 0 linked, closing, or referencing pull requests.
- Consequently: 0 PR bodies, 0 PR conversation comments, 0 submitted review bodies, and 0 inline review comments.

Chronology:

- **2017-08-17 15:18:10 — lkrispen/elkris — [issue body](https://github.com/389ds/389-ds-base/issues/2414):** Deleted entries become tombstones and are removed from most ordinary indexes. This makes tombstone search results depend on filter order and the candidate threshold. A tombstone-first AND with an indexed `sn` can return one result below the threshold and none above it; the reversed AND returns none; analogous filters using an unindexed `description` return the entry in either order. Ordinary searches already hide tombstones unless the filter requests `objectClass=nsTombstone`, so the proposal is to retain their normal index values and obtain consistent tombstone searches.
- **2017-08-18 01:36:38 — Firstyear — [comment](https://github.com/389ds/389-ds-base/issues/2414#issuecomment-691595299):** Attributes removed from indexes produce empty IDLs and trigger early return, whereas the tombstone object-class path can produce ALLIDS and force entry-level filtering. He characterizes the problem as trying to hide tombstones while still using the normal search machinery. He proposes a tombstone-presence flag and automatic injection of a tombstone-exclusion term for normal searches, allowing tombstones and ordinary entries to share indexes. Alternatives mentioned are marking tombstones as LDAP subentries or storing them under a hidden suffix.
- **2017-08-18 01:36:39 — Firstyear — [comment](https://github.com/389ds/389-ds-base/issues/2414#issuecomment-691595300):** **Metadata-only.** Cleared the component, origin, review-status, type, and version fields.
- **2017-08-18 11:12:24 — lkrispen/elkris — [comment](https://github.com/389ds/389-ds-base/issues/2414#issuecomment-691595301):** Notes that a tombstone filter flag and entry-level hiding check already exist, so hiding ordinary searches works. The unresolved problem is inconsistent results when tombstones are explicitly requested. Agrees with retaining the same indexes for both entry kinds, subject to checking for regressions.
- **2017-08-18 12:54:42 — tbordaz — [comment](https://github.com/389ds/389-ds-base/issues/2414#issuecomment-691595303):** Says common indexes for ordinary and tombstone entries would simplify the code. Asks whether removal was chosen only to reduce tombstone storage footprint and suggests making index retention available.
- **2017-08-18 16:02:53 — lkrispen/elkris — [comment](https://github.com/389ds/389-ds-base/issues/2414#issuecomment-691595305):** Does not know the original rationale. Guesses it was partly intended to hide tombstones through scoping and partly to avoid IDs that would later be filtered out. Expects the added index overhead to be limited and says retaining tombstone index values would make explicit tombstone searches correct.
- **2017-08-21 05:05:33 — Firstyear — [comment](https://github.com/389ds/389-ds-base/issues/2414#issuecomment-691595307):** Expands the automatic-filter idea. Normal searches would gain a negative `nsTombstone` clause alongside the existing referral clause. Everything could then be indexed uniformly; tombstone knowledge would stay in the front end, while backends would process all entries alike. He notes this should also prevent tombstones from interfering with internal UID-uniqueness checks. He requests review and improvement of NOT-filter performance before relying more heavily on negative filters.
- **2017-09-07 17:59:21 — mreynolds389 — [comment](https://github.com/389ds/389-ds-base/issues/2414#issuecomment-691595311):** **Metadata-only.** Assigned the issue to the 1.4 backlog milestone.
- **2017-09-28 02:49:19 — Firstyear, in issue #2431 — [cross-referencing comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595686):** Reports that the filter-optimization patch for #2431 passed referral testing and 25 tests after crash fixes. A separate test still failed. Printed filters showed `nsTombstone` and `uid` terms in both orders without apparent corruption; he suggested the remaining failure might instead be #2414.
- **2024-08-21 15:30:01 UTC — vashirov — [comment](https://github.com/389ds/389-ds-base/issues/2414#issuecomment-2302380151):** Closed the issue as WONTFIX. The timeline records the matching close event by vashirov with no closing commit or PR.

## Issue #841 — “idlistscanlimit per index/type/value”

[Issue](https://github.com/389ds/389-ds-base/issues/841) — imported as closed/fixed.

Surface counts:

- 1 issue body.
- 13 issue comments: 10 substantive or implementation-link posts, 3 administrative/metadata posts.
- 0 GitHub timeline cross-references.
- 0 linked, closing, or referencing pull requests.
- Consequently: 0 PR bodies, 0 PR conversation comments, 0 submitted review bodies, and 0 inline review comments.
- Implementation was exchanged as attached patches and committed directly to several branches.

Chronology:

- **2013-09-05 21:02:12 — rmeggins/richm — [issue body](https://github.com/389ds/389-ds-base/issues/841):** Large databases can spend substantial work constructing huge IDLs for broad terms such as `objectClass=inetOrgPerson`, only to intersect them with a tiny `uid` IDL. Proposes a per-index, index-type, and equality-value limit, initially sketched as `nsIndexIDSize`, so selected values can skip IDL generation while other values continue using the global limit. Warns that the setting affects every query containing a configured value, not only a particular AND filter. Explicitly says this should also help legacy ticket 47474, now #811.
- **2013-09-05 21:49:15 — nkinder — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555124):** Endorses the proposed mechanism as flexible and useful in multiple situations.
- **2013-09-05 22:02:58 — nkinder — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555127):** **Administrative.** Notes that the ticket was cloned to Red Hat Bugzilla 1004876.
- **2013-09-17 03:46:41 — nhosoi — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555129):** Asks how the finalized `nsIndexIDListScanLimit` interacts with paged lookthrough, paged IDL-scan, and range-lookthrough limits; whether it supersedes global `nsslapd-idlistscanlimit`; and whether parser pointers should be checked for NULL or a missing `=`, or protected with assertions.
- **2013-09-17 04:11:25 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555132):** Says range and matching-rule support still need special implementation. Otherwise a matching per-index request overrides paged IDL-scan limits and the ordinary global limit; when nothing matches, the existing global or paged setting remains in force. Agrees to add an assertion because the parser pointer should always be initialized at those call sites.
- **2013-09-17 07:11:03 — nhosoi — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555136):** Acknowledges the answers and gives approval.
- **2013-09-23 21:13:46 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555139):** Posts the [final patch attachment](https://fedorapeople.org/groups/389ds/github_attachments/9e0239019a5b8ea270a76a17c3f05d8d1b892d0b5fa144b89c63154d9ff3a5e9-0001-Ticket-47504-idlistscanlimit-per-index-type-value.patch).
- **2013-09-23 21:14:03 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555146):** Posts a [changes-since-prior-patch diff](https://fedorapeople.org/groups/389ds/github_attachments/943ac0092ab9a9e6a192a2b537b82c1262e86e9e8dcf29ebd89d288ce3273c05-newdiffs).
- **2013-09-24 00:21:39 — nkinder — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555147):** Links the “Fine Grained ID List Size” design document.
- **2013-09-24 20:06:43 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555149):** Records the first implementation push to four branches: [1.2.11](https://github.com/389ds/389-ds-base/commit/b5ad052dcccec7318ac4717bbda5d02d6d415c06), [1.3.0](https://github.com/389ds/389-ds-base/commit/3ea8e586c93d2537412c919785b27c27225ffa82), [1.3.1](https://github.com/389ds/389-ds-base/commit/b348886030318cd43855ae439ec3f30f898b8cd4), and [master](https://github.com/389ds/389-ds-base/commit/824b3019beffa5bf2bc5ab2a2a3e579d50833577).
- **2013-09-24 20:13:29 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555152):** **Administrative.** Links Red Hat Bugzilla 1011539 for RHEL 7.
- **2013-09-24 20:22:06 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555153):** Records a second direct push to [1.2.11](https://github.com/389ds/389-ds-base/commit/d83311ad26de153270ef8e7297f7b1790bd58868), [1.3.0](https://github.com/389ds/389-ds-base/commit/527c3e49ed14bc585f29ed873e71c6f551ad193b), [1.3.1](https://github.com/389ds/389-ds-base/commit/e95d7d6bd893d777c88be1bd847996f299621d99), and [master](https://github.com/389ds/389-ds-base/commit/36f506d05fb940e56c42a6b966f11ad1fdf8cba6).
- **2013-09-26 00:17:41 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555156):** Records a third direct push to [1.2.11](https://github.com/389ds/389-ds-base/commit/373e36a6835672746b2e6a97fcb8b6ede2084e32), [1.3.0](https://github.com/389ds/389-ds-base/commit/c96eaa03738e36b7cde0656edfbe6c4769847b52), [1.3.1](https://github.com/389ds/389-ds-base/commit/e5405e627439ccaf370d90c42e65c0a987e33e73), and [master](https://github.com/389ds/389-ds-base/commit/058d01d7479204a2507dab822cd81e32c37be862).
- **2017-02-11 23:05:12 — nkinder — [comment](https://github.com/389ds/389-ds-base/issues/841#issuecomment-691555160):** **Metadata-only.** Assigned the issue to the 1.3.2 September 2013 milestone.
- **2020-09-12 21:45:36 UTC — 389-ds-bot — timeline close event:** GitHub migration close event, with no closing commit or PR. The imported issue states that the original Pagure ticket was closed as fixed.

## Issue #811 — “Ordering of ANDed search terms in filter can negatively impact search etimes”

[Issue](https://github.com/389ds/389-ds-base/issues/811) — imported as closed/fixed.

Surface counts:

- 1 issue body.
- 8 issue comments: 7 substantive, 1 metadata-only.
- 1 attached text file containing 2 dated email threads.
- 1 inbound cross-reference, from issue #2435.
- 0 linked, closing, or referencing pull requests.
- Consequently: 0 PR bodies, 0 PR conversation comments, 0 submitted review bodies, and 0 inline review comments.

Chronology:

- **2013-07-03 — Chris Unger and Rich Megginson — [attached email thread](https://fedorapeople.org/groups/389ds/github_attachments/8c2abb78f449796173066a326295e14ab5b930cbff21f431d971c3ed0fca783a-389bug.txt):** Unger says previously supplied patches did not change the performance problem, although he considers them worth shipping. He reports roughly 0.020-second execution for a vendor-generated AND whose broad object-class OR comes before a selective user-ID equality, versus roughly 0.001 seconds on Sun DS or when the two AND operands are reversed. Megginson says Sun DS performed filter optimization and contrasts Sun's “ALLIDS on write” behavior with 389 DS's “ALLIDS on read.” Sun may discard an oversized index while updating it; 389 retains the index and reads IDs until `nsslapd-idlistscanlimit`, discards the partial list, and repeats that work for each broad filter component. Megginson suggests lowering the scan limit might help this query, but explains that doing so can force other moderately broad indexed searches into full-database entry filtering. Unger says the filter comes from vendor software and cannot easily be changed; the observed difference is approximately 1,000 such searches per second on Sun DS versus 50 on 389 DS.
- **2013-07-11 — Chris Unger and Rich Megginson — [same attachment](https://fedorapeople.org/groups/389ds/github_attachments/8c2abb78f449796173066a326295e14ab5b930cbff21f431d971c3ed0fca783a-389bug.txt):** Unger reports that lowering `idlistscanlimit` helps but remains slower than Sun DS. With about 2.2 million entries, he asks how low the limit can safely be set and whether Sun's suggestion of 10% of total entries has a 389 equivalent. Megginson says there is no known method beyond trial and error, calls the 10% recommendation a rough rule likely to require more tuning, and asks him to file a 389 ticket.
- **2013-08-15 00:57:44 — chrisunger — [issue body](https://github.com/389ds/389-ds-base/issues/811):** Documents a sixfold elapsed-time difference on a database exceeding two million entries: the object-class OR followed by a selective `c3sUserID` term takes about 6 ms, while reversing the two AND terms takes about 1 ms, matching Sun DS regardless of order. Requests order-independent search performance.
- **2013-08-15 01:04:44 — chrisunger — [comment](https://github.com/389ds/389-ds-base/issues/811#issuecomment-691554568):** Attaches the preceding email exchange with Rich Megginson.
- **2013-08-19 12:46:22 — lkrispen/elkris — [comment](https://github.com/389ds/389-ds-base/issues/811#issuecomment-691554570):** Attributes the behavior to old-IDL versus new-IDL processing. New IDL requires more index accesses before deciding a value represents ALLIDS. If the selective component runs first and returns fewer than the filter threshold of ten IDs, candidate generation skips the second component and is faster.
- **2013-08-27 17:06:52 — lkrispen/elkris — [comment](https://github.com/389ds/389-ds-base/issues/811#issuecomment-691554571):** Points to legacy tickets 47326 and 47372 for using and tuning old IDL, noting their fixes were only in the main branch.
- **2013-09-17 02:20:41 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/811#issuecomment-691554572):** Requests `dbscan` IDL sizes for each object-class value and asks whether the deployment also performs searches with single broad object-class terms. Says the per-index/value scan-limit work in legacy ticket 47504, now #841, should help, but wants to distinguish one or more individually huge keys from the combined OR.
- **2013-09-28 00:34:06 — chrisunger — [comment](https://github.com/389ds/389-ds-base/issues/811#issuecomment-691554579):** Supplies counts: `organizationalPerson` 1,636,395; `inetOrgPerson` 928,969; `organization` 1; `organizationalUnit` 138; `groupOfUniqueNames` 86,731; and no keys found for `groupOfNames` or `group`. Says they do not run the example standalone object-class/group search.
- **2013-09-28 00:37:00 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/811#issuecomment-691554585):** Asks whether the reporter can test the patches from legacy ticket 47504/#841.
- **2013-10-10 19:36:38 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/811#issuecomment-691554586):** Requests testing with a new build containing the #841 fix and says he would like to close #811 if possible.
- **2017-02-11 22:49:07 — rmeggins/richm — [comment](https://github.com/389ds/389-ds-base/issues/811#issuecomment-691554588):** **Metadata-only.** Set the issue milestone to N/A.
- **2017-09-12 01:55:51 — Firstyear, in issue #2435 — [cross-referencing comment](https://github.com/389ds/389-ds-base/issues/2435#issuecomment-691595791):** References #811 from the discussion proposing that the default IDL scan limit be raised or removed. The [source issue body](https://github.com/389ds/389-ds-base/issues/2435) describes OR and broad-AND cases where hitting the limit produces ALLIDS and a full `id2entry` scan.
- **2020-09-12 21:41:57 UTC — 389-ds-bot — timeline close event:** GitHub migration close event, with no closing commit or PR. The imported issue states that the original Pagure ticket was closed as fixed.

## Pull-request discovery record

No qualifying pull requests exist for these three issues.

Each GitHub timeline was checked for PR-origin cross-references and PR closers. PR titles, bodies, and comments were also searched using the GitHub issue number, complete issue URL, `Issue NNN`, and legacy Pagure IDs 49355, 47504, and 47474.

Two search-only false positives were excluded:

- PR #6920 matched the token `2414` only because a crash trace mentioned source line `bdb_import.c:2414`; it does not reference issue #2414.
- PR #7449 matched `841` inside an imported external `uuid-rs` changelog entry for that other repository's PR #841; it does not reference 389-ds-base issue #841.
