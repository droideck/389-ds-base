# Filter-optimizer follow-up pull-request discussions

Collection only; no evaluation. All timestamps are UTC. This records every currently visible human-authored PR body, top-level comment, submitted review envelope, and inline review comment for PRs #5285, #5301, #5315, #5316, and #5604 as of 2026-07-16. All retrieved authors have GitHub user type “User”; there were no bot-authored discussion posts in these five PRs.

## PR #5285

[“Issue 5170 - BUG - ldapsubentries were incorrectly returned”](https://github.com/389ds/389-ds-base/pull/5285), authored by Firstyear, created 2022-05-09 04:12:42, merged 2022-05-14 01:24:36.

Counts:

- 1 PR body.
- 12 top-level comments.
- 1 submitted review.
- 0 inline review threads and 0 inline comments.
- 0 empty discussion bodies.

Chronology:

- **2022-05-09 04:12:42 — Firstyear, [PR body](https://github.com/389ds/389-ds-base/pull/5285).** Says the filter-optimizer logic change caused LDBM searches to return LDAP subentries accidentally. The proposed correction cleans up the logic and comments in ldbm_search.c so those subentries are not returned. Declares that it fixes issue #5170.
- **2022-05-09 04:13:07 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1120620625).** Says tests/suites/filter/complex_filters_test.py passes.
- **2022-05-09 12:29:28 — mreynolds389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1121036848).** Reports that the subentries test is now failing.
- **2022-05-10 00:56:28 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1121741439).** Says they cannot reproduce the failure and that all tests, including subentries, pass locally.
- **2022-05-10 12:23:44 — progier389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1122320750).** Suggests rerunning the PR tests and checking whether the subentries failure persists.
- **2022-05-10 18:05:42 — mreynolds389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1122709074).** Says the subentries test fails locally with the patch just as it does in GitHub CI. Provides a run showing one failure and four passes: the inetorgperson case expected five results but received zero.
- **2022-05-13 03:59:29 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1125633279).** Realizes the report concerns the standalone subentries suite rather than the subentries test inside the complex-filter suite, reproduces that failure, and says they will investigate.
- **2022-05-13 05:53:57 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1125681872).** Reports that the failure is fixed.
- **2022-05-13 13:22:48 — mreynolds389, [approved review](https://github.com/389ds/389-ds-base/pull/5285#pullrequestreview-972250318).** Metadata-only approval body: “LGTM.”
- **2022-05-14 01:24:36 — Firstyear, [merge](https://github.com/389ds/389-ds-base/pull/5285).** Merges the PR.
- **2022-05-14 01:24:50 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1126603738).** Asks whether the other branches to which #5170 was applied need to be checked.
- **2022-05-14 16:48:06 — mreynolds389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1126773996).** Says this correction must be cherry-picked to the 2.1 and 2.0 branches.
- **2022-05-16 00:57:00 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1127108338).** Says they are ill and asks mreynolds389 to perform the backport.
- **2022-05-16 12:16:42 — mreynolds389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1127598557).** Agrees to do it, then reports that regressions still remain, says a test case is being developed, and points to issue #5289 for a possible later investigation.
- **2022-05-17 00:08:28 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5285#issuecomment-1128256281).** Says they will try to investigate when feeling better.

## PR #5301

[“Issue 5170 - RFE - improve filter logging to assist debugging”](https://github.com/389ds/389-ds-base/pull/5301), authored by Firstyear, created 2022-05-18 03:11:03, merged 2022-05-18 23:54:38.

Counts:

- 1 PR body.
- 0 top-level comments.
- 1 submitted review.
- 0 inline review threads and 0 inline comments.
- 0 empty discussion bodies.

Chronology:

- **2022-05-18 03:11:03 — Firstyear, [PR body](https://github.com/389ds/389-ds-base/pull/5301).** Says filter logging should be improved to help diagnose issue #5170 and future filter reports. The fix is described simply as improving the logging and declares that it fixes #5170.
- **2022-05-18 12:00:29 — progier389, [approved review](https://github.com/389ds/389-ds-base/pull/5301#pullrequestreview-976829303).** Metadata-only approval body: “LGTM.”
- **2022-05-18 23:54:38 — Firstyear, [merge](https://github.com/389ds/389-ds-base/pull/5301).** Merges the PR.

Empty surfaces: the top-level-comment surface and inline-review surface contain no posts; there are no empty review envelopes.

## PR #5315

[“Issue 5170 - BUG - incorrect behaviour of filter test”](https://github.com/389ds/389-ds-base/pull/5315), authored by Firstyear, created 2022-05-30 02:47:46, merged 2022-06-03 00:05:56.

Counts:

- 1 PR body.
- 13 top-level comments.
- 8 submitted reviews.
- 3 inline review threads containing 5 inline comments.
- 5 submitted review bodies were empty:
  - [mreynolds389 review 990380542](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-990380542).
  - [mreynolds389 review 991980124](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-991980124).
  - [Firstyear review 992777329](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-992777329).
  - [Firstyear review 992813252](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-992813252).
  - [mreynolds389 review 994183340](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-994183340).
- Inline thread states: all 3 are resolved; 2 are outdated and 1 is current.
- No empty PR body, top-level comments, or inline comments.

Chronology:

- **2022-05-30 02:47:46 — Firstyear, [PR body](https://github.com/389ds/389-ds-base/pull/5315).** Says OR branches were evaluated incorrectly during the filter test’s access-only mode: access was checked, but the code did not confirm that the accessed branch was the one the entry actually matched, so queries could incorrectly remove entries. Proposes removing the access-only special case and running the complete OR evaluation so matching and access correspond. Declares that it fixes #5170.
- **2022-05-30 02:54:19 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1140630547).** States that this PR conflicts with #5316 and only one can be merged.
- **2022-05-30 03:10:58 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1140638650).** Says the filter-suite tests all pass locally and tags mreynolds389.
- **2022-05-31 12:44:06 — mreynolds389, [inline comment](https://github.com/389ds/389-ds-base/pull/5315#discussion_r885591273), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-990380542) at 12:44:07.** Requests an indentation correction in ldbm_search.c. The thread is resolved and outdated.
- **2022-05-31 13:06:54 — mreynolds389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1142112834).** Supplies a revised regression/CVE test. It grants anonymous read/search/compare access only to objectClass and postalCode, creates container, allowed, and restricted organizational units, then exercises nine allowed compound filters with expected result counts and six prohibited filters expected to return zero. Requests updating the committed test case, says the remainder looks good, and indicates approval.
- **2022-05-31 13:07:32 — mreynolds389, [dismissed review](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-990416005).** Says there are a few minor comments but gives an acknowledgment. GitHub records the review state as dismissed.
- **2022-05-31 18:47:02 — mreynolds389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1142524546).** Reports nine filter-suite regressions: four non-root-user cases, one large manager-filter case, and four virtual-filter cases. The failures involve nested AND/OR/NOT filters, substrings, approximate matches, location/mail/role attributes, and a large manager OR.
- **2022-06-01 00:00:13 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1142792517).** Says discovering why those cases fail will likely show that tests depended on prior buggy behavior.
- **2022-06-01 02:54:56 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1143062869).** Says the access-only filter-test logic is fundamentally broken because it separates access checks from the attributes that actually matched. Proposes always performing the filter test when ACL checks are performed.
- **2022-06-01 02:59:28 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1143064839).** Explains that many test attributes are unindexed, forcing ALLIDS and the access-only path. Says indexed versions would also fail because bypassing the filter test selects the same broken access-only route. Restates that matching and access must always be checked together and says the PR will be updated after testing.
- **2022-06-01 03:03:45 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1143067050).** Notes that this was the only code path using access-check-only mode; all other paths either perform full access checks or none.
- **2022-06-01 03:08:56 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1143069546).** Posts a non-root test result after fixing the ACL-only path: 134 passed with 136 warnings in about 11 minutes 15 seconds.
- **2022-06-01 13:32:53 — mreynolds389, [inline comment](https://github.com/389ds/389-ds-base/pull/5315#discussion_r886812408), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-991980124) at 13:32:54.** Asks why a value in slapi-plugin.h was changed to 22.
- **2022-06-01 13:35:41 — mreynolds389, [changes-requested review](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-991984749).** Requests fixing indentation, updating the CI test case, and enriching new and existing filter-log lines with information such as the entry DN to assist debugging.
- **2022-06-01 23:16:59 — Firstyear, [inline reply](https://github.com/389ds/389-ds-base/pull/5315#discussion_r887372942), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-992777329).** Says the value was hard-coded during debugging because setting the log level through the ns-slapd command-line -d option did not work locally, requiring filter logging to be routed to the error log.
- **2022-06-01 23:17:07 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1144236537).** Says the requested changes will be made that day.
- **2022-06-02 00:33:46 — Firstyear, [inline reply](https://github.com/389ds/389-ds-base/pull/5315#discussion_r887402175), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-992813252).** Says the “22” issue is resolved. The three-comment thread is resolved and outdated.
- **2022-06-02 01:49:11 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1144332313).** Says the changes are done but asks what specifically was wanted for the test case.
- **2022-06-02 20:56:10 — mreynolds389, [inline comment](https://github.com/389ds/389-ds-base/pull/5315#discussion_r888406468), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-994183340).** Requests adding the entry DN to a filterentry.c log message. The thread is resolved and current.
- **2022-06-02 21:10:31 — mreynolds389, [approved review](https://github.com/389ds/389-ds-base/pull/5315#pullrequestreview-994197216).** Says the change looks good apart from improving the logging and reports that it passed IPA tests.
- **2022-06-02 23:39:35 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1145439881).** Responds with relief and says the logging will be improved before merging.
- **2022-06-03 00:05:56 — Firstyear, [merge](https://github.com/389ds/389-ds-base/pull/5315).** Merges the PR.
- **2022-06-03 00:07:57 — Firstyear, [top-level metadata comment](https://github.com/389ds/389-ds-base/pull/5315#issuecomment-1145460178).** Records the backport commit ranges for the 389-ds-base-2.1 and 389-ds-base-2.0 branches.

## PR #5316

[“5170 revert fix CVE in access”](https://github.com/389ds/389-ds-base/pull/5316), authored by Firstyear, created 2022-05-30 02:53:39, closed without merge 2022-06-03 00:04:47.

Counts:

- 1 PR body.
- 2 top-level comments.
- 0 submitted reviews.
- 0 inline review threads and 0 inline comments.
- 0 empty discussion bodies.

Chronology:

- **2022-05-30 02:53:39 — Firstyear, [PR body](https://github.com/389ds/389-ds-base/pull/5316).** Says a shortcut query could bypass access controls by returning a result set prematurely and then failing to enforce access correctly on entries, potentially exposing passwords. Proposes setting the filter-test threshold to zero and correcting the attribute-filter access check so matching attributes are enforced. Declares that it fixes #5170.
- **2022-05-30 02:54:06 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5316#issuecomment-1140630451).** States that this PR conflicts with #5315 and only one can be merged.
- **2022-05-30 05:52:18 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5316#issuecomment-1140727033).** Says they strongly prefer not to merge this PR and instead want it used as a template for backports that resolve the ACI bypass.
- **2022-06-03 00:04:47 — Firstyear, [closure](https://github.com/389ds/389-ds-base/pull/5316).** Closes the PR without merging it.

Empty surfaces: the submitted-review and inline-review surfaces contain no posts; there are no empty comment bodies.

## PR #5604

[“Issue 5598 - In 2.x, SRCH throughput drops by 10% because of handling… of referral”](https://github.com/389ds/389-ds-base/pull/5604), authored by tbordaz, created 2023-01-13 12:36:23, merged 2023-02-22 14:06:53.

Counts:

- 1 PR body.
- 10 top-level comments.
- 9 submitted reviews.
- 3 inline review threads containing 10 inline comments.
- All 9 submitted review bodies were empty:
  - [mreynolds389 review 1247642709](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1247642709), COMMENTED.
  - [tbordaz review 1247653503](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1247653503), COMMENTED.
  - [tbordaz review 1248206273](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1248206273), COMMENTED.
  - [Firstyear review 1249400504](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1249400504), CHANGES_REQUESTED.
  - [progier389 review 1250417153](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1250417153), COMMENTED.
  - [tbordaz review 1253225417](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1253225417), COMMENTED.
  - [progier389 review 1253627491](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1253627491), COMMENTED.
  - [tbordaz review 1261855937](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1261855937), COMMENTED.
  - [Firstyear review 1300654137](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1300654137), APPROVED.
- Inline thread states: all 3 are unresolved and outdated.
- No empty PR body, top-level comments, or inline comments.

Chronology:

- **2023-01-13 12:36:23 — tbordaz, [PR body](https://github.com/389ds/389-ds-base/pull/5604).** Says part of #5170 appends an objectClass=referral OR branch to direct subtree-search filters for RFC 3296 smart-referral behavior, reducing search throughput by about 10%. Says that most servers have no smart referrals and internal searches should not get the extra branch. Proposes a periodic 30-second referral check, logging transitions between referrals present/absent, and appending the branch to direct subtree searches only while a referral exists. Relates the change to issue #5598.
- **2023-01-13 13:32:39 — mreynolds389, [inline comment](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1069461101), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1247642709) at 13:32:40.** Asks whether the shared referral-existence flag needs a lock and recalls that it may need to be a static uint64_t for safety.
- **2023-01-13 13:40:28 — tbordaz, [inline reply](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1069472150), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1247653503).** Says a lock is unnecessary because the update is periodic and temporarily stale reads are acceptable. Agrees the size/cache-line point merits testing and says cache-line alignment will be benchmarked.
- **2023-01-13 13:59:50 — progier389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1381899622), edited 2023-01-16 15:29:03.** Initially asks why only internal-search behavior is optimized and suspects a result-rate regression. The edit says the test was misread: the referral branch is not added to internal operations, which is appropriate because most plugins do not handle referrals and can add the branch themselves when needed.
- **2023-01-13 14:01:55 — progier389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1381903537).** Proposes one referral-presence flag per backend so a referral in one backend does not affect searches in every backend.
- **2023-01-13 15:30:20 — mreynolds389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1382020673).** Reports that several tests are crashing the server and says it is not yet clear whether the PR is responsible.
- **2023-01-13 17:35:35 — progier389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1382176739).** Addresses nested suffixes: suggests that search processing read only the current backend flag, while the periodic task should propagate a true flag to parent suffixes when a nested backend contains a referral.
- **2023-01-13 18:13:38 — tbordaz, [inline reply](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1069805610), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1248206273).** Reports no performance benefit from changing the flag to uint64_t and aligning it to a cache line.
- **2023-01-16 00:36:23 — Firstyear, [inline comment](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1070725375).** Says the current conditional-check logic can leave the flag permanently true after a referral is added and later removed, because the check will no longer run.
- **2023-01-16 00:37:15 — Firstyear, [inline reply](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1070725532).** Says a lock is probably unnecessary but recommends an atomic RELEASE store and ACQUIRE load for the shared flag.
- **2023-01-16 00:38:01 — Firstyear, [inline comment](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1070725674).** Suggests checking once every 60 seconds or five minutes rather than every 30 seconds.
- **2023-01-16 00:38:08 — Firstyear, [empty changes-requested review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1249400504).** Contains the preceding three inline comments and no overall review text.
- **2023-01-16 16:14:53 — progier389, [inline reply](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1071406647), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1250417153).** Says a lock or atomic is the standard cross-thread approach but agrees it is excessive here because timing is unimportant and checks may be minutes apart.
- **2023-01-18 10:36:53 — tbordaz, [inline reply](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1073366186), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1253225417) at 10:36:54.** Explains that the patch currently uses a server-wide flag and stops scanning backends once any referral is found. Says it will be reworked to use per-backend flags as progier389 suggested.
- **2023-01-18 14:46:45 — progier389, [inline reply](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1073632443), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1253627491).** Says the logic is acceptable but the similar local and global variable names, exist_referral and exist_referrals, are confusing and should be made more distinct.
- **2023-01-19 14:01:47 — tbordaz, [inline reply](https://github.com/389ds/389-ds-base/pull/5604#discussion_r1081303865), with [empty submitted review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1261855937) at 14:01:48.** Agrees the naming was confusing and says the patch now uses per-suffix flags with no global exist_referrals variable. Notes that backend-flag access remains unprotected but says a missed update will be repeated a few seconds later.
- **2023-02-03 12:49:39 — tbordaz, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1415828497).** Says referral_check has been changed to operate per backend: a backend containing a smart referral sets its own flag, and subtree searches consult it through slapi_exist_referrals. Asks Firstyear whether this addresses the requested changes.
- **2023-02-03 14:39:47 — progier389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1415961293).** Suggests moving the backend referral search into a separate function and invoking it immediately after enabling a backend so behavior after imports is predictable.
- **2023-02-16 00:39:44 — mreynolds389, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1432292667).** Tells Firstyear that Thierry made the requested changes and asks for a review.
- **2023-02-16 02:19:50 — Firstyear, [empty approved review envelope](https://github.com/389ds/389-ds-base/pull/5604#pullrequestreview-1300654137).** GitHub records approval with no overall review body and no attached inline comment.
- **2023-02-16 02:20:02 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1432377953).** Apologizes for the review delay.
- **2023-02-21 13:49:24 — tbordaz, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1438528171), edited 13:58:50.** Asks whether slapi_exist_referrals(be) is the separate function requested by progier389. The same comment body then distinguishes that flag-reading function from the requested function that should perform the internal search, set the flag, and run when the backend is enabled.
- **2023-02-22 14:05:00 — tbordaz, [top-level comment](https://github.com/389ds/389-ds-base/pull/5604#issuecomment-1440070091).** Says slapi_exist_referral now performs the internal search and flag handling.
- **2023-02-22 14:06:53 — tbordaz, [merge](https://github.com/389ds/389-ds-base/pull/5604).** Merges the PR.

Inline thread inventory:

1. backend.c original line 307: lock, atomic, integer-size/cache-line, and staleness discussion; 5 comments; unresolved and outdated.
2. backend.c original line 232: referral-removal behavior, server-wide versus per-backend/per-suffix flags, and naming discussion; 4 comments; unresolved and outdated.
3. backend.c original line 295: periodic-check interval; 1 comment; unresolved and outdated.
