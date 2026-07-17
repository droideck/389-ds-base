# Filter optimiser discussion collection

Collected from the GitHub issue, pull-request, review, review-comment, and timeline APIs on 2026-07-16. Text below is a terse paraphrase of each post; links point to the original discussion item. Pagure-originated dates are taken from the migrated comment headers.

## Surface inventory

| Item | Body | Top-level comments | Submitted reviews | Inline review comments | Notes |
|---|---:|---:|---:|---:|---|
| [Issue #2431](https://github.com/389ds/389-ds-base/issues/2431) | 1 | 31 | n/a | n/a | Migrated Pagure issue; 8 comments are metadata-only |
| [Legacy PR mirror #3311](https://github.com/389ds/389-ds-base/issues/3311) | 1 | 71 | 0 | 0 | Migrated Pagure PR represented as a GitHub issue |
| [Issue #5170](https://github.com/389ds/389-ds-base/issues/5170) | 1 | 47 | n/a | n/a | Main 2022 implementation discussion |
| [PR #5168](https://github.com/389ds/389-ds-base/pull/5168) | 1 | 5 | 0 | 0 | Superseded by #5171 |
| [PR #5171](https://github.com/389ds/389-ds-base/pull/5171) | 1 | 42 | 11 | 12 | 9 submitted reviews have empty bodies |
| [PR #5285](https://github.com/389ds/389-ds-base/pull/5285) | 1 | 12 | 1 | 0 | One approval review |
| [PR #5301](https://github.com/389ds/389-ds-base/pull/5301) | 1 | 0 | 1 | 0 | Empty top-level discussion surface |
| [PR #5315](https://github.com/389ds/389-ds-base/pull/5315) | 1 | 13 | 8 | 5 | 4 submitted reviews have empty bodies |
| [PR #5316](https://github.com/389ds/389-ds-base/pull/5316) | 1 | 2 | 0 | 0 | Closed without merge; empty review surfaces |
| [PR #5604](https://github.com/389ds/389-ds-base/pull/5604) | 1 | 10 | 9 | 10 | All 9 submitted review bodies are empty; inline comments carry the discussion |

The complete post-by-post PR chronologies are split into supplemental PR collection files prepared alongside this issue/legacy-PR collection.

## Issue #2431 — optimise filters for common query types

### Body

- **Firstyear — 2017-09-05 07:10:08:** Proposes moving predictably expensive AND components, especially broad `objectClass` and NOT terms, behind selective equality terms so the filter-test threshold can avoid loading large indexes. Gives `(&(objectClass=person)(uid=william))` and `(&(!(objectClass=nsTombstone))(uid=william))` as examples. [Issue body](https://github.com/389ds/389-ds-base/issues/2431)

### Comments, chronological

1. **mreynolds389 — 2017-09-07 17:52:02:** Metadata-only: cleared several custom fields and placed the issue in the 1.4 backlog milestone. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595670)
2. **Firstyear — 2017-09-08 07:32:49:** Attached the first patch; moved nested-filter folding into `filter_optimise` and delayed optimisation until the last practical point so IDL/IDL-set processing sees the improved order. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595671)
3. **Firstyear — 2017-09-08 08:15:04:** Posted timings showing order dependence before the patch and near-equivalent timings after it; reported additional gains for multi-`objectClass` filters and gains beyond merely lowering `idlistscanlimit`. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595673)
4. **ilstam — 2017-09-08 11:44:25:** Suggested replacing numeric LDAP filter-choice values and explanatory comments in the Python diagnostic code with constants or enums. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595676)
5. **Firstyear — 2017-09-11 03:41:14:** Adopted an `IntEnum` and uploaded a revised patch. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595679)
6. **mreynolds389 — 2017-09-11 18:55:26:** Reported regressions in tests 48252 and 48265, with 48265 hanging the server at 100% CPU, and requested a full suite run before another revision. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595680)
7. **Firstyear — 2017-09-12 02:06:21:** Said 48265 appeared to trigger a heap use-after-free and would be investigated. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595682)
8. **elkris — 2017-09-12 10:10:31:** Supported the optimisation in principle but requested referral database coverage both with and without ManageDsaIT because referral handling also changed. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595683)
9. **Firstyear — 2017-09-28 00:00:44:** Metadata-only: assigned the issue to Firstyear. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595684)
10. **Firstyear — 2017-09-28 02:49:19:** Uploaded a crash-fix revision, reported 25 relevant tests passing, said referral testing already passed, asked how to test ManageDsaIT, and suspected the remaining 48252 failure was related to #2414 rather than malformed filters. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595686)
11. **mreynolds389 — 2017-09-28 04:20:26:** Said 48252 had recently been fixed on master and requested rebasing plus rerunning the updated CI suite. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595689)
12. **Firstyear — 2017-09-28 04:55:07:** Said the branch might not have been rebased and would be checked. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595692)
13. **Firstyear — 2017-09-28 05:32:51:** Confirmed rebased master passed while the patch failed and suspected a lost object-class-related flag. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595693)
14. **Firstyear — 2017-09-29 03:24:39:** Compared working and failing tombstone filter orders; concluded that putting `uid` first yielded an empty IDL and an early threshold return, and proposed suppressing optimisation when the tombstone flag is present. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595694)
15. **Firstyear — 2017-09-29 03:59:09:** Uploaded a patch that skips optimisation for tombstone-flagged filters and reported 48252 passing. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595696)
16. **Firstyear — 2017-10-03 04:59:40:** Linked lib389 issue 102, which added smart-referral objects and a ManageDsaIT test, and said that test passed with this patch. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595697)
17. **mreynolds389 — 2017-10-04 15:31:40:** Metadata-only: marked review status acknowledged. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595699)
18. **Firstyear — 2017-10-05 01:09:09:** Reported commit `4cd1a24b3` pushed to master and thanked reviewers. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595700)
19. **Firstyear — 2017-10-05 01:09:09:** Metadata-only: closed the issue as fixed. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595703)
20. **mreynolds389 — 2018-07-05 21:32:23:** Said the change also appeared to fix one-level search issues in 1.3.7/1.3.8. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595709)
21. **mreynolds389 — 2018-07-05 21:32:24:** Metadata-only: added Bugzilla 1598186 and moved the milestone to 1.3.7.0. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595712)
22. **mreynolds389 — 2018-07-05 22:02:08:** Listed the 1.3.7 and 1.3.8 backport commits. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595713)
23. **mreynolds389 — 2018-08-24 22:19:11:** Said the fix was breaking many things and blocking Fedora 27, so it needed to be reverted from every branch pending further work. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595715)
24. **mreynolds389 — 2018-08-24 22:19:12:** Metadata-only: reopened the issue. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595718)
25. **mreynolds389 — 2018-08-24 22:43:35:** Listed master, 1.3.8, and 1.3.7 revert commits for both this optimisation and the related filter-optimise crash fix. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595721)
26. **elkris — 2018-08-29 09:33:22:** Said the backout also resolved Bugzilla 1616412/48275 and made the uncommitted 49617 patch unnecessary; both would need attention before reintroduction. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595722)
27. **mreynolds389 — 2019-04-17 22:25:25:** Linked Bugzilla 1616412 as the regression originally caused by the enhancement. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595724)
28. **Firstyear — 2019-04-18 02:14:41:** Said a debugging PR existed; suspected one-level reordering, and warned that the old report lacked enough logging to reconstruct the cause easily. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595727)
29. **mreynolds389 — 2019-08-23 20:05:28:** Metadata-only: moved the milestone to 1.4.2. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595728)
30. **vashirov — 2020-03-11 15:39:02:** Metadata-only: moved the milestone back to the 1.4 backlog. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-691595729)
31. **vashirov — 2024-08-21 15:58:40:** Closed the issue as completed by #5170. [Comment](https://github.com/389ds/389-ds-base/issues/2431#issuecomment-2302439121)

### Cross-reference events

- **2020-09-13:** Migrated issues [#2624](https://github.com/389ds/389-ds-base/issues/2624), [#2435](https://github.com/389ds/389-ds-base/issues/2435), and legacy PR mirror [#3311](https://github.com/389ds/389-ds-base/issues/3311) were recorded as cross-references.
- **2024-08-21:** #5170 cross-referenced and superseded this issue when it was closed.

## Legacy Pagure PR mirror #3311 — Ticket 49372 filter optimisation improvements

### Body

- **Firstyear — 2019-03-01 04:21:36:** Describes the IDL rules being exploited: an unindexed OR member makes the union ALLIDS, while a small AND member permits an early partial return and later filter test. Proposes moving substring members first in ORs and non-`objectClass` equalities first in ANDs; names SSSD sudo filters and broad `objectClass` indexes as motivating cases; resolves #2431 and #3132. [Body](https://github.com/389ds/389-ds-base/issues/3311)

### Comments, chronological

1. **Firstyear — 2019-03-01 04:23:13:** Said the patch also repaired filter tests that failed with optimisation disabled and now passed them in both modes, likely relying on the one-level scope fix. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615463)
2. **Firstyear — 2019-03-05 04:13:45:** Requested mreynolds389's review. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615465)
3. **Firstyear — 2019-03-12 03:23:45:** Sent a review reminder. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615466)
4. **mreynolds389 — 2019-03-13 19:45:58:** Said FreeIPA needed to test because it found the original regression. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615467)
5. **mreynolds389 — 2019-03-13 21:49:24:** Reported that the patch broke FreeIPA installation and said successful/failing logs were being gathered. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615468)
6. **Firstyear — 2019-03-13 23:50:01:** Expressed surprise because the optimiser itself was disabled. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615470)
7. **Firstyear — 2019-03-14 00:29:19:** Said IPA cleanup obscured the useful logs and returned to code inspection. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615471)
8. **Firstyear — 2019-03-14 01:38:19:** Rebase-only update onto `9983d7806`. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615473)
9. **Firstyear — 2019-03-14 01:40:57:** Added RESULT logging for the executed/optimised filter and requested access plus IPA-install logs; noted that referral and one-level filter construction changed even with optimisation disabled. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615475)
10. **mreynolds389 — 2019-03-14 04:10:12:** Said repeated patched/unpatched tests confirmed the patch caused the failure despite the feature being disabled. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615479)
11. **Firstyear — 2019-03-14 04:14:29:** Reiterated that referral and one-level construction remained likely causes and that new logs should distinguish them. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615480)
12. **Firstyear — 2019-04-02 02:01:32:** Asked whether the IPA build had been checked and offered to refresh it. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615484)
13. **Firstyear — 2019-04-17 02:41:37:** Asked again for IPA results and noted the intended benefit to SSSD-generated queries. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615486)
14. **Firstyear — 2019-04-17 02:50:01:** Rebase-only update onto `2b4e0029f`. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615489)
15. **mreynolds389 — 2019-04-17 17:10:53:** Said a new build for IPA retesting was still needed. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615490)
16. **Firstyear — 2019-04-18 03:11:54:** Ran the Bugzilla's working and failing cert-map filters through one-level and subtree transforms; found only expected AND folding and no visible transform that explained missing results. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615493)
17. **mreynolds389 — 2019-04-18 15:30:49:** Suspected ACI filter processing rather than candidate generation; said IPA passed with the feature off and would be retried with it on. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615495)
18. **mreynolds389 — 2019-04-18 20:57:26:** Reported IPA still failed when optimisation was enabled and offered logs or another debug build. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615496)
19. **Firstyear — 2019-04-19 01:34:01:** Requested access and IPA-install logs; said the on/off distinction narrowed the fault and provided a compile-time fallback. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615499)
20. **mreynolds389 — 2019-04-19 02:40:21:** Confirmed uncommenting the optimiser define reproduced the original failure and asked whether the error log was also needed. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615504)
21. **Firstyear — 2019-04-29 00:57:59:** Confirmed receipt of the diagnostic material and planned investigation. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615508)
22. **Firstyear — 2019-04-29 04:23:01:** Linked a 389-devel investigation write-up. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615509)
23. **Firstyear — 2019-04-30 03:58:55:** Rebase-only update onto `e2048f237`. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615511)
24. **Firstyear — 2019-04-30 04:03:17:** Hardened the subtree filter-bypass flag and `LOG_FILTER` output, kept optimisation disabled, proposed landing the non-optimiser cleanup, and requested exact QE queries with filter logging. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615513)
25. **Firstyear — 2019-04-30 04:57:44:** Automated update: added a `DEBUG BUILD` commit. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615516)
26. **tbordaz — 2019-04-30 09:48:32:** Summarised the possible 10× gain versus review/test complexity and listed known regressions 48252, 48265, 1616412, 48275, and 49617 that must be covered. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615518)
27. **Firstyear — 2019-04-30 11:27:51:** Said reports lacked the failing query; described a debug IPA install initially failing because logging slowdown caused a duplicate Kerberos add, then solved logging throughput with a RAM disk. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615520)
28. **Firstyear — 2019-05-01 00:48:56:** Reported a successful debug IPA install and asked who in QE had the reproducible failure. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615521)
29. **Firstyear — 2019-05-02 03:52:08:** Automated update: added a `More debugging` commit. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615523)
30. **Firstyear — 2019-05-02 04:09:11:** Automated update: added another `More debugging` commit. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615524)
31. **Firstyear — 2019-05-02 04:28:32:** Automated update: added another `More debugging` commit. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615525)
32. **Firstyear — 2019-05-02 05:25:33:** Automated update: added another `More debugging` commit. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615527)
33. **tbordaz — 2019-05-02 09:54:12:** Suggested waiting for mreynolds389's failure confirmation and asked whether every known regression case had been verified. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615529)
34. **Firstyear — 2019-05-02 11:21:00:** Reported obtaining QE reproduction cases and a likely breakthrough. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615531)
35. **Firstyear — 2019-05-02 12:16:04:** Automated update: added another `More debugging` commit. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615532)
36. **Firstyear — 2019-05-02 13:28:07:** Tentatively attributed the cert-map failure to missing read access for `altSecurityIdentities`; asked why disabled optimisation did not fail and proposed disabling filter-test bypass for comparison. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615533)
37. **Firstyear — 2019-05-03 03:38:09:** Posted the full single-threaded trace: candidate generation and transformed filter were logical, but filter testing failed with insufficient access to `altSecurityIdentities` for the machine account. Listed follow-ups for schema/index/ACI issues, filter correctness, logging performance/structure, and a runtime optimiser switch. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615535)
38. **Firstyear — 2019-05-03 03:59:27:** Linked the newly opened filter-schema, structured-logging, logging-performance, filter-bypass, and FreeIPA schema/index/ACI issues; promised a cleaned patch and runtime switch. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615536)
39. **abbra — 2019-05-03 08:37:00:** Explained that SSSD applies shared certificate-map rules to IPA and AD sources, so unknown AD attributes cannot simply be removed; cited RFC 4511/X.511 requirements that unknown filter assertions evaluate undefined rather than cause errors. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615539)
40. **Firstyear — 2019-05-03 10:33:25:** Argued unknown attributes create unindexable denial-of-service and operational risks; proposed either defining/indexing them or not sending them, with a compatibility switch if standards behavior must remain available. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615542)
41. **abbra — 2019-05-03 11:03:47:** Accepted that input could be ignored but opposed returning an RFC-prohibited error; said FreeIPA cannot control arbitrary user cert-map rules and SSSD/domain routing might be the right layer. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615548)
42. **abbra — 2019-05-03 11:10:09:** Asked sbose whether SSSD could separate cert-map filters by source domain to avoid AD-only attributes in IPA searches. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615550)
43. **sbose — 2019-05-03 11:25:23:** Said `altSecurityIdentities` comes from mapping rules, not SSSD defaults; rules can be scoped per domain with `ipa certmap-add/mod --domain`, while unscoped rules apply to IPA. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615552)
44. **tbordaz — 2019-05-03 11:57:14:** Said clients may legally use unknown/unindexed attributes, questioned matching-rule selection, agreed missing ACI should be fixed, and asked whether the failure existed without this patch. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615553)
45. **abbra — 2019-05-03 12:16:53:** Updated FreeIPA PR 3110 to add `altSecurityIdentities` schema and authenticated read access, index it and `ipaCertMapData`, and restrict AD-only mapping rules to trusted AD domains. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615556)
46. **Firstyear — 2019-05-07 02:01:40:** Said the FreeIPA changes should resolve many observed issues. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615561)
47. **Firstyear — 2019-05-07 02:05:03:** Proposed either rejecting unknown attributes or marking them invalid with IDL(0), behind a compatibility flag; said the observed test also failed without optimisation and proposed initially defaulting the optimiser off. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615563)
48. **Firstyear — 2019-05-07 06:38:19:** Rebase-only update onto `2fae03ab1`. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615564)
49. **Firstyear — 2019-05-07 06:39:40:** Removed debug clutter, added a `cn=config` switch defaulting off, and deferred default-on behavior until FreeIPA changes landed and were tested. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615567)
50. **elkris — 2019-05-08 16:50:00:** Planned to review the following week. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615568)
51. **Firstyear — 2019-05-14 04:45:34:** Rebase-only update onto `99778336b`. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615569)
52. **Firstyear — 2019-05-21 06:35:14:** Said filter-schema validation PR #3438 should wait because both touched filter verification and stacking them increased risk. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615570)
53. **elkris — 2019-05-22 12:21:54:** Reported 48275 and 49617 tests still failing, required them to be preserved, and requested evidence that the complex patch's optimisation benefit justified its side effects. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615571)
54. **Firstyear — 2019-05-23 04:07:12:** Agreed to integrate and investigate those tests and rerun performance measurements. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615573)
55. **Firstyear — 2019-05-23 05:32:55:** Initially read 49617 as changed default data/ACIs and 48275 as denied `mail` access, finding no transform corruption; planned to include both tests. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615576)
56. **Firstyear — 2019-05-23 05:48:25:** Acknowledged that test changes had lost their intent; traced one-level failure to access testing of injected `parentid` and suggested granting/exempting that internal attribute. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615580)
57. **elkris — 2019-05-23 09:07:58:** Corrected the diagnosis: clients should not need access to injected `parentid`; candidate execution should use the transformed filter while ACI testing uses the original filter. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615581)
58. **tbordaz — 2019-05-23 09:15:05:** Recalled a prior FreeIPA workaround for injected `parentid` and asked whether the omission was in this patch or the default deployment. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615583)
59. **elkris — 2019-05-23 09:19:04:** Said this was not an ACI-definition change but OR handling for unknown/denied attributes; recounted the choice between checking every OR attribute and ignoring inaccessible components, with existing customer-compatible behavior requiring the latter. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615585)
60. **elkris — 2019-05-23 09:21:31:** Clarified that FreeIPA's temporary workaround was never committed after the optimiser backout. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615591)
61. **elkris — 2019-05-23 09:39:37:** Pointed to a 49617 patch but had not verified it against the new proposal. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615592)
62. **Firstyear — 2019-05-24 01:45:40:** Explained that returning the transformed filter in the pblock exposed injected `parentid`/referral terms to ACI checks; listed cloning, exemptions, or a separate executed-filter pblock slot as possible designs. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615593)
63. **Firstyear — 2019-05-27 05:15:39:** Preferred storing both intended and executed filters, logging both, and using only the intended filter for ACI evaluation. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615594)
64. **elkris — 2019-05-28 08:55:05:** Agreed to retaining both filters for different purposes. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615596)
65. **Firstyear — 2019-05-28 09:06:48:** Confirmed that design and promised implementation plus load-test results. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615598)
66. **elkris — 2019-05-29 14:30:30:** Required 48275 behavior: for `(|(uid=allowed)(employeeNumber=denied))`, entries matching the accessible branch must still be returned, equivalent to separate searches. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615601)
67. **Firstyear — 2019-06-11 17:03:39:** Rebase-only update onto `0355f62a9`. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615604)
68. **Firstyear — 2019-06-11 17:07:37:** Added 48275, 49617, and the mixed allowed/denied OR case; reported passing behavior and explicit frees for new pblock values, with cleanup and load tests remaining. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615606)
69. **Firstyear — 2019-06-19 09:47:03:** Noted that VLV still needed testing. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615608)
70. **Firstyear — 2019-06-19 15:35:37:** Reported a new VLV memory leak and began fixing it. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615609)
71. **389-ds-bot — migrated attachment:** Attached the final `50252.patch`; no additional prose. [Comment](https://github.com/389ds/389-ds-base/issues/3311#issuecomment-691615611)

### Formal-review and inline-review surfaces

- This Pagure PR was migrated as a GitHub issue, so it has **0 submitted GitHub reviews** and **0 inline GitHub review comments**. Review discussion is contained in the 71 comments above.

### Cross-reference events

- Migrated timeline references point to [#3132](https://github.com/389ds/389-ds-base/issues/3132), [#3339](https://github.com/389ds/389-ds-base/issues/3339), [#3438](https://github.com/389ds/389-ds-base/issues/3438), and [#3782](https://github.com/389ds/389-ds-base/issues/3782).

## Issue #5170 — Filter optimiser

### Body

- **Firstyear — 2022-02-22 03:43:31:** States that the backend evaluates filter terms in supplied order, producing surprising performance, and proposes a real query optimiser instead of relying on IDL scan limits. [Issue body](https://github.com/389ds/389-ds-base/issues/5170)

### Comments, chronological

1. **mreynolds389 — 2022-02-23 17:53:40:** Linked implementation PR #5171. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1049051498)
2. **mreynolds389 — 2022-05-05 01:50:37:** Asked for a cherry-pick to 2.0. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1118090531)
3. **Firstyear — 2022-05-05 01:54:04:** Agreed to cherry-pick. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1118091996)
4. **Firstyear — 2022-05-05 01:58:21:** Reported pushes to the 2.1 and 2.0 branches. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1118093694)
5. **Firstyear — 2022-05-05 02:00:04:** Requested independent testing because the 2.x cherry-pick required a careful `ldbm_search.c` conflict resolution. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1118094278)
6. **mreynolds389 — 2022-05-05 13:53:30:** Reported a CI-detected regression: `complex_filters_test.py` now returned an `ldapsubentry` that should have been excluded. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1118583350)
7. **Firstyear — 2022-05-06 00:48:07:** Recalled a conflict around subentry code and deferred investigation because of a security incident. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1119168422)
8. **mreynolds389 — 2022-05-06 02:24:25:** Clarified the failure was on master and unrelated to backport conflicts; requested investigation the following week. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1119204241)
9. **Firstyear — 2022-05-06 02:25:29:** Agreed to investigate. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1119204645)
10. **mreynolds389 — 2022-05-17 19:57:40:** While investigating #5289, found that a filter attribute absent from schema led to an empty candidate set after optimiser changes; a local hack bypassing the invalid-attribute branch restored results and suggested another IPA regression might remain. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1129262265)
11. **Firstyear — 2022-05-17 23:40:38:** Suspected OR-condition handling or a partial-candidate shortcut and offered to investigate. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1129421741)
12. **Firstyear — 2022-05-18 03:10:57:** Linked the corresponding #5289 investigation comment. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1129520499)
13. **mreynolds389 — 2022-05-18 03:51:35:** Reopened the issue, saying an `idnsServerId` equality search worked before optimiser commits regardless of schema presence; distinguished this simple reproducer from the unresolved IPA behavior. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1129537153)
14. **Firstyear — 2022-05-18 03:53:09:** Said unknown-attribute rejection predated optimisation under schema-filter protection and suggested configuring warn/disabled verification. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1129537673)
15. **Firstyear — 2022-05-18 03:55:59:** Requested `LOG_FILTER` output using logging PR #5301. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1129538763)
16. **mreynolds389 — 2022-05-18 04:02:14:** Reiterated that reverting optimiser commits restored behavior, so the difference appeared new. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1129541300)
17. **Firstyear — 2022-05-18 04:03:26:** Requested enhanced logs or a standalone reproducer that did not invoke schema checking. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1129541884)
18. **mreynolds389 — 2022-05-19 11:38:58:** Supplied a two-entry standalone reproducer and argued the symptom was partial empty results rather than schema check error 53. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1131580531)
19. **mreynolds389 — 2022-05-19 16:39:43:** Withdrew that reproducer after repeated builds showed identical pre/post behavior, but kept the issue open for the remaining IPA regression. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1131943981)
20. **Firstyear — 2022-05-19 23:20:34:** Suggested using new logging and checking whether candidate sets were above or below the threshold of 10. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1132292176)
21. **mreynolds389 — 2022-05-23 19:33:04:** Narrowed the IPA issue to access control rather than filter processing and began isolating the relevant ACI. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1135062486)
22. **mreynolds389 — 2022-05-23 21:36:21:** Observed that new code checked access to each filter attribute, including `idnsServerId`, while old code oddly appeared to check only `nsUniqueId`. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1135159611)
23. **Firstyear — 2022-05-23 23:16:03:** Attributed `nsUniqueId` to preexisting tombstone exclusion, recalled fixing shortcut ACI enforcement and query corruption/order cases, and described the query code as difficult and inconsistent. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1135226209)
24. **mreynolds389 — 2022-05-24 13:47:26:** Objected that a known access-control behavior change should not have merged mid-release; then reported an apparently unrelated upper-tree ACI overriding the expected DNS-subtree ACI and began checking ACI selection itself. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1135946451)
25. **mreynolds389 — 2022-05-24 15:45:05:** Found a typo in the intended IPA ACI: old incomplete filter checks had accidentally let another ACI grant access. Fixing the typo restored new-code behavior, but compatibility concerns suggested a possible switch. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1136095335)
26. **mreynolds389 — 2022-05-24 22:39:47:** Said IPA would fix its ACI, migration tests might still expose compatibility trouble, and the issue could close unless an optional mode proved necessary. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1136496258)
27. **Firstyear — 2022-05-25 00:20:02:** Reframed the behavior as a high-severity access-control-bypass fix and said disabling only reordering would not undo the query-engine correction to shortcut ACI enforcement. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1136555383)
28. **Firstyear — 2022-05-25 00:22:27:** Said an optimiser compatibility switch would not restore prior behavior because the relevant correction was query evaluation; reverting it would retain a security exposure. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1136556653)
29. **Firstyear — 2022-05-25 00:38:19:** Decided to report the suspected ACI bypass to SUSE product security for CVE handling. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1136564758)
30. **mreynolds389 — 2022-05-25 17:50:22:** Reopened again with a regression test showing OR evaluation continued into inaccessible branches after an already-matching branch; said the test passed before optimiser commits and failed afterward. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1137637897)
31. **mreynolds389 — 2022-05-25 17:51:53:** Posted the full lib389 test source, covering accessible OR branches and inaccessible attributes across good and bad compound filters. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1137639963)
32. **progier389 — 2022-05-26 13:54:00:** Separated compatibility impact from OR ACI semantics; compared global rejection with ignoring inaccessible branches, noted logical consistency versus intuitive behavior, and preferred preserving established behavior. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1138604306)
33. **Firstyear — 2022-05-26 23:21:07:** Catalogued two query-corruption cases, a potential ACI bypass, and a bug in access-only OR checking; argued these existed in IDL/filter-test paths beyond reordering and made both fixing and reverting risky. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1139138104)
34. **mreynolds389 — 2022-05-27 13:41:38:** Produced an old-code ACI-bypass case that occurred only when a candidate list stayed below the shortcut threshold; separated over-restrictive new OR behavior from the security-critical shortcut bypass. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1139631318)
35. **Firstyear — 2022-05-30 01:28:48:** Agreed the bypass might permit bytewise extraction of secrets; said `vattr_test_filter_list_or` could fix disruption, but the optimiser and scan-limit strategy fundamentally relied on shortcut behavior. Proposed retain-and-fix, revert-and-disable-shortcut, or split master/maintenance approaches. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1140585504)
36. **Firstyear — 2022-05-30 02:27:50:** Considered removing filter-test bypass entirely because access-only evaluation was too complex and unreliable; proposed demonstration PRs with and without the optimiser. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1140618464)
37. **Firstyear — 2022-05-30 02:33:34:** Realised removing bypass also conflicted with injected `parentid` in base searches, so the OR access-only implementation still had to be fixed. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1140621269)
38. **Firstyear — 2022-05-30 02:55:19:** Presented two alternatives: #5315 retaining the optimiser with OR fix, and #5316 reverting it while fixing the threshold/security path. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1140630971)
39. **Firstyear — 2022-05-30 02:58:53:** Requested the bypass reproducer as a permanent lib389 test. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1140632431)
40. **tbordaz — 2022-05-30 13:10:08:** Agreed an inaccessible OR component should not reject the entire filter and thought the older intuitive behavior should be restored without a compatibility toggle. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1141140952)
41. **Firstyear — 2022-05-30 23:30:04:** Said #5315 already fixed that behavior and clarified that both alternatives fix preexisting OR/security problems; preferred #5315 because #5316 could reduce performance. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1141538174)
42. **Firstyear — 2022-05-31 02:16:45:** Summarised three cases: over-restrictive OR behavior, high-severity disclosure via OR shortcut, and referral visibility under ACIs; recorded whether each predated optimisation and which PR addressed it. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1141599211)
43. **Firstyear — 2022-05-31 04:28:54:** Announced CVE-2022-1949, CVSS 7.4, and said optimiser-free code streams needed the #5316-style fix. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1141655807)
44. **mreynolds389 — 2022-05-31 16:23:36:** Could no longer reproduce the bypass with old or new builds despite having reproduced it earlier, and questioned the CVE state. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1142347629)
45. **Firstyear — 2022-06-01 03:01:18:** Maintained that prior FreeIPA behavior and the earlier reproducer were strong evidence; suggested indexes or threshold conditions explained intermittent reproduction. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1143065870)
46. **mreynolds389 — 2022-06-01 12:40:03:** Corrected the FreeIPA account: one ACI legitimately allowed access while another was wrongly overriding it under the new OR behavior, so IPA itself did not prove the bypass. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1143558425)
47. **mreynolds389 — 2022-06-01 13:08:07:** Reaffirmed that a separate non-IPA test had reproduced a real bypass and continued trying to make it reliable. [Comment](https://github.com/389ds/389-ds-base/issues/5170#issuecomment-1143590029)

### Direct PR and cross-reference events

- **2022-02-23:** The issue discussion linked implementation [PR #5171](https://github.com/389ds/389-ds-base/pull/5171), which superseded [PR #5168](https://github.com/389ds/389-ds-base/pull/5168).
- **2022-05-09:** [PR #5285](https://github.com/389ds/389-ds-base/pull/5285) cross-referenced the issue for the `ldapsubentry` regression.
- **2022-05-18:** [PR #5301](https://github.com/389ds/389-ds-base/pull/5301) cross-referenced it for filter logging.
- **2022-05-30:** The issue and PR timelines cross-linked mutually exclusive alternatives [#5315](https://github.com/389ds/389-ds-base/pull/5315) and [#5316](https://github.com/389ds/389-ds-base/pull/5316).
- **2023-01-13:** [PR #5604](https://github.com/389ds/389-ds-base/pull/5604) directly referenced #5170 while addressing the referral-filter throughput cost.
- Additional issue cross-references in the timeline are [#3132](https://github.com/389ds/389-ds-base/issues/3132), [#5598](https://github.com/389ds/389-ds-base/issues/5598), [#5700](https://github.com/389ds/389-ds-base/issues/5700), [#2431](https://github.com/389ds/389-ds-base/issues/2431), and [#6307](https://github.com/389ds/389-ds-base/issues/6307).
