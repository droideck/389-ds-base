# Modern IDL/filter discussion collection

Collection only; no evaluation. All timestamps are UTC. Data is from the currently visible GitHub REST and GraphQL discussion surfaces as of 2026-07-16.

## Direct-link inventory

GitHub issue timelines plus repository pull-request search found:

- [Issue #6275](https://github.com/389ds/389-ds-base/issues/6275): 0 directly linked, closing, or referencing pull requests.
- [Issue #6966](https://github.com/389ds/389-ds-base/issues/6966): 3 directly connected pull requests:
  - [PR #6967](https://github.com/389ds/389-ds-base/pull/6967) — its body says “fixes: #6966”; merging it closed the issue.
  - [PR #7026](https://github.com/389ds/389-ds-base/pull/7026) — a top-level discussion comment attributes a healthcheck regression to #6966 and generated the cross-reference.
  - [PR #7036](https://github.com/389ds/389-ds-base/pull/7036) — its body explicitly says the #6966 fix caused the healthcheck regression.
- One directly cross-referencing non-PR issue was also present: [Issue #6975](https://github.com/389ds/389-ds-base/issues/6975).
- [PR #7030](https://github.com/389ds/389-ds-base/pull/7030), [issue #7032](https://github.com/389ds/389-ds-base/issues/7032), and [issue #6846](https://github.com/389ds/389-ds-base/issues/6846) appear inside the connected PR discussions, but are not pull requests directly referencing #6275 or #6966.

## Issue #6275

[“Search request executes slowly, if filter contains many values (more than 100 in ‘or’ list)”](https://github.com/389ds/389-ds-base/issues/6275), open, milestone 3.3.

Counts: 1 issue body, 3 issue comments, 0 direct PR cross-references. No empty bodies or comments.

Chronology:

- **2024-07-25 11:15:28 — OGSmv, [issue body](https://github.com/389ds/389-ds-base/issues/6275).** Reports that one search containing 1,000 UID alternatives is slower than two searches containing 500 alternatives each followed by client-side concatenation. Environment is Debian Buster with 389 DS 2.4 and 3.0. Reproduction creates about 100,000 accounts, searches for 1,000 of them, then compares split requests. Includes two timing screenshots and a linked Python reproducer gist.
- **2024-07-25 13:09:08 — progier389, [comment](https://github.com/389ds/389-ds-base/issues/6275#issuecomment-2250284727).** Attributes the result to candidate-list merging for OR, including duplicate suppression. Describes 1,000 singleton candidate lists with distinct values as a worst case, estimates array-based behavior around quadratic complexity, says improving this was not expected to be prioritized, and recommends applications use a reasonable number of OR subfilters.
- **2024-07-25 16:51:43 — OGSmv, [comment](https://github.com/389ds/389-ds-base/issues/6275#issuecomment-2250972186).** Asks whether the expected application pattern is therefore multiple simple requests rather than one request for 1,000 or more unique entries.
- **2024-07-25 23:53:13 — Firstyear, [comment](https://github.com/389ds/389-ds-base/issues/6275#issuecomment-2251588628).** Points to back-ldbm.h, filterindex.c, and idl_set.c. Describes the IDL-set union process as repeatedly finding the next minimum and pruning exhausted IDLs; many small, unique IDLs can therefore produce quadratic work. Notes it is still better than the older repeated incremental-union implementation and says the existing OR optimization targeted SSSD queries with a few large OR branches. Proposes allocating an array sized to the total ID count, appending every ID unsorted, sorting once with qsort, then copying unique IDs into a correctly sized final sorted IDList.

## Issue #6966

[“On large DB, unlimited IDL scan limit reduce the SRCH performance”](https://github.com/389ds/389-ds-base/issues/6966), closed, milestone 3.2.

Counts: 1 issue body, 4 issue comments, 3 PR cross-references, 1 issue cross-reference. No empty bodies or comments.

Chronology:

- **2025-09-03 10:14:51 — tbordaz, [issue body](https://github.com/389ds/389-ds-base/issues/6966).** Says #2435 removed the IDList-size limit, allowing subtree and one-level system-index IDLs to approach database size. On a five-million-entry database, building that IDL consumed more than 90% of search elapsed time even when other filter components were indexed. The reproduction imports five million entries, equality-indexes an attribute, marks 50 entries with a specific value, enables index statistics, and repeatedly runs subtree searches returning those 50 entries.
- **2025-09-03 12:07:36 — progier389, [comment](https://github.com/389ds/389-ds-base/issues/6966#issuecomment-3248976806).** Frames candidate generation as a tradeoff between constructing/intersecting another IDL and retaining final filter checks. Notes the historical stop threshold is 10 candidates. Proposes stopping AND evaluation when a later subfilter’s candidate list grows by 10, 100, or 1,000 times relative to the first sorted subfilter. Also proposes an equality-specific intersection method that walks IDs from the existing IDL and probes whether each key/ID pair exists in the index, avoiding construction of a large second IDL. Says these approaches would retain the ability to return large result sets, unlike a global ID scan limit.
- **2025-09-03 12:24:08 — tbordaz, [PR #6967 cross-reference](https://github.com/389ds/389-ds-base/pull/6967).** Opens the fixing PR, initially applying a 5,000-ID fine-grained limit to parentid and ancestorid.
- **2025-09-05 09:16:33 — tbordaz, [issue #6975 cross-reference](https://github.com/389ds/389-ds-base/issues/6975).** Opens a follow-up noting that idl_new_fetch constructs the full duplicate-key IDL before checking allidscanlimit; proposes comparing the running count to the limit and stopping earlier. It uses the #6966 reproducer. That issue has 0 comments.
- **2025-10-03 13:11:13 — [PR #6967 merged](https://github.com/389ds/389-ds-base/pull/6967).** The merge closes #6966.
- **2025-10-03 15:12:37 — tbordaz, [comment](https://github.com/389ds/389-ds-base/issues/6966#issuecomment-3366125326).** Records backports wherever #2435 existed: main, 3.0, 2.7, 2.6, 2.5, 2.4, 2.3, 2.2, 2.1, 2.0, and 1.4.3, with the old/new commit ranges for each branch.
- **2025-10-06 16:42:35 — tbordaz, [PR #7026 cross-reference comment](https://github.com/389ds/389-ds-base/pull/7026#issuecomment-3372762258).** States that a newly observed healthcheck regression tracked as #7032 is related to #6966 and says they will work on it.
- **2025-10-08 13:19:45 — tbordaz, [PR #7036 cross-reference](https://github.com/389ds/389-ds-base/pull/7036).** Opens the healthcheck correction, explicitly identifying the #6966 change as its cause.
- **2025-10-08 13:21:37 — tbordaz, [comment](https://github.com/389ds/389-ds-base/issues/6966#issuecomment-3381529728).** Records that the #6966 fix contained a bug addressed by #7032.
- **2025-11-26 09:40:11 — tbordaz, [comment](https://github.com/389ds/389-ds-base/issues/6966#issuecomment-3580461191).** Records a correction to an invalid 1.4.3 backport, giving the replacement commit range.

## PR #6967

[“Issue 6966 - On large DB, unlimited IDL scan limit reduce the SRCH pe…”](https://github.com/389ds/389-ds-base/pull/6967), authored by tbordaz, merged 2025-10-03.

Counts:

- 1 PR body.
- 5 top-level comments.
- 7 submitted reviews.
- 3 inline review threads containing 5 comments.
- 2 submitted review bodies were empty:
  - [tbordaz review 3180753621](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3180753621).
  - [tbordaz review 3180762625](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3180762625).
- Inline thread states: 2 resolved, 1 unresolved; 2 outdated, 1 current.
- No empty top-level or inline-comment bodies.

Chronology:

- **2025-09-03 12:24:08 — tbordaz, [PR body](https://github.com/389ds/389-ds-base/pull/6967).** Repeats the five-million-entry performance problem and says large IDLs account for more than 90% of operation time. Proposes fine-grained limits on parentid for one-level searches and ancestorid for subtree searches, initially using “limit=5000 type=eq flags=AND.” Reports roughly 50-times throughput/response-time improvement. The current body’s generated summary also records making the scan limit configurable, emitting it through DSE configuration, and treating ancestorid reads as AND.
- **2025-09-03 12:24:18 — sourcery-ai, [top-level reviewer guide](https://github.com/389ds/389-ds-base/pull/6967#issuecomment-3249029707).** Enumerates changes to index-config initialization, default limits for both system indexes, DSE serialization of nsIndexIDListScanLimit, and forced AND semantics for ancestorid. Also repeats that the PR addresses #6966 and includes bot-use/help boilerplate.
- **2025-09-03 12:25:23 — sourcery-ai, [submitted review](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3180393497).** Gives a positive overall message but includes two requested discussion points: explain why the ancestorid entry is added in two places, and validate or sanitize nsIndexIDListScanLimit values before serializing them.
  - **Same time — [inline thread 1](https://github.com/389ds/389-ds-base/pull/6967#discussion_r2318806670).** Asks for an explanation of the apparently duplicated ancestorid index-entry addition.
  - **Same time — [inline thread 2](https://github.com/389ds/389-ds-base/pull/6967#discussion_r2318806674).** Suggests validating scan-limit values before appending them to generated configuration and supplies an integer-validation sketch.
- **2025-09-03 13:46:05 — tbordaz, [empty review envelope](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3180753621), [inline reply](https://github.com/389ds/389-ds-base/pull/6967#discussion_r2319037874).** Explains that configuration starts in dse.ldif and is loaded into memory; ancestorid had existed only in memory. The change also creates its config-file entry to match parentid, which exists in both places. Thread is resolved and outdated.
- **2025-09-03 13:48:21 — tbordaz, [empty review envelope](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3180762625), [inline reply](https://github.com/389ds/389-ds-base/pull/6967#discussion_r2319044474).** Says additional serialization-time validation is unnecessary because the fix writes a valid value and startup validates it when loading. Thread is resolved and current.
- **2025-09-05 09:30:33 — tbordaz, [top-level comment](https://github.com/389ds/389-ds-base/pull/6967#issuecomment-3257702738).** Says there is no CI performance test because creating and exercising a huge database would be slow and fragile. Provides the manual procedure: generate/import five million entries, equality-index an attribute, update 50 entries, enable index stats, load-test subtree retrieval of those entries, and observe that ancestorid lookup accounts for nearly all elapsed time.
- **2025-09-08 23:19:07 — mreynolds389, [approved review](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3198460677).** Metadata-only approval body: “LGTM.”
- **2025-09-09 00:21:47 — droideck, [inline comment](https://github.com/389ds/389-ds-base/pull/6967#discussion_r2331665247).** Asks whether the numeric limit should be a named constant for future changes. Thread remains unresolved and is outdated.
- **2025-09-09 00:29:40 — droideck, [approved review](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3198588559).** Approves, references the minor issue, and asks whether changing nsslapd-idlistscanlimit now requires a restart.
- **2025-09-09 11:00:33 — progier389, [top-level comment](https://github.com/389ds/389-ds-base/pull/6967#issuecomment-3270162163).** Asks whether a simpler implementation would be to make idl_new_get_allidslimit return the minimum of the existing threshold and 5,000 for parentid and ancestorid.
- **2025-09-09 11:05:35 — progier389, [changes-requested review](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3200945324).** Says a hard-coded 5,000 limit could turn a legitimate search over 5,001 children into a fully unindexed search that might be rejected, without a customer remedy. Requests making the limit configurable.
- **2025-09-09 22:25:21 — Firstyear, [top-level comment](https://github.com/389ds/389-ds-base/pull/6967#issuecomment-3272469167).** Expresses concern that a hard-coded special-case fix may defer a new problem to the future.
- **2025-09-16 16:43:32 — tbordaz, [top-level comment](https://github.com/389ds/389-ds-base/pull/6967#issuecomment-3299564095).** Says the implementation has been changed to make the setting tunable.
- **2025-09-25 12:02:31 — progier389, [approved review](https://github.com/389ds/389-ds-base/pull/6967#pullrequestreview-3267320898).** Metadata-only approval body: “LGTM.”
- **2025-10-03 13:11:13 — tbordaz, [merge](https://github.com/389ds/389-ds-base/pull/6967).** Merges the PR and closes #6966.

## PR #7026

[“Issue 6846 - Attribute uniqueness is not enforced with modrdn”](https://github.com/389ds/389-ds-base/pull/7026), authored by jchapma, merged 2025-10-14. Its direct connection to #6966 is the healthcheck-regression discussion.

Counts:

- 1 PR body.
- 4 top-level comments.
- 4 submitted reviews.
- 1 inline review thread containing 3 comments.
- 2 submitted review bodies were empty:
  - [progier389 review 3299228707](https://github.com/389ds/389-ds-base/pull/7026#pullrequestreview-3299228707).
  - [jchapma review 3304127735](https://github.com/389ds/389-ds-base/pull/7026#pullrequestreview-3304127735).
- Inline thread state: resolved and outdated.
- No empty top-level or inline-comment bodies.

Chronology:

- **2025-09-30 18:56:31 — jchapma, [PR body](https://github.com/389ds/389-ds-base/pull/7026).** Describes a MODRDN attribute-uniqueness bug: with no new superior, destinationSDN is an empty SDN, breaking marker and subtree searches. The fix falls back to the source entry’s parent and enables the previously expected-failure tests. It closes #6846.
- **2025-09-30 18:57:17 — sourcery-ai, [submitted review](https://github.com/389ds/389-ds-base/pull/7026#pullrequestreview-3286319406).** Gives a positive overall message but flags a possible memory leak when an already allocated destinationSDN is replaced.
  - **Same time — [inline thread](https://github.com/389ds/389-ds-base/pull/7026#discussion_r2392547611).** Requests freeing or reusing the existing destination object. The bot later edited this comment on 2025-10-06 to say commit 7e505592 addressed it by allocating only when NULL and reusing the existing pointer otherwise.
- **2025-10-03 14:16:01 — progier389, [empty review envelope](https://github.com/389ds/389-ds-base/pull/7026#pullrequestreview-3299228707), [inline reply](https://github.com/389ds/389-ds-base/pull/7026#discussion_r2402104462).** Agrees with the bot and sketches separating allocation from the NULL-DN fallback: allocate only when the pointer is NULL, then populate the parent when its DN is NULL.
- **2025-10-06 11:47:27 — jchapma, [empty review envelope](https://github.com/389ds/389-ds-base/pull/7026#pullrequestreview-3304127735), [inline reply](https://github.com/389ds/389-ds-base/pull/7026#discussion_r2405897194).** Acknowledges the mistake and says the PR feedback had not been checked.
- **2025-10-06 14:26:24 — jchapma, [top-level comment](https://github.com/389ds/389-ds-base/pull/7026#issuecomment-3371969610).** Says the newly failing tests need investigation and did not appear to fail before the last commit.
- **2025-10-06 15:33:34 — progier389, [top-level comment](https://github.com/389ds/389-ds-base/pull/7026#issuecomment-3372333786).** Says the import/plugin failures are unrelated and also occur in #7030, which merely adds a test. Mentions a likely recent healthcheck regression because FreeIPA tests are also failing, while recommending confirmation.
- **2025-10-06 15:34:18 — progier389, [approved review](https://github.com/389ds/389-ds-base/pull/7026#pullrequestreview-3305521658).** Metadata-only approval body: “LGTM.”
- **2025-10-06 16:42:35 — tbordaz, [top-level comment and #6966 cross-reference](https://github.com/389ds/389-ds-base/pull/7026#issuecomment-3372762258).** States that the recent healthcheck regression, tracked as #7032, is related to #6966 and says they will work on it.
- **2025-10-06 22:31:13 — jchapma, [top-level comment](https://github.com/389ds/389-ds-base/pull/7026#issuecomment-3374484205).** Clarifies that they were investigating four failing attruniq_test.py cases: MODRDN uniqueness, multiple-attribute uniqueness, add-across-subtrees, and multiple-container MODRDN.
- **2025-10-14 19:35:01 — jchapma, [merge](https://github.com/389ds/389-ds-base/pull/7026).** Merges the PR.

## PR #7036

[“Issue 7032 - The new ipahealthcheck test ipahealthcheck.ds.backends.B…”](https://github.com/389ds/389-ds-base/pull/7036), authored by tbordaz, merged 2025-10-20.

Counts:

- 1 PR body.
- 1 top-level comment.
- 3 submitted reviews.
- 1 inline review thread containing 1 comment.
- 0 empty discussion bodies.
- Inline thread state: unresolved and current.

Chronology:

- **2025-10-08 13:19:45 — tbordaz, [PR body](https://github.com/389ds/389-ds-base/pull/7036).** Says the #6966 fix added a scanlimit to the parentid system index, meaning not every expected index dictionary contains that key. The healthcheck assumed the key always existed and raised a critical result. The correction retrieves parentid with the dictionary’s safe access routine; Florence Renaud is credited for debugging and fixing it. Closes #7032.
- **2025-10-08 13:20:29 — sourcery-ai, [submitted review](https://github.com/389ds/389-ds-base/pull/7036#pullrequestreview-3314793543).** Metadata-only positive review saying the change looks good, followed by the bot’s standard sharing/help boilerplate; no inline findings are included.
- **2025-10-13 14:41:07 — progier389, [approved review](https://github.com/389ds/389-ds-base/pull/7036#pullrequestreview-3331912255).** Metadata-only approval body: “LGTM.”
- **2025-10-15 02:48:09 — droideck, [inline comment](https://github.com/389ds/389-ds-base/pull/7036#discussion_r2430969326).** Notes an adjacent message-format issue outside this PR’s scope: the “missing fine grain definition of IDs limit” message prints expected_mr, and asks whether it should print expected_scanlimit. The thread has no reply and remains unresolved/current.
- **2025-10-15 02:48:20 — droideck, [approved review](https://github.com/389ds/389-ds-base/pull/7036#pullrequestreview-3338164273).** Metadata-only approval body: “LGTM.”
- **2025-10-20 12:30:52 — tbordaz, [merge](https://github.com/389ds/389-ds-base/pull/7036).** Merges the fix.
- **2025-10-20 12:45:49 — tbordaz, [top-level comment](https://github.com/389ds/389-ds-base/pull/7036#issuecomment-3421914189).** Records backports to main, 3.0, 2.7, 2.6, 2.5, 2.4, 2.3, 2.2, 2.1, 2.0, and 1.4.3, with a commit range for each branch.
