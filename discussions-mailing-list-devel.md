# 389-devel source reader: candidate generation

## Scope

This is a message-level reader for the mailing-list material most directly connected to candidate-list construction, IDL limits, filter ordering, and the final filter-test correctness boundary. It contains 13 individual messages selected from the complete 389-devel mbox export covering 2005-06-01 through 2026-07-14.

Each Message link opens the exact archived email. Each Thread link opens its full HyperKitty conversation. Third-party emails are not reproduced verbatim; the detailed paraphrases preserve the substantive content contributed by each selected message. Quoted history carried inside replies is represented by the earlier entries instead of being repeated. Where a review email consists mainly of issue and patch links, the paraphrase identifies that fact and summarizes the material the email linked for review. No reproducer containers were run.

## Source messages

### 1. Noriko Hosoi — 2010-09-24 11:56 -0700

**Subject:** Please review (revised): [Bug 635987] Incorrect sub scope search result with ACL containing ldap:///self

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/K3V4YI7YAUGPIA4JPT5LGWWICFUKUNI2/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/K3V4YI7YAUGPIA4JPT5LGWWICFUKUNI2/)

**Paraphrase:** This revision reports that the first fix for bug 635987 introduced a replication failure in subtree_candidates. During a tombstone-filter search, the descendants IDL is NULL; intersecting the existing candidates with that NULL descendants list removes all candidates and leaves only the base entry ID. The revised patch makes the intersection conditional: it is skipped for a tombstone filter and when entryrdn_get_noancestorid is active, while the normal subtree intersection remains in place for other searches. The message links the bug and revised patch.

### 2. Noriko Hosoi — 2012-12-13 17:42 -0800

**Subject:** Please review: [389 Project] #497: Escaped character cannot be used in the substring search filter

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/H5KNUDKMYJFY2HHMQR7AHLGMYTXEFHPG/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/H5KNUDKMYJFY2HHMQR7AHLGMYTXEFHPG/)

**Paraphrase:** The message attributes the substring-search regression to the earlier ticket 328 commit. That commit needed an escaped string representation of a filter for logging, but it also replaced the live filter used for evaluation with the escaped form. As a result, escaped characters could not be used correctly in a substring assertion. The linked patch reverses the escaping only for the real filter, leaving the logging representation separate. The message supplies the ticket, patch, and introducing commit links.

### 3. Noriko Hosoi — 2013-09-06 16:31 -0700

**Subject:** Re: [389-devel] RFC: New Design: Fine Grained ID List Size

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/YFABINP5222AWZVHPUB7IK25EL5N7QF3/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/L6CT7ZFSEFZ2HKAVCRNG7ALTLYE6WT6T/)

**Paraphrase:** Hosoi asks for an additional flag in the proposed per-index/type/value scan-limit syntax so a limit can depend on the filter's boolean context. Her concrete case applies the special limit to a broad objectClass equality only when it is a component of an AND, while leaving a standalone objectClass search unchanged. She explains that this distinction can matter in a database containing millions of inetOrgPerson entries alongside millions of other object classes, but may not help when nearly every entry is inetOrgPerson. She proposes an AND-only flag as the initial use case while leaving room for other flags.

### 4. David Boreham — 2013-09-06 18:30 -0600

**Subject:** Re: [389-devel] RFC: New Design: Fine Grained ID List Size

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/3OCXVXWRKDXWKRPUVIBQO5L6FCZFADAH/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/L6CT7ZFSEFZ2HKAVCRNG7ALTLYE6WT6T/)

**Paraphrase:** Boreham relates the proposal to SQL index statistics and server-side index hints. He recalls candidate processing that can avoid a later index lookup after an earlier AND component has already produced a very small IDL, provided the components arrive in a useful order. In his uid-equality plus objectClass example, putting the selective uid component first can eliminate the broad objectClass lookup, but clients may be unable to control their filter layout. He therefore describes a server planner that reads the proposed index hints before performing lookups, orders the predicates itself, and avoids the unnecessary broad lookup. In this model the administrator records that an index has low cardinality rather than supplying per-query client knowledge. He also describes a utility that could populate the hint data by inspecting index contents, analogous to updating database statistics.

### 5. Nathan Kinder — 2013-09-06 19:49 -0700

**Subject:** Re: [389-devel] RFC: New Design: Fine Grained ID List Size

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/ZOGA7NWPCDJ37Z5THZTPW6OY5YJASYWZ/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/L6CT7ZFSEFZ2HKAVCRNG7ALTLYE6WT6T/)

**Paraphrase:** Kinder says the server-side planner had also been discussed off list and explains the implementation cost the group had associated with it: maintaining an ID count for every key would change the index format, and existing indexes would need a conversion or population pass. He separates that from the immediate goal, which is to improve particular unmodifiable client filters without changing the on-disk index format. He also records the broader form of the idea: per-key counts could later let the server choose automatically and reduce the amount of detailed index configuration required from administrators.

### 6. David Boreham — 2013-09-06

**Subject:** Re: [389-devel] RFC: New Design: Fine Grained ID List Size

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/NEKI6PWMQ5RA3ROQZ2CP7UHXS4A7QUCX/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/L6CT7ZFSEFZ2HKAVCRNG7ALTLYE6WT6T/)

**Paraphrase:** Boreham clarifies that his planner proposal does not require keeping a cardinality count for every index key or changing the index format. He proposes using the same coarse information already contemplated by the fine-grained scan-limit design: metadata associated with an index that tells the planner a lookup is unlikely to be selective. The distinction is where that information is consumed—before candidate generation, to decide which AND component to read first or avoid—rather than during a lookup after IDs have already been read. He characterizes per-key counts as substantially more state than the proposal needs and leaves their additional value unresolved.

### 7. Ludwig Krispenz — 2013-09-09 10:27 +0200

**Subject:** Re: [389-devel] RFC: New Design: Fine Grained ID List Size

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/2CEKG6U7E6SP325IKUOSDNNDLQYW2X3J/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/L6CT7ZFSEFZ2HKAVCRNG7ALTLYE6WT6T/)

**Paraphrase:** Krispenz notes that the old IDL implementation exposes key cardinality and that this makes some searches with ALLIDS filter components fast; he presents the fine-grained configuration as a way to address corresponding ALLIDS behavior in the new IDL implementation. He describes the filter ordering then present in the server as based mainly on index type, with expensive range-style components such as less-than-or-equal deferred. The proposed configuration could later supply more detailed information for ordering. He also gives a separate caching model for ticket 47474: cache the expensive, repeated OR of broad objectClass terms and reuse it across searches where only the selective c3sUserID equality changes.

### 8. Rich Megginson — 2013-09-13 14:18 -0600

**Subject:** Re: [389-devel] RFC: New Design: Fine Grained ID List Size

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/UQM2L77KAENK76DQOY5RS7DNXJDNGWTB/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/IYZ3VXU4LMJDDSE7DHWC76U6XQ3U7DFC/)

**Paraphrase:** Megginson reports an inspection of Berkeley DB 4.7 to determine whether duplicate cardinality can be obtained cheaply. He maps the B-tree cursor count method to the Berkeley DB implementation and reads it as iterating the duplicate pages to count their records rather than returning a counter maintained on updates. On that reading, asking for a count would itself traverse the large duplicate set the planner was trying to avoid. He also says he did not find code that made this cursor-count behavior depend on creating the database with DB_RECNUM and asks whether that interpretation is missing another mechanism.

### 9. Howard Chu — 2013-09-14 11:44 -0700

**Subject:** Re: [389-devel] RFC: New Design: Fine Grained ID List Size

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/TH6HNINMB7XNGKIPOJ3J27TBNEVUZ5IX/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/TH6HNINMB7XNGKIPOJ3J27TBNEVUZ5IX/)

**Paraphrase:** Chu revises his earlier recollection of Berkeley DB and contrasts it with LMDB. He states that LMDB updates record counts during every write, so reading a count does not require scanning the records. In LMDB's copy-on-write structure, modifying a leaf already requires rewriting the path through the root; maintaining the counts along that path therefore does not add another page-update path. He notes that OpenLDAP was not then using those available counts to order filter evaluation.

### 10. William Brown — 2017-06-28 15:02 +1000

**Subject:** Please review: 49290 - improve idl behaviours

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/FSOQ6JAGK77PJLLH2B5UEY7ZIQ4OXXL5/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/FSOQ6JAGK77PJLLH2B5UEY7ZIQ4OXXL5/)

**Paraphrase:** The email is a review request containing the Pagure ticket and two patch links. One linked patch adds the unindexed-operation note for an unindexed range search. The other addresses complex filters by replacing repeated pairwise set operations with an idl_set that first retains every child candidate list and then performs a k-way intersection or union. The linked description explains that pairwise AND processing repeatedly allocated and copied large intermediate lists until a later selective term reduced them, making elapsed time sensitive to component order. Pairwise OR processing repeatedly merged a growing sorted list, so each additional term increased the repeated merge work; the motivating ticket included several hundred OR terms. Collecting the child lists before combining them removes those intermediate pairwise allocations and leaves all component lists available together for later NOT/OR processing work.

### 11. William Brown — 2017-10-03 14:18 +1000

**Subject:** Please review: 49376 idlistscanlimit

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/GYIXGF2WHHF2NMZACLDHUF64KPGZVY2D/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/GYIXGF2WHHF2NMZACLDHUF64KPGZVY2D/)

**Paraphrase:** The email itself contains a Pagure issue link and a review link to a patch named raise-idscanlimit. The linked change treats the global IDL scan limit as a coarse query shortcut: when an OR component exceeds the limit and becomes ALLIDS, the union also becomes ALLIDS; in an AND where no earlier component permits a shortcut, discarding a long indexed candidate list can move work to final entry scanning instead of reducing it. The patch raises the default limit while retaining explicit configuration, so candidate lists are not cut off by the previous default threshold. This legacy ticket later became GitHub issue 2435.

### 12. William Brown — 2019-04-29 12:10 +1000

**Subject:** Second opinion on backend filter testing

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/545CSBD4OY3RGUDTSL37J7FYXFEAW63H/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/545CSBD4OY3RGUDTSL37J7FYXFEAW63H/)

**Paraphrase:** Brown asks for review of a possible search-correctness interaction exposed while investigating FreeIPA failures with the filter optimizer. He lays out the original nested filter and the optimized form, observes that all logical components remain present, and separates logical filter rewriting from the new execution order caused by rewriting. His working question is whether the order change reaches an existing mistake in the decision to bypass the final filter test.

He traces the path from ldbm_back_search through build_candidate_list and the later bypass condition. With search bypass enabled by default, the decision depends in part on lookup_returned_allids. A fully ALLIDS candidate set prevents bypass, while a partially evaluated IDL can be smaller than the bypass threshold and also set SLAPI_BE_FLAG_DONT_BYPASS_FILTERTEST during IDL union or intersection. He then identifies can_skip_filter_test as not consulting that backend flag before setting SR_FLAG_CAN_SKIP_FILTER_TEST. If that sequence occurs, ldbm_back_next_search_entry_ext can accept candidate members without running the remaining filter, even though the candidate list was deliberately widened or only partially evaluated.

Brown inventories the locations that set and read DONT_BYPASS_FILTERTEST and notes that its read path is tied to one-level candidate handling. He compares the example filter with a candidate FreeIPA entry that has the certificate mapping value but lacks the required ipaIDObject object class, while also noting that he does not know whether FreeIPA actually expects that entry. His proposed hardening passes the backend into can_skip_filter_test and immediately disallows skipping when DONT_BYPASS_FILTERTEST is set; he names setting lookup_returned_allids from the flag inside subtree_candidates as an alternate placement. Basic and filter suites pass both with optimization disabled plus the bypass change and with optimization enabled plus the change. He also gives verify-mode logging as another way to detect mismatches. The final distinction left for investigation is whether reordered, logically equivalent evaluation is revealing an invalid caller expectation or a server path that previously accepted candidates without applying every filter term.

### 13. William Brown — 2019-04-29 19:23 +1000

**Subject:** Re: Second opinion on backend filter testing

[Message](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/message/OWC3MD5YPKBXEJFTV6QQS7WIZOWUZRI5/) · [Thread](https://lists.fedoraproject.org/archives/list/389-devel@lists.fedoraproject.org/thread/545CSBD4OY3RGUDTSL37J7FYXFEAW63H/)

**Paraphrase:** In the follow-up, Brown says grok_filter may already force can_skip to false in many of the relevant cases, so he cannot establish the suspected bypass path from the available evidence; he also cannot reproduce the failure, although he still finds the flag handling unclear. He plans to harden the path, add debugging, and enable verification to look for a failing FreeIPA condition. He records the remaining information gap: the logs do not identify which exact query FreeIPA considers wrong or what result FreeIPA expects. He asks for FreeIPA-side isolation of that query and expected result, while retaining the filter-optimization work as the surrounding performance project.
