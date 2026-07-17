# 389-users source reader: filter candidate generation

This is a curated, chronological reader of individual messages from the `389-users` archive that directly describe the problems and mechanisms surrounding AND-component order, substring candidate lists, ID-list scan limits, partial candidates, filter-test shortcuts, and forced filter testing. It is not an exhaustive mailing-list catalog. Third-party emails are not reproduced verbatim; each detailed paraphrase preserves the substantive content of the selected message. Each entry links both the exact message and its complete HyperKitty thread.

## 1. Broad first component and AND-filter order

**Rich Megginson — 2006-08-02 — “Re: Odd performance problem, server not using indeces”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/UWMWS6XDVYCIY7XXZMEPEGMFLIJRBGXU/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/2BI7JNWSGVGKUSYMVFB5RCPWYCPVBX4Z/)

The question concerned `(&(objectClass=organizationalPerson)(employeeNumber=*))` in a directory containing roughly 350,000 users, about 5,000 of which belonged to the more specific `icasOrgPerson` class. Both filter attributes had the expected indexes, but the search was slow and logged `notes=U`. Megginson asks how many entries match the broad `objectClass=organizationalPerson` component. He describes the database as looking up that first component, finding that it has too many matches, and abandoning that path. He gives two alternatives within the same filter shape: replace the broad class with the more specific `icasOrgPerson`, or reverse the order of the filter components.

## 2. Indexed wildcard searches reaching the scan limit

**Paul Lemoine — 2009-07-03 — “Directory server: search problem with wildcard”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/BNRLNEP46NSGDZH2FVPXRM2WULPQBF7Y/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/BNRLNEP46NSGDZH2FVPXRM2WULPQBF7Y/)

Lemoine reports Fedora DS 1.1.3 with approximately 350,000 `inetOrgPerson` entries and an extended schema. Prefix wildcard filters such as `(cn=smith*)` and `(uid=25698*)` take about a minute and return LDAP error 11. The `cn` and `uid` attributes have equality, presence, and substring indexes, and the indexes have been recreated. Setting the look-through limit to infinity removes error 11 but leaves the search very slow; the access log records an elapsed time of 77 seconds and `notes=U`. The equivalent searches against entries using the native schema complete normally, so the message asks whether the extended schema is involved and whether the server can be made to use the configured indexes.

## 3. Reported result after increasing the limit

**Paul Lemoine — 2009-07-07 — “Re: Directory server: search problem with wildcard”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/YQQ2AQVQACS5EAGKEQXLOHLB7CHZ243M/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/YQQ2AQVQACS5EAGKEQXLOHLB7CHZ243M/)

After the earlier diagnosis pointed to `idlistscanlimit`, Lemoine reports changing the value from 4,000 to 40,000. With that setting, the wildcard-search problem disappears. He then asks how the limit should be sized for a directory expected to grow to three million `inetOrgPerson` entries and whether there is a formula relating the setting to the total entry count.

## 4. Matching population rather than total directory size

**Rich Megginson — 2009-07-07 — “Re: Directory server: search problem with wildcard”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/GS76NH26CUCTDUTAME3PHQ6VWABQLS7G/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/YQQ2AQVQACS5EAGKEQXLOHLB7CHZ243M/)

Megginson answers that the relevant relationship is not between `idlistscanlimit` and the directory's total number of entries. The relationship is between the limit and the number of entries expected to match one search component. He uses a broad substring such as `(cn=*e*)` as the example for a search whose expected matching population would require a correspondingly large limit.

## 5. Fine-grained rule scoped to AND evaluation

**Mark Reynolds — 2014-12-09 — “Re: 389-ds and Multi CPU's”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/RAKEHHQRYQ2QBQNTQJD7DJF5UB3TNFCI/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/5OWZKG5TB3XHRG4CTJTNKNRL6KHT4XIF/)

The reporter had added an unlimited equality rule for the `inetOrgPerson` value in the `objectClass` index, but continued to see hundreds of unindexed components for `(&(objectClass=inetOrgPerson))`. Reynolds supplies a replacement configuration containing two `nsIndexIDListScanLimit` values: an unlimited equality rule for `inetOrgPerson`, and a second unlimited equality rule for the same value with `flags=AND`. He also asks whether `userRoot` is the backend mapped to the searched suffix, because the rule must be attached to the active `objectClass` index entry, and asks whether the error log contains messages about the settings. The message states that the additional AND-scoped rule is intended to remove those unindexed-search records.

## 6. Per-index substring-limit proposal

**Mark Reynolds — 2015-08-05 — “Re: 389-DS poor performance retrieving groups”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/SKGO2GYTVNCE3SGM52V64RQQDR3A677P/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/3KSRLV7MSGEGNW7BAKVJ2QTGPGZ5XM3J/)

The underlying search is `(cn=*MT*)`, returning roughly 2,600 groups. Reynolds says the access-log excerpt should establish whether the search is marked with `notes=U` or `notes=A`. He then gives a fine-grained `nsIndexIDListScanLimit` example on the `cn` index: if this is the only affected search, an unlimited substring rule scoped to the `*mt` and `mt*` values; if multiple `cn` substring searches are affected, an unlimited rule for the whole substring index type. This message records the proposed per-value and per-index forms before the later follow-up below.

## 7. Withdrawal of the two-character substring proposal

**Mark Reynolds — 2015-08-05 — “Re: 389-DS poor performance retrieving groups”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/T33XR434GQBJWGR64JMKJMDEGRUSEZFT/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/3KSRLV7MSGEGNW7BAKVJ2QTGPGZ5XM3J/)

Later in the same conversation, Reynolds withdraws the preceding configuration as a solution for `(cn=*mt*)`. He states that this two-character interior substring is not represented by the default substring index and that changing the ID-list rule therefore does not make that filter indexed. For a recurring query of this shape, the message identifies a client-issued VLV search backed by a VLV index as the alternative discussed in the thread and points to the administration guide for that mechanism.

## 8. Threshold transition from an index list to a full scan

**Noriko Hosoi — 2017-02-17 — “Re: elapsed time gremlin”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/KZQ7GM7EGKEUANCN3M47MTLU2BDXUMWM/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/I5OG7ZGHWCHWCNJ47RIYGTTTV7EMDI2S/)

Hosoi responds after increasing the scan limit changed a one-level `(cn=*)` search over a roughly 6,000-entry branch from about 123 seconds to seconds. She cites the then-current performance guide and describes the limit as the maximum number of IDs read for a key before that key is treated as matching the entire primary index. At that point the search uses the unindexed-search resource limits and tests entries rather than continuing to use the key's ID list. She illustrates why large indexed populations matter with a million-entry `inetOrgPerson` or surname index. For the observed difference between the `PEOPLE` and `STUDENTS` branches, she describes a possible entry-ID layout in which older `PEOPLE` records have lower IDs and `STUDENTS` records occur later, so a full scan reaches one population earlier than the other. In the indexed path, the server obtains the entry IDs from the indexes instead of walking entries individually.

## 9. Partial candidates and the purpose of two limits

**William Brown — 2019-11-05 — “Re: Unexpected failure while searching”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/U4C6RYRST4NYG4QRVW3YXLCZOQH7TJ2R/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/MWOB3NQPRAT6XAFBY35N6YU36D4UH6YW/)

Brown identifies LDAP error 11 as an administrative-limit result and describes the immediate possibility as a partial candidate set larger than the configured limits. He distinguishes the settings: the look-through limit controls how many candidate entries may be filter-tested in a full-scan or incompletely indexed search, while the ID-list scan limit controls how large an index list may be read. He describes the latter as discarding a large component list in the expectation that a later filter component may yield a smaller candidate list. The rest of the message checks the other possible cause in that incident: it identifies the active `uid` index DN, distinguishes it from the default-index template, mentions rebuilding the database index, and supplies `dbscan` commands for two concrete equality keys so the resulting nonzero entry IDs can be inspected.

## 10. Filter-test threshold, component reordering, and scan-limit tradeoffs

**William Brown — 2020-08-17 — “Re: CPU Scalability / Scaling”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/JY6NDEMUR3E4KXCAIL7DBVQSE5FDXW3U/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/KTYVGLCWEHXKASF2STJXDYGQ2GY3PNSG/)

Brown first places server scaling in the context of workload, enabled plugins, replication topology, NUMA, and worker-thread configuration. In the filter-specific portion, he describes `IDListScanLimit` as a mechanism that stops reading a broad index component, treats it as effectively covering the table, and continues in the expectation that another component is more selective. His example is `(&(objectClass=account)(uid=william))`: abandoning the broad object-class list still allows the single-ID `uid` list to become the candidate set for entry-level filter testing.

He contrasts that case with a broad search that genuinely needs a 10,000-ID group index. Abandoning that index after 4,000 IDs can turn a finite index lookup into a scan and thousands of filter tests, while reading the complete list permits the server to return the candidate set directly. He therefore describes the setting as a tradeoff between broad searches and targeted compound searches.

The message then explains the filter optimizer's threshold behavior. Once an evaluated component produces a candidate set below the filter-test threshold, the server can stop loading later index components and test the remaining filter against those candidates. A selective-first `(&(uid=william)(objectClass=account))` reaches one ID and never loads the broad object-class list; reordering is intended to produce that evaluation order from the broad-first form. The message also records access-log analysis through `notes=U` and `notes=A`, filter-syntax validation, and version-dependent behavior as ways the author used to distinguish full, partial, and internally wrapped unindexed filters. Its remaining sections cover read/write scaling across replicas, plugin effects on the write path, batched replication, log-device latency, and cache information exposed under the monitoring entries.

## 11. Cost of mandatory filter testing after issue #5170

**Thierry Bordaz — 2023-03-14 — “Re: 2.x query performance problem”**

[Message](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/message/YQ7CRBUPVKPE5BYUNFXNDHSLXOMINWEY/) · [Full thread](https://lists.fedoraproject.org/archives/list/389-users@lists.fedoraproject.org/thread/4FIZROX2BKGN5PYBUQOMVVJWRPJSMVTC/)

Bordaz reports a controlled comparison in which 1.4.4 returns 1,000 matching group DNs for an indexed `uniqueMember` equality search in about 0.027 seconds, approximately 28 times faster than the corresponding 2.x observation. He connects the difference to issue #5170, which made the server evaluate the filter against returned entries even in paths that had previously bypassed that evaluation. He describes the additional evaluation as significant when the result contains roughly 500 or more entries and when the tested attribute itself has a large value set, as with `uniqueMember` on large groups. The message also records the reason for the #5170 behavior: it prevents entries that do not satisfy the complete filter from being returned. It states that this performance effect had not been detected with the original correctness change and was being revisited.
