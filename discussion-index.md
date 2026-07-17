# 389-ds-base filter and IDL discussion collection

Collected on 2026-07-16 from GitHub issue, issue-comment, pull-request, review, inline-review, and timeline surfaces, together with the Fedora 389-devel and 389-users mailing-list archives. The collection is chronological and descriptive; it contains no evaluation or recommendations.

## Source issues

- [#2414 — keep indexes for tombstones](https://github.com/389ds/389-ds-base/issues/2414)
- [#841 — idlistscanlimit per index/type/value](https://github.com/389ds/389-ds-base/issues/841)
- [#811 — Ordering of ANDed search terms in filter can negatively impact search etimes](https://github.com/389ds/389-ds-base/issues/811)
- [#2431 — optimise filters for common query types](https://github.com/389ds/389-ds-base/issues/2431)
- [#5170 — Filter optimiser](https://github.com/389ds/389-ds-base/issues/5170)
- [#6275 — Search request executes slowly with many OR values](https://github.com/389ds/389-ds-base/issues/6275)
- [#6966 — On large DB, unlimited IDL scan limit reduces search performance](https://github.com/389ds/389-ds-base/issues/6966)

## Collection files

- [Legacy tombstone and IDL-limit issues](discussions-legacy.md): #2414, #841, and #811, including migrated Pagure dates, attachments, direct commits, metadata-only entries, cross-references, and the verified absence of qualifying PRs.
- [Historical optimiser issues and archived review](discussions-optimizer.md): #2431, the 71-comment Pagure PR mirror #3311, and #5170.
- [Main GitHub optimiser PRs](discussions-optimizer-main-prs.md): superseded PR #5168 and merged implementation PR #5171, including review envelopes and inline threads.
- [Corrective and follow-up optimiser PRs](discussions-optimizer-followup-prs.md): #5285, #5301, #5315, #5316, and #5604.
- [Modern OR and large-IDL discussions](discussions-modern.md): #6275, #6966, #6967, the #7026 cross-reference discussion, and causal follow-up #7036.
- [389-devel mailing-list source reader](discussions-mailing-list-devel.md): 13 essential design and correctness messages about IDLs, candidate generation, filter ordering, scan limits, tombstones, substrings, and final filter testing.
- [389-users mailing-list source reader](discussions-mailing-list-users.md): 11 essential problem and mechanism messages about AND order, substring candidates, ALLIDS thresholds, partial candidates, and filter-test cost.

Each file records its own exact discussion-surface counts. Posts are represented by terse paraphrases with author, date, and a direct permalink to the original body, comment, review, or inline thread. Empty review bodies and metadata-only posts are explicitly identified. Automated CI/status noise is counted only when needed to explain the discussion surface and is not treated as human discussion.

## Direct-link discovery notes

- No qualifying GitHub pull request was found for #2414, #841, #811, or #6275.
- #3311 is the migrated Pagure pull-request discussion for the original #2431 implementation and is represented on GitHub as an issue.
- #5168 was superseded by #5171.
- #5285, #5301, #5315, and unmerged #5316 directly reference #5170; #5604 is a later performance follow-up that explicitly attributes part of its behavior to #5170.
- #6967 closes #6966. #7036 fixes the healthcheck regression attributed to #6966. #7026 is included only because its discussion contains the direct #6966/#7032 cross-reference.
- Cross-referencing issues and attachments are linked from the relevant chronology but were not recursively expanded unless they are one of the seven source issues or a directly connected PR listed above.
