/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2026 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/

/* Temporary, low-overhead diagnostic probe for PR 7920. Never ship in a fix. */
#ifndef PR7920_PROBE_H
#define PR7920_PROBE_H

#include <stdint.h>
#include <time.h>

static inline uint64_t
pr7920_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

void pr7920_poll_record(uint64_t connid, int32_t opid, uint64_t lock_wait_ns,
                        uint64_t lock_acquired_ns, uint64_t poll_enter_ns,
                        uint64_t poll_exit_ns, uint64_t lock_released_ns,
                        int waits_done, int poll_rc);
void pr7920_flush_record(uint64_t connid, int32_t opid, uint64_t lock_wait_ns,
                         uint64_t lock_acquired_ns, uint64_t write_enter_ns,
                         uint64_t write_exit_ns, uint64_t lock_released_ns,
                         int type, int write_rc);
void pr7920_dump_bind(uint64_t connid, int32_t opid, uint64_t lock_wait_ns);

#endif /* PR7920_PROBE_H */
