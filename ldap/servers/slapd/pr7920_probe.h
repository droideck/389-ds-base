/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2026 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/

/* Diagnostic-only timing probe for PR 7920; omit from any production fix. */
#ifndef PR7920_PROBE_H
#define PR7920_PROBE_H

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Each translation unit opens the same O_APPEND file once. A single write
 * keeps each short record together without adding a lock to server paths.
 * By default the file is next to the configured errors log, which remains
 * visible despite the systemd service's PrivateTmp setting. An explicit
 * DS_PR7920_PROBE_PATH override is also supported.
 */
static int pr7920_probe_fd = -1;
static pthread_once_t pr7920_probe_once = PTHREAD_ONCE_INIT;

static void
pr7920_probe_open(void)
{
    const char *path = getenv("DS_PR7920_PROBE_PATH");
    char *errorlog = NULL;
    char pathbuf[PATH_MAX];
    int n;

    if (path == NULL || path[0] == '\0') {
        errorlog = config_get_errorlog();
        if (errorlog == NULL) {
            return;
        }
        n = snprintf(pathbuf, sizeof(pathbuf), "%s.pr7920-probe", errorlog);
        slapi_ch_free_string(&errorlog);
        if (n < 0 || n >= (int)sizeof(pathbuf)) {
            return;
        }
        path = pathbuf;
    }
    pr7920_probe_fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
}

static uint64_t
pr7920_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void
pr7920_probe(const char *event, uint64_t connid, int32_t opid,
             uint64_t when_ns, uint64_t wait_ns, int aux)
{
    char line[256];
    int n;

    pthread_once(&pr7920_probe_once, pr7920_probe_open);
    if (pr7920_probe_fd < 0) {
        return;
    }
    n = snprintf(line, sizeof(line),
                 "pr7920 ns=%" PRIu64 " tid=%lu lwp=%ld conn=%" PRIu64
                 " op=%d event=%s wait_ns=%" PRIu64 " aux=%d\n",
                 when_ns, (unsigned long)pthread_self(), (long)syscall(SYS_gettid), connid, opid,
                 event, wait_ns, aux);
    if (n > 0 && n < (int)sizeof(line)) {
        (void)write(pr7920_probe_fd, line, (size_t)n);
    }
}

#endif /* PR7920_PROBE_H */
