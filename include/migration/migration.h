/*
 * QEMU live migration
 *
 * Copyright IBM, Corp. 2008
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef QEMU_MIGRATION_H
#define QEMU_MIGRATION_H

#include "qapi/qmp/qdict.h"
#include "qemu-common.h"
#include "qemu/thread.h"
#include "qemu/notify.h"
#include "qapi/error.h"
#include "migration/vmstate.h"
#include "qapi-types.h"
#include "qemu/thread-posix.h"
#include "exec/cpu-common.h"

struct MigrationParams {
    bool blk;
    bool shared;
};

typedef struct MigrationState MigrationState;

struct MigrationState
{
    int64_t bandwidth_limit;
    size_t bytes_xfer;
    size_t xfer_limit;
    QemuThread thread;
    QEMUBH *cleanup_bh;
    QEMUFile *file;

    int state;
    MigrationParams params;
    int64_t total_time;
    int64_t downtime;
    int64_t expected_downtime;
    int64_t xmit_time;
    int64_t ram_copy_time;
    int64_t log_dirty_time;
    int64_t bitmap_time;
    int64_t dirty_pages_rate;
    int64_t dirty_bytes_rate;
    bool enabled_capabilities[MIGRATION_CAPABILITY_MAX];
    int64_t xbzrle_cache_size;
};

void process_incoming_migration(QEMUFile *f);

void qemu_start_incoming_migration(const char *uri, Error **errp);

uint64_t migrate_max_downtime(void);

void do_info_migrate_print(Monitor *mon, const QObject *data);

void do_info_migrate(Monitor *mon, QObject **ret_data);

void exec_start_incoming_migration(const char *host_port, Error **errp);

void exec_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp);

void tcp_start_incoming_migration(const char *host_port, Error **errp);

void tcp_start_outgoing_migration(MigrationState *s, const char *host_port, Error **errp);

void unix_start_incoming_migration(const char *path, Error **errp);

void unix_start_outgoing_migration(MigrationState *s, const char *path, Error **errp);

void fd_start_incoming_migration(const char *path, Error **errp);

void fd_start_outgoing_migration(MigrationState *s, const char *fdname, Error **errp);

void mc_start_incoming_migration(const char *uri, Error **errp);

void mc_start_outgoing_migration(MigrationState *s, const char *uri, Error **errp);

void migrate_fd_error(MigrationState *s);

void migrate_fd_connect(MigrationState *s);

int migrate_fd_close(MigrationState *s);

void add_migration_state_change_notifier(Notifier *notify);
void remove_migration_state_change_notifier(Notifier *notify);
bool migration_is_active(MigrationState *);
bool migration_has_finished(MigrationState *);
bool migration_has_failed(MigrationState *);
MigrationState *migrate_get_current(void);

uint64_t ram_bytes_remaining(void);
uint64_t ram_bytes_transferred(void);
uint64_t ram_bytes_total(void);

extern SaveVMHandlers savevm_ram_handlers;

uint64_t dup_mig_bytes_transferred(void);
uint64_t dup_mig_pages_transferred(void);
uint64_t skipped_mig_bytes_transferred(void);
uint64_t skipped_mig_pages_transferred(void);
uint64_t norm_mig_bytes_transferred(void);
uint64_t norm_mig_pages_transferred(void);
uint64_t norm_mig_log_dirty_time(void);
uint64_t norm_mig_bitmap_time(void);
uint64_t norm_mig_ram_copy_time(void);
uint64_t xbzrle_mig_bytes_transferred(void);
uint64_t xbzrle_mig_pages_transferred(void);
uint64_t xbzrle_mig_pages_overflow(void);
uint64_t xbzrle_mig_pages_cache_miss(void);
void acct_clear(void);

/**
 * @migrate_add_blocker - prevent migration from proceeding
 *
 * @reason - an error to be returned whenever migration is attempted
 */
void migrate_add_blocker(Error *reason);

/**
 * @migrate_del_blocker - remove a blocking error from migration
 *
 * @reason - the error blocking migration
 */
void migrate_del_blocker(Error *reason);

int xbzrle_encode_buffer(uint8_t *old_buf, uint8_t *new_buf, int slen,
                         uint8_t *dst, int dlen);
int xbzrle_decode_buffer(uint8_t *src, int slen, uint8_t *dst, int dlen);

int migrate_use_xbzrle(void);
int64_t migrate_xbzrle_cache_size(void);

int64_t xbzrle_cache_resize(int64_t new_size);

void *migration_bitmap_worker(void *opaque);
void migration_bitmap_worker_start(MigrationState *s);
void migration_bitmap_worker_stop(MigrationState *s);

void migrate_finish_error(MigrationState *s);
void migrate_finish_complete(MigrationState *s);

#define MBPS(bytes, time) time ? ((((double) bytes * 8)         \
        / ((double) time / 1000.0)) / 1000.0 / 1000.0) : -1.0

/*
 * Micro-checkpointing mode.
 */
enum MC_MODE {
    MC_MODE_ERROR = -1,
    MC_MODE_OFF,
    MC_MODE_INIT,
    MC_MODE_RUNNING,
};

extern enum MC_MODE mc_mode;

int mc_enable_buffering(void);
int mc_start_buffer(void);
void mc_start_checkpointer(MigrationState *s);
void mc_process_incoming_checkpoints(QEMUFile *f);

#endif
