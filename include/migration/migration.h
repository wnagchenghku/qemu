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

void rdma_start_outgoing_migration(void *opaque, const char *host_port, Error **errp);

void rdma_start_incoming_migration(const char * host_port, Error **errp);

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
uint64_t xbzrle_mig_bytes_transferred(void);
uint64_t xbzrle_mig_pages_transferred(void);
uint64_t xbzrle_mig_pages_overflow(void);
uint64_t xbzrle_mig_pages_cache_miss(void);

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

bool migrate_check_for_zero(void);
bool migrate_chunk_register_destination(void);

/*
 * Hooks before and after each iteration round to perform special functions.
 * In the case of RDMA, this is to handle dynamic server registration.
 */
#define RAM_CONTROL_SETUP    0
#define RAM_CONTROL_ROUND    1
#define RAM_CONTROL_REGISTER 2
#define RAM_CONTROL_FINISH   3

typedef void (RAMFunc)(QEMUFile *f, void *opaque, int section);

struct QEMURamControlOps {
    RAMFunc *before_ram_iterate;
    RAMFunc *after_ram_iterate;
    RAMFunc *register_ram_iterate;
    size_t (*save_page)(QEMUFile *f,
               void *opaque, ram_addr_t block_offset, 
               ram_addr_t offset, int cont, size_t size, 
               bool zero);
};

const QEMURamControlOps *qemu_savevm_get_control(QEMUFile *f);

void ram_control_before_iterate(QEMUFile *f, int section);
void ram_control_after_iterate(QEMUFile *f, int section);
void ram_control_register_iterate(QEMUFile *f, int section);
size_t ram_control_save_page(QEMUFile *f, ram_addr_t block_offset, 
                                    ram_addr_t offset, int cont, 
                                    size_t size, bool zero);

#ifdef CONFIG_RDMA
extern const QEMURamControlOps qemu_rdma_control;

size_t qemu_rdma_save_page(QEMUFile *f, void *opaque,
                           ram_addr_t block_offset, 
                           ram_addr_t offset, int cont, 
                           size_t size, bool zero);

void qemu_rdma_registration_stop(QEMUFile *f, void *opaque, int section);
void qemu_rdma_registration_handle(QEMUFile *f, void *opaque, int section);
void qemu_ram_registration_start(QEMUFile *f, void *opaque, int section);
#endif

#endif
