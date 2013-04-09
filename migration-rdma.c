/*
 *  Copyright (C) 2013 Michael R. Hines <mrhines@us.ibm.com>
 *  Copyright (C) 2010 Jiuxing Liu <jl@us.ibm.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include "migration/rdma.h"
#include "qemu-common.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>

//#define DEBUG_MIGRATION_RDMA

#ifdef DEBUG_MIGRATION_RDMA
#define DPRINTF(fmt, ...) \
    do { printf("migration-rdma: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

static void rdma_accept_incoming_migration(void *opaque)
{
    int ret;
    QEMUFile *f;

    DPRINTF("Accepting rdma connection...\n");

    if ((ret = qemu_rdma_accept(opaque))) {
        fprintf(stderr, "RDMA Migration initialization failed!\n");
        goto err;
    }

    DPRINTF("Accepted migration\n");

    f = qemu_fopen_rdma(opaque, "rb");
    if (f == NULL) {
        fprintf(stderr, "could not qemu_fopen_rdma!\n");
        goto err;
    }

    process_incoming_migration(f);
    return;

err:
    qemu_rdma_cleanup(opaque);
}

void rdma_start_incoming_migration(const char * host_port, Error **errp)
{
    int ret;
    void *opaque;

    DPRINTF("Starting RDMA-based incoming migration\n");

    if ((opaque = qemu_rdma_data_init(host_port, errp)) == NULL) {
        return;
    }

    ret = qemu_rdma_server_init(opaque, NULL);

    if (!ret) {
        DPRINTF("qemu_rdma_server_init success\n");
        ret = qemu_rdma_server_prepare(opaque, NULL);

        if (!ret) {
            DPRINTF("qemu_rdma_server_prepare success\n");

            qemu_set_fd_handler2(qemu_rdma_get_fd(opaque), NULL, 
                                 rdma_accept_incoming_migration, NULL,
                                    (void *)(intptr_t) opaque);
            return;
        }
    }

    g_free(opaque);
}

void rdma_start_outgoing_migration(void *opaque, const char *host_port, Error **errp)
{
    MigrationState *s = opaque;
    void *rdma_opaque = NULL;
    int ret;

    if ((rdma_opaque = qemu_rdma_data_init(host_port, errp)) == NULL)
        return; 

    ret = qemu_rdma_client_init(rdma_opaque, NULL,
        s->enabled_capabilities[MIGRATION_CAPABILITY_CHUNK_REGISTER_DESTINATION]);

    if(!ret) {
        DPRINTF("qemu_rdma_client_init success\n");
        ret = qemu_rdma_connect(rdma_opaque, NULL);

        if(!ret) {
            s->file = qemu_fopen_rdma(rdma_opaque, "wb");
            DPRINTF("qemu_rdma_client_connect success\n");
            migrate_fd_connect(s);
            return;
        }
    }

    g_free(rdma_opaque);
    migrate_fd_error(s);
}
