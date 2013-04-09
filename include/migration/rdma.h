/*
 *  Copyright (C) 2013 Michael R. Hines <mrhines@us.ibm.com>
 *  Copyright (C) 2013 Jiuxing Liu <jl@us.ibm.com>
 *
 *  RDMA data structures and helper functions (for migration)
 *
 *  This program is free software; you can redistribute it and/or modify *  it under the terms of the GNU General Public License as published by
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

#ifndef _RDMA_H
#define _RDMA_H

#include "config-host.h"
#ifdef CONFIG_RDMA 
#include <rdma/rdma_cma.h>
#endif
#include "monitor/monitor.h"
#include "exec/cpu-common.h"
#include "migration/migration.h"

#define Mbps(bytes, ms) ((double) bytes * 8.0 / ((double) ms / 1000.0)) \
                                / 1000.0 / 1000.0

extern const QEMUFileOps rdma_read_ops;
extern const QEMUFileOps rdma_write_ops;

#ifdef CONFIG_RDMA

void qemu_rdma_disable(void *opaque);
void qemu_rdma_cleanup(void *opaque);
int qemu_rdma_client_init(void *opaque, Error **errp,
            bool chunk_register_destination);
int qemu_rdma_connect(void *opaque, Error **errp);
void *qemu_rdma_data_init(const char *host_port, Error **errp);
int qemu_rdma_server_init(void *opaque, Error **errp);
int qemu_rdma_server_prepare(void *opaque, Error **errp);
int qemu_rdma_drain_cq(QEMUFile *f);
int qemu_rdma_put_buffer(void *opaque, const uint8_t *buf, 
                            int64_t pos, int size);
int qemu_rdma_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size);
int qemu_rdma_close(void *opaque);
size_t save_rdma_page(QEMUFile *f, ram_addr_t block_offset, 
            ram_addr_t offset, int cont, size_t size, bool zero);
void *qemu_fopen_rdma(void *opaque, const char * mode);
int qemu_rdma_get_fd(void *opaque);
int qemu_rdma_accept(void *opaque);
void rdma_start_outgoing_migration(void *opaque, const char *host_port, Error **errp);
void rdma_start_incoming_migration(const char * host_port, Error **errp);
int qemu_rdma_handle_registrations(QEMUFile *f);
int qemu_rdma_finish_registrations(QEMUFile *f);

#else /* !defined(CONFIG_RDMA) */
#define NOT_CONFIGURED() do { printf("WARN: RDMA is not configured\n"); } while(0)
#define qemu_rdma_cleanup(...) NOT_CONFIGURED()
#define qemu_rdma_data_init(...) NOT_CONFIGURED() 
#define rdma_start_outgoing_migration(...) NOT_CONFIGURED()
#define rdma_start_incoming_migration(...) NOT_CONFIGURED()
#define qemu_rdma_handle_registrations(...) 0
#define qemu_rdma_finish_registrations(...) 0
#define qemu_rdma_get_buffer NULL
#define qemu_rdma_put_buffer NULL
#define qemu_rdma_close NULL
#define qemu_fopen_rdma(...) NULL
#define qemu_rdma_client_init(...) -1 
#define qemu_rdma_client_connect(...) -1 
#define qemu_rdma_server_init(...) -1 
#define qemu_rdma_server_prepare(...) -1 
#define qemu_rdma_drain_cq(...) -1 
#define save_rdma_page(...) -ENOTSUP

#endif /* CONFIG_RDMA */

#endif
