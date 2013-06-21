/*
 *  Copyright (C) 2013 Michael R. Hines <mrhines@us.ibm.com>
 *
 *  Qdisc plug network buffering for Micro-Checkpointing
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
#include <libnl3/netlink/route/qdisc/plug.h>
#include <libnl3/netlink/route/class.h>
#include <libnl3/netlink/cli/utils.h>
#include <libnl3/netlink/cli/tc.h>
#include <libnl3/netlink/cli/qdisc.h>
#include <libnl3/netlink/cli/link.h>
#include "qemu-common.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-net.h"
#include "qemu/sockets.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "qmp-commands.h"

#define DEBUG_MC
//#define DEBUG_MC_VERBOSE

#ifdef DEBUG_MC
#define DPRINTF(fmt, ...) \
    do { printf("mc: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_MC_VERBOSE
#define DDPRINTF(fmt, ...) \
    do { printf("mc: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DDPRINTF(fmt, ...) \
    do { } while (0)
#endif

#define MC_BUFFER_SIZE_MAX (5 * 1024 * 1024)
#define MC_DEV_NAME_MAX_SIZE    256


typedef struct MChunk MChunk;

/*
 * Micro checkpoints (MC)s are typically less than 5MB.
 * However, they can easily be much larger during heavy workloads.
 *
 * To support this possibility during transient periods,
 * a micro checkpoint consists of a linked list of "chunks",
 * each of identical size (not unlike slabs in the kernel).
 * This allows MCs to grow and shrink without constantly
 * re-allocating memory in place.
 *
 * During steady-state, the 'head' chunk is permanently
 * allocated and never goes away, so most of the time there
 * is no memory allocation at all.
 */
struct MChunk {
    MChunk *next;
    uint8_t buf[MC_BUFFER_SIZE_MAX];
    uint64_t size;
    uint64_t read;
};

typedef struct MCParams {
    MChunk *chunks;
    MChunk *curr_chunk;
    uint64_t chunk_total;
    QEMUFile *file;
} MCParams;

enum MC_TRANSACTION {
    MC_TRANSACTION_NACK = -1,
    MC_TRANSACTION_COMMIT,
    MC_TRANSACTION_CANCEL,
    MC_TRANSACTION_ACK,
};

static struct rtnl_qdisc *qdisc = NULL;
static struct nl_sock *sock = NULL;
static struct rtnl_tc *tc = NULL;
static struct nl_cache *link_cache = NULL;
static struct rtnl_tc_ops *ops = NULL;
static struct nl_cli_tc_module *tm = NULL;

/*
* Assuming a guest can 'try' to fill a 1 Gbps pipe,
* that works about to 125000000 bytes/sec.
* 
* Netlink better not be pre-allocating megabytes in the
* kernel qdisc, that would be crazy....
*/
#define START_BUFFER (1000*1000*1000 / 8)
static int buffer_size = START_BUFFER, new_buffer_size = START_BUFFER;
static const char * parent = "root";
static int buffering_enabled = 0;
static const char * NIC_PREFIX = "tap";
static const char * BUFFER_NIC_PREFIX = "ifb";
static QEMUBH *checkpoint_bh = NULL;
static bool mc_requested = false;

static int mc_deliver(int update)
{
    int err, flags = NLM_F_CREATE;

    if(!buffering_enabled)
        return -EINVAL;

    if (!update)
        flags |= NLM_F_EXCL;
  
    if ((err = rtnl_qdisc_add(sock, qdisc, flags)) < 0) {
        fprintf(stderr, "Unable control qdisc: %s! %p %p %d\n", 
            nl_geterror(err), sock, qdisc, flags);
        return -EINVAL;
    }

    return 0;
}

static int mc_set_buffer_size(int size)
{
    int err;

    if(!buffering_enabled)
    return 1;

    buffer_size = size;
    new_buffer_size = size;

    if ((err = rtnl_qdisc_plug_set_limit((void *) qdisc, size)) < 0) {
       fprintf(stderr, "MC: Unable to change buffer size: %s\n", 
			nl_geterror(err));
       return -EINVAL;
    } 

    DPRINTF("Set buffer size to %d bytes\n", size);

    return mc_deliver(1);
}

/*
 * Micro-checkpointing may require buffering network packets.
 * Set that up for the first NIC only....
 */
static void init_mc_nic_buffering(NICState *nic, void *opaque)
{
    char * device = opaque;
    static int first_nic_chosen = 0;
    NetClientState * nc = &nic->ncs[0];
    const char * key = "ifname=";
    int keylen = strlen(key);
    char * name;
    int end = 0;
    
    if(first_nic_chosen) {
         fprintf(stderr, "Micro-Checkpointing with multiple NICs not yet supported!\n");
         return;
    }

    if(!nc->peer) {
        fprintf(stderr, "Micro-Checkpoint nic %s does not have peer host device for buffering. VM will not be consistent.\n", nc->name);
        return;
    }

    name = nc->peer->info_str;

    if(strncmp(name, key, keylen)) {
        fprintf(stderr, "Micro-Checkpoint nic %s does not have 'ifname' in its description %s. VM will not be consistent.\n", nc->name, name);
        return;
    }

    name += keylen;

    while(name[end++] != ',');

    strncpy(device, name, end - 1);
    memset(&device[end - 1], 0, MC_DEV_NAME_MAX_SIZE - (end - 1));

    first_nic_chosen = 1;
}

static int mc_suspend_buffering(void)
{
   int err;

   if(!buffering_enabled)
	return -EINVAL;

   if ((err = rtnl_qdisc_plug_release_indefinite((void *) qdisc)) < 0) {
       fprintf(stderr, "MC: Unable to release indefinite: %s\n", 
			nl_geterror(err));
       return -EINVAL;
   }

   DPRINTF("Buffering suspended.\n");

   return mc_deliver(1);
}

static int mc_disable_buffering(void)
{
    int err;

    if (!buffering_enabled) {
		goto out;
	}

    mc_suspend_buffering();

    if (qdisc && sock && (err = rtnl_qdisc_delete(sock, (void *) qdisc)) < 0) {
        fprintf(stderr, "Unable to release indefinite: %s\n", nl_geterror(err));
    }

out:
    buffering_enabled = 0;
    qdisc = NULL;
    sock = NULL;
    tc = NULL;
    link_cache = NULL;
    ops = NULL;
    tm = NULL;

    DPRINTF("Buffering disabled.\n");

    return 0;
}

/*
 * Install a Qdisc plug for micro-checkpointing. 
 * If it exists already (say, from a previous dead VM or debugging
 * session) then just open all the netlink data structures pointing 
 * to the existing plug so that we can continue to manipulate it.
 */
int mc_enable_buffering(void)
{
    char dev[MC_DEV_NAME_MAX_SIZE], buffer_dev[MC_DEV_NAME_MAX_SIZE];
    int prefix_len = strlen(NIC_PREFIX);
    int buffer_prefix_len = strlen(BUFFER_NIC_PREFIX);

    if(buffering_enabled) {
        fprintf(stderr, "Buffering already enabled. Skipping.\n");
        return 0;
    }

    qemu_foreach_nic(init_mc_nic_buffering, dev);

    if (strncmp(dev, NIC_PREFIX, prefix_len)) {
        fprintf(stderr, "NIC %s does not have prefix %s. Cannot buffer\n",
                        dev, NIC_PREFIX);
        goto failed;
    }

    strcpy(buffer_dev, BUFFER_NIC_PREFIX);
    strncpy(buffer_dev + buffer_prefix_len, 
                dev + prefix_len, strlen(dev) - prefix_len + 1);

    fprintf(stderr, "Initializing buffering for nic %s => %s\n", dev, buffer_dev);

    if(sock == NULL) {
        sock = (struct nl_sock *) nl_cli_alloc_socket(); 
        if (!sock) {
            fprintf(stderr, "MC: failed to allocate netlink socket\n");
            goto failed;
        }
		nl_cli_connect(sock, NETLINK_ROUTE);
    }

    if(qdisc == NULL) {
        qdisc = nl_cli_qdisc_alloc(); 
        if (!qdisc) {
            fprintf(stderr, "MC: failed to allocate netlink qdisc\n");
            goto failed;
        }
        tc = (struct rtnl_tc *) qdisc;
    }

    if(link_cache == NULL) {
		link_cache = nl_cli_link_alloc_cache(sock);
        if (!link_cache) {
            fprintf(stderr, "MC: failed to allocate netlink link_cache\n");
            goto failed;
        }
    }

    nl_cli_tc_parse_dev(tc, link_cache, (char *) buffer_dev);
    nl_cli_tc_parse_parent(tc, (char *) parent);

    if (!rtnl_tc_get_ifindex(tc)) {
        fprintf(stderr, "Qdisc device '%s' does not exist!\n", buffer_dev);
        goto failed;
    }

    if (!rtnl_tc_get_parent(tc)) {
        fprintf(stderr, "Qdisc parent '%s' is not valid!\n", parent);
        goto failed;
    }

    if (rtnl_tc_set_kind(tc, "plug") < 0) {
        fprintf(stderr, "Could not open qdisc plug!\n");
        goto failed;
    }

    if (!(ops = rtnl_tc_get_ops(tc))) {
        fprintf(stderr, "Could not open qdisc plug!\n");
        goto failed;
    }

    if (!(tm = nl_cli_tc_lookup(ops))) {
        fprintf(stderr, "Qdisc plug not supported!\n");
        goto failed;
    }
    
    buffering_enabled = 1;
 
    if (mc_deliver(0) < 0) {
		fprintf(stderr, "First time qdisc create failed.\n");
		goto failed;
    }

    DPRINTF("Buffering enabled, size: %d MB.\n", buffer_size / 1024 / 1024);
   
    if (mc_set_buffer_size(buffer_size) < 0) {
		goto failed;
	}

    if (mc_suspend_buffering() < 0) {
		goto failed;
	}


    return 0;

failed:
    mc_disable_buffering();
    return -EINVAL;
}

int mc_start_buffer(void)
{
    int err;

    if(!buffering_enabled) {
        return -EINVAL;
    }

    if(new_buffer_size != buffer_size) {
        buffer_size = new_buffer_size;
        fprintf(stderr, "GDB setting new buffer size to %d\n", buffer_size);
        if (mc_set_buffer_size(buffer_size) < 0)
            return -EINVAL;
    }
 
    if ((err = rtnl_qdisc_plug_buffer((void *) qdisc)) < 0) {
        fprintf(stderr, "Unable to flush oldest checkpoint: %s\n", nl_geterror(err));
        return -EINVAL;
    }

    DDPRINTF("Inserted checkpoint barrier\n");

    return mc_deliver(1);
}

static int mc_flush_oldest_buffer(void)
{
    int err;

    if(!buffering_enabled)
        return -EINVAL;

    if ((err = rtnl_qdisc_plug_release_one((void *) qdisc)) < 0) {
        fprintf(stderr, "Unable to flush oldest checkpoint: %s\n", nl_geterror(err));
        return -EINVAL;
    }

    DDPRINTF("Flushed oldest checkpoint barrier\n");

    return mc_deliver(1);
}

/*
 * Stop the VM, perform the micro checkpoint,
 * but save the dirty memory into staging memory
 * (buffered_file will sit on it) until
 * we can re-activate the VM as soon as possible.
 */
static int capture_checkpoint(MigrationState *s, QEMUFile *staging)
{
    int ret = 0;
    int64_t start, stop;

    qemu_mutex_lock_iothread();
    vm_stop_force_state(RUN_STATE_CHECKPOINT_VM);
    start = qemu_get_clock_ms(rt_clock);

    /*
     * If buffering is enabled, insert a Qdisc plug here
     * to hold packets for the *next* MC, (not this one,
     * the packets for this one have already been plugged
     * and will be released after the MC has been transmitted.
     */
    mc_start_buffer();
    qemu_reset_buffer(staging);

    qemu_savevm_state_begin(staging, &s->params);
    ret = qemu_file_get_error(s->file);

    if (ret < 0) {
        migrate_set_state(s, MIG_STATE_MC, MIG_STATE_ERROR);
    }

    qemu_savevm_state_complete(staging);

    ret = qemu_file_get_error(s->file);
    if (ret < 0) {
        migrate_set_state(s, MIG_STATE_MC, MIG_STATE_ERROR);
        goto out;
    }

    stop = qemu_get_clock_ms(rt_clock);

    /*
     * MC is safe in buffered_file. Let the VM go.
     */
    vm_start();
    qemu_ftell(staging);
    s->downtime = stop - start;
out:
    qemu_mutex_unlock_iothread();
    return ret;
}

/*
 * Synchronously send a micro-checkpointing command.
 */
static int mc_send(QEMUFile *f, uint32_t request)
{
    int ret = 0;

    qemu_put_be32(f, request);

    ret = qemu_file_get_error(f);
    if (ret) {
        fprintf(stderr, "transaction: send error while sending %u, "
                "bailing: %s\n", request, strerror(-ret));
    }

    qemu_ftell(f);

    return ret;
}

/*
 * Synchronously receive a micro-checkpointing command.
 */
static int mc_recv(QEMUFile *f, uint32_t request)
{
    int ret = 0;
    uint32_t got;

    qemu_reset_buffer(f);

    got = qemu_get_be32(f);

    ret = qemu_file_get_error(f);
    if (ret) {
        fprintf(stderr, "transaction: recv error while expecting %d,"
                " bailing: %s\n", request, strerror(-ret));
    } else {
        if(request != got) {
            fprintf(stderr, "transaction: was expecting %u but got %d instead\n",
                    request, got);
            ret = -EINVAL;
        }
    }

    return ret;
}

int64_t freq = 100;

static int migrate_use_bitworkers(void)
{
    MigrationState *s;

    s = migrate_get_current();

    return s->enabled_capabilities[MIGRATION_CAPABILITY_BITWORKERS];
}

/*
 * Main MC loop. Stop the VM, dump the dirty memory
 * into buffered_file, restart the VM, transmit the MC,
 * and then sleep for 'freq' milliseconds before
 * starting the next MC.
 */
static void *mc_thread(void *opaque)
{
    MigrationState *s = opaque;
    MCParams mc = { .file = s->file };
    int64_t initial_time = qemu_get_clock_ms(rt_clock);
    int ret = 0, fd = qemu_get_fd(s->file);
    QEMUFile *mc_write, *mc_read, *mc_staging = NULL;
    
    if (migrate_use_bitworkers()) {
        DPRINTF("Starting bitmap workers.\n");
        qemu_mutex_lock_iothread();
        migration_bitmap_worker_start(s);
        qemu_mutex_unlock_iothread();
    }

    if (!(mc_write = qemu_fopen_socket(fd, "wb"))) {
        fprintf(stderr, "Failed to setup write MC control\n");
        goto err;
    }

    if (!(mc_read = qemu_fopen_socket(fd, "rb"))) {
        fprintf(stderr, "Failed to setup read MC control\n");
        goto err;
    }

    if (!(mc_staging = qemu_fopen_mc(&mc, "wb"))) {
        fprintf(stderr, "Failed to setup MC staging area\n");
        goto err;
    }

    qemu_realloc_buffer(mc_read, sizeof(uint32_t));
    qemu_realloc_buffer(mc_write, sizeof(uint32_t));

    qemu_set_block(fd);
    socket_set_nodelay(fd);
    /*
     * One ACK from the secondary is required to kick everything off.
     */
    if((ret = mc_recv(mc_read, MC_TRANSACTION_ACK)) < 0)
        goto err;

    while (s->state == MIG_STATE_MC) {
        int64_t current_time = qemu_get_clock_ms(rt_clock);
        int64_t start_time, xmit_start, end_time;
        MChunk * chunk = mc.chunks, *next;

        mc.chunk_total = 0;
        mc.curr_chunk = mc.chunks;
        mc.chunks->read = 0;
        mc.chunks->size = 0;
        mc.chunks->next = NULL;

        assert(mc.chunks);
        acct_clear();
        start_time = qemu_get_clock_ms(rt_clock);

        if (capture_checkpoint(s, mc_staging) < 0)
                break;

        xmit_start = qemu_get_clock_ms(rt_clock);
        s->bytes_xfer = qemu_ftell(mc_staging);

        DDPRINTF("MC: Buffer has %" PRId64 " bytes in it, took %" PRId64 "ms\n",
                        s->bytes_xfer, s->downtime);

        /*
         * The MC is safe, and VM is running again. 
         * Start a transaction and send it.
         */
        if ((ret = mc_send(mc_write, MC_TRANSACTION_COMMIT) < 0))
            break;

        DDPRINTF("Sending checkpoint size %" PRId64 "\n", s->bytes_xfer);

        qemu_put_be32(mc_write, s->bytes_xfer);
        qemu_ftell(mc_write);
        
        ret = 1;
        while(chunk && chunk->size) {
            int total = 0;
            next = chunk->next;
            while(total != chunk->size) { 
                if(ret > 0) {
                    ret = qemu_send_full(fd, chunk->buf + total, chunk->size -
                                            total, 0);
                    if(ret > 0) {
                        total += ret;
                    }
                    DDPRINTF("Sent %d chunk %ld total %d all %ld\n", 
                            ret, chunk->size, total, s->bytes_xfer);
                } 
                if(ret <= 0) {
                    DDPRINTF("failed, skipping send\n");
                    break;
                }
            }

            if(chunk == mc.chunks) {
                chunk->next = NULL;
                chunk->size = 0;
                chunk->read = 0;
            } else
                g_free(chunk);

            chunk = next;
        }

        if(ret <= 0) {
            fprintf(stderr, "Error sending checkpoint: %d\n", ret);
            goto err;
        }

        if (qemu_file_get_error(s->file)) {
            goto err;
        }

        DDPRINTF("Waiting for commit ACK\n");
        if ((ret = mc_recv(mc_read, MC_TRANSACTION_ACK)) < 0)
            goto err;

        /*
         * The MC is safe on the other side now, 
         * go along our merry way and release the network
         * packets from the buffer if enabled.
         */
        mc_flush_oldest_buffer();

        end_time = qemu_get_clock_ms(rt_clock);
        s->total_time = end_time - start_time;
        s->xmit_time = end_time - xmit_start;
        s->bitmap_time = norm_mig_bitmap_time();
        s->log_dirty_time = norm_mig_log_dirty_time();
        s->ram_copy_time = norm_mig_ram_copy_time();

        if (current_time >= initial_time + 1000) {
            DDPRINTF("bytes %" PRIu64 " xmit_mbps %0.1f xmit_time %" PRId64
                    " downtime %" PRIu64 " sync_time %" PRId64 
                    " logdirty_time %" PRId64 " ram_copy_time %" PRId64 
                    " copy_mbps %0.1f\n",
                    s->bytes_xfer, 
                    MBPS(s->bytes_xfer, s->xmit_time), 
                    s->xmit_time, 
                    s->downtime, s->bitmap_time,
                    s->log_dirty_time, 
                    s->ram_copy_time, 
                    MBPS(s->bytes_xfer, s->ram_copy_time));
            initial_time = current_time;
        }

        /*
         * Checkpoint frequency in microseconds.
         */
        g_usleep(freq * 1000);
    }

    goto out;

err:
    migrate_set_state(s, MIG_STATE_MC, MIG_STATE_ERROR);
out:
    if(mc_staging) {
        qemu_fclose(mc_staging);
    }

    mc_disable_buffering();

    qemu_mutex_lock_iothread();

    if (migrate_use_bitworkers()) {
        DPRINTF("Stopping bitmap workers.\n");
        migration_bitmap_worker_stop(s);
    }

    if(s->state != MIG_STATE_ERROR) {
        migrate_set_state(s, MIG_STATE_MC, MIG_STATE_COMPLETED);
    }

    qemu_bh_schedule(s->cleanup_bh);
    qemu_mutex_unlock_iothread();

    return NULL;
}

void mc_process_incoming_checkpoints_if_requested(QEMUFile *f)
{
    MCParams mc = { .file = f };
    int fd = qemu_get_fd(f);
    QEMUFile *mc_read, *mc_write, *mc_staging;

    if(!mc_requested) {
        DPRINTF("Source has not requested MC. Returning.\n");
        return;
    }
    
    if (!(mc_write = qemu_fopen_socket(fd, "wb"))) {
        fprintf(stderr, "Could not make incoming MC control channel\n");
        goto rollback;
    }

    if (!(mc_read = qemu_fopen_socket(fd, "rb"))) {
        fprintf(stderr, "Could not make outgoing MC control channel\n");
        goto rollback;
    }

    if (!(mc_staging = qemu_fopen_mc(&mc, "rb"))) {
        fprintf(stderr, "Could not make outgoing MC staging area\n");
        goto rollback;
    }

    //socket_set_block(fd);
    socket_set_nodelay(fd);

    qemu_realloc_buffer(mc_read, sizeof(uint32_t));
    qemu_realloc_buffer(mc_write, sizeof(uint32_t));

    DPRINTF("Signaling ready to primary\n");

    if (mc_send(mc_write, MC_TRANSACTION_ACK) < 0)
        goto rollback;

    while(true) {
        int64_t start_time, end_time;
        uint32_t checkpoint_size = 0;
        int received = 0, got;
        MChunk * chunk = mc.chunks;

        mc.chunk_total = 0;
        mc.chunks->read = 0;
        mc.chunks->size = 0;
        mc.chunks->next = NULL;

        DDPRINTF("Waiting for next transaction\n");
        if(mc_recv(mc_read, MC_TRANSACTION_COMMIT) < 0)
            goto rollback;

        start_time = qemu_get_clock_ms(rt_clock);

        checkpoint_size = qemu_get_be32(mc_read);

        if(checkpoint_size == 0) {
                fprintf(stderr, "Empty checkpoint? huh?\n");
                goto rollback;
        }

        DDPRINTF("Transaction start: size %d\n", checkpoint_size);

        while(received < checkpoint_size) {
            int total = 0;
            chunk->size = MIN((checkpoint_size - received), MC_BUFFER_SIZE_MAX);
            mc.chunk_total += chunk->size;

            while(total != chunk->size) {
                got = qemu_recv(fd, chunk->buf + total, chunk->size - total, 0);
                if(got <= 0) {
                    fprintf(stderr, "Error pre-filling checkpoint: %d\n", got);
                    goto rollback;
                }
                DDPRINTF("Received %d chunk %d / %ld received %d total %d\n", 
                        got, total, chunk->size, received, checkpoint_size);
                received += got;
                total += got;
            }

            if(received != checkpoint_size) {
                DDPRINTF("adding chunk to received checkpoint\n");
                chunk->next = g_malloc(sizeof(MChunk));
                chunk = chunk->next;
                chunk->size = 0;
                chunk->read = 0;
                chunk->next = NULL;
            }
        }

        DDPRINTF("Acknowledging successful commit\n");

        if(mc_send(mc_write, MC_TRANSACTION_ACK) < 0)
            goto rollback;
        
        mc.curr_chunk = mc.chunks;

        DDPRINTF("Committed. Loading MC state\n");
        if (qemu_loadvm_state(mc_staging) < 0) {
            fprintf(stderr, "loadvm transaction failed\n");
            goto err;
        }
        end_time = qemu_get_clock_ms(rt_clock);
        DDPRINTF("Transaction complete %" PRId64 " ms\n", end_time - start_time);
        end_time += 0;
        start_time += 0;
    }

rollback:
    fprintf(stderr, "MC: checkpoint stopped. Recovering VM\n");
    return;

err:
    fprintf(stderr, "Micro Checkpointing Protocol Failed\n");
    exit(1);  
}

static int mc_get_buffer(void *opaque, uint8_t *buf, int64_t pos, int size)
{
    MCParams *mc = opaque;
    MChunk *chunk = mc->curr_chunk, *next;
    uint64_t len = size;
    uint8_t *data = (uint8_t *) buf;

    while(len && chunk) {
        uint64_t remaining = chunk->size - chunk->read;
        uint64_t get = MIN(remaining, len);

        memcpy(data, chunk->buf + chunk->read, get);

        data += get;
        chunk->read += get;
        mc->chunk_total -= get;
        len -= get;

        DDPRINTF("got: %" PRIu64 " read: %" PRIu64 " remaining: %" PRIu64
                " this chunk %" PRIu64 " total %" PRIu64 "\n", 
                get, chunk->read, len, remaining, mc->chunk_total);

        next = chunk->next;

        if(chunk->read == chunk->size) {
            if(chunk == mc->chunks) {
                    chunk->next = NULL;
                    chunk->size = 0;
                    chunk->read = 0;
            } else {
                DDPRINTF("Shrinking chunks by one\n");
                g_free(chunk);
            }
            mc->curr_chunk = NULL;
        }

        if(len) {
            mc->curr_chunk = chunk = next;
        }
    }

    DDPRINTF("Returning %" PRIu64 " / %d bytes\n", size - len, size);

    return size - len;
}

static int mc_put_buffer(void *opaque, const uint8_t *buf, int64_t pos, int size)
{
    MCParams *mc = opaque;
    MChunk *chunk = mc->curr_chunk;
    uint64_t len = size;
    uint8_t *data = (uint8_t *) buf;
 
    assert(chunk && mc->chunks);

    while(len) {
        uint64_t room = MC_BUFFER_SIZE_MAX - chunk->size;
        uint64_t put = MIN(room, len);

        memcpy(chunk->buf + chunk->size, data, put);

        data += put;
        chunk->size += put;
        len -= put;
        mc->chunk_total += put;

        DDPRINTF("put: %" PRIu64 " remaining: %" PRIu64 
                " room %" PRIu64 " total %" PRIu64 "\n", 
                put, len, room, mc->chunk_total);

        if(len) {
            DDPRINTF("Extending chunks by one\n");
            mc->curr_chunk = g_malloc(sizeof(MChunk));
            mc->curr_chunk->size = 0;
            mc->curr_chunk->read = 0;
            mc->curr_chunk->next = NULL;
            chunk->next = mc->curr_chunk;
            chunk = mc->curr_chunk;
        }
    }

    return size;
}
       
static int mc_get_fd(void *opaque)
{
    MCParams *mc = opaque;

    return qemu_get_fd(mc->file);
}

static int mc_close(void *opaque)
{
    MCParams *mc = opaque;
    MChunk *chunk = mc->chunks;
    MChunk *next;

    assert(chunk);

    while(chunk) {
        next = chunk->next;
        g_free(chunk);
        chunk = next;
    }

    mc->curr_chunk = NULL;
    mc->chunks = NULL;

    return 0;
}
	
static const QEMUFileOps mc_write_ops = {
    .put_buffer = mc_put_buffer,
    .get_fd = mc_get_fd,
    .close = mc_close,
};

static const QEMUFileOps mc_read_ops = {
    .get_buffer = mc_get_buffer,
    .get_fd = mc_get_fd,
    .close = mc_close,
};

QEMUFile *qemu_fopen_mc(void *opaque, const char *mode)
{
    MCParams *mc = opaque;

    if (qemu_file_mode_is_not_valid(mode))
        return NULL;

    mc->chunks = g_malloc(sizeof(MChunk));
    mc->chunks->size = 0;
    mc->chunks->read = 0;
    mc->chunks->next = NULL;
    mc->chunk_total = 0; 
    mc->curr_chunk = mc->chunks;

    if (mode[0] == 'w') {
        return qemu_fopen_ops(mc, &mc_write_ops);
    }

    return qemu_fopen_ops(mc, &mc_read_ops);
}

static void mc_start_checkpointer(void *opaque) {
    MigrationState *s = opaque;

    if(checkpoint_bh) {
        qemu_bh_delete(checkpoint_bh);
        checkpoint_bh = NULL;
    }

    qemu_mutex_unlock_iothread();
    qemu_thread_join(s->thread);
    qemu_mutex_lock_iothread();

    migrate_set_state(s, MIG_STATE_ACTIVE, MIG_STATE_MC);
	qemu_thread_create(s->thread, mc_thread, s, QEMU_THREAD_DETACHED);
}

void mc_init_checkpointer(MigrationState *s)
{
    checkpoint_bh = qemu_bh_new(mc_start_checkpointer, s);
    qemu_bh_schedule(checkpoint_bh);
}

void qmp_migrate_set_mc_delay(int64_t value, Error **errp)
{
    freq = value;
    DPRINTF("Setting checkpoint frequency to %" PRId64 " milliseconds\n", value);
}

int mc_info_load(QEMUFile *f, void *opaque, int version_id)
{
    bool enabled = qemu_get_byte(f);

    if(enabled && !mc_requested) {
        DPRINTF("MC is requested\n");
        mc_requested = true;
    }

    return 0;
}

void mc_info_save(QEMUFile *f, void *opaque)
{
    qemu_put_byte(f, migrate_use_mc());
}
