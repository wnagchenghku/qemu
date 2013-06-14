/*
 * RDMA protocol and interfaces
 *
 * Copyright IBM, Corp. 2010-2013
 *
 * Authors:
 *  Michael R. Hines <mrhines@us.ibm.com>
 *  Jiuxing Liu <jl@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */
#include "qemu-common.h"
#include "migration/migration.h"
#include "migration/qemu-file.h"
#include "exec/cpu-common.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include "block/coroutine.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <rdma/rdma_cma.h>

//#define DEBUG_RDMA
//#define DEBUG_RDMA_VERBOSE
//#define DEBUG_RDMA_REALLY_VERBOSE

#ifdef DEBUG_RDMA
#define DPRINTF(fmt, ...) \
    do { printf("rdma: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_RDMA_VERBOSE
#define DDPRINTF(fmt, ...) \
    do { printf("rdma: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DDPRINTF(fmt, ...) \
    do { } while (0)
#endif

#ifdef DEBUG_RDMA_REALLY_VERBOSE
#define DDDPRINTF(fmt, ...) \
    do { printf("rdma: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DDDPRINTF(fmt, ...) \
    do { } while (0)
#endif

/*
 * Print and error on both the Monitor and the Log file.
 */
#define ERROR(errp, fmt, ...) \
    do { \
        fprintf(stderr, "RDMA ERROR: " fmt, ## __VA_ARGS__); \
        if (errp && (*(errp) == NULL)) { \
            error_setg(errp, "RDMA ERROR: " fmt, ## __VA_ARGS__); \
        } \
    } while (0)

#define RDMA_RESOLVE_TIMEOUT_MS 10000

/* Do not merge data if larger than this. */
#define RDMA_MERGE_MAX (2 * 1024 * 1024)
#define RDMA_SIGNALED_SEND_MAX (RDMA_MERGE_MAX / 4096)

#define RDMA_REG_CHUNK_SHIFT 20 /* 1 MB */

/*
 * This is only for non-live state being migrated.
 * Instead of RDMA_WRITE messages, we use RDMA_SEND
 * messages for that state, which requires a different
 * delivery design than main memory.
 */
#define RDMA_SEND_INCREMENT 32768

/*
 * Maximum size infiniband SEND message
 */
#define RDMA_CONTROL_MAX_BUFFER (512 * 1024)
#define RDMA_CONTROL_MAX_WR 2
#define RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE 4096

/*
 * Capabilities for negotiation.
 */
#define RDMA_CAPABILITY_PIN_ALL 0x01

/*
 * Add the other flags above to this list of known capabilities
 * as they are introduced.
 */
static uint32_t known_capabilities = RDMA_CAPABILITY_PIN_ALL;

#define CHECK_ERROR_STATE() \
    do { \
        if (rdma->error_state) { \
            if (!rdma->error_reported) { \
                fprintf(stderr, "RDMA is in an error state waiting migration" \
                                " to abort!\n"); \
                rdma->error_reported = 1; \
            } \
            return rdma->error_state; \
        } \
    } while (0);
/*
 * RDMA migration protocol:
 * 1. RDMA Writes (data messages, i.e. RAM)
 * 2. IB Send/Recv (control channel messages)
 */
#define RDMA_WRITE_START 1
#define RDMA_SEND_CONTROL 20000
#define RDMA_RECV_CONTROL 40000

enum {
    RDMA_WRID_NONE = 0,
    RDMA_WRID_RDMA_WRITE_START = RDMA_WRITE_START,
    RDMA_WRID_SEND_CONTROL = RDMA_SEND_CONTROL,
    RDMA_WRID_RECV_CONTROL = RDMA_RECV_CONTROL,
};

#define RDMA_WRID_RDMA_WRITE_STOP \
    (RDMA_WRITE_START + (RDMA_SIGNALED_SEND_MAX - 1))

#if RDMA_WRID_RDMA_WRITE_STOP >= RDMA_SEND_CONTROL
#error "RDMA Compile Error: RDMA_SIGNALED_SEND_MAX is too large."
#endif

const char *wrid_desc[] = {
        [RDMA_WRID_NONE] = "NONE",
        [RDMA_WRID_RDMA_WRITE_START] = "WRITE RDMA",
        [RDMA_WRID_SEND_CONTROL] = "CONTROL SEND",
        [RDMA_WRID_RECV_CONTROL] = "CONTROL RECV",
};

/*
 * SEND/RECV IB Control Messages.
 */
enum {
    RDMA_CONTROL_NONE = 0,
    RDMA_CONTROL_ERROR,
    RDMA_CONTROL_READY,              /* ready to receive */
    RDMA_CONTROL_QEMU_FILE,          /* QEMUFile-transmitted bytes */
    RDMA_CONTROL_RAM_BLOCKS_REQUEST, /* RAMBlock synchronization */
    RDMA_CONTROL_RAM_BLOCKS_RESULT,  /* RAMBlock synchronization */
    RDMA_CONTROL_COMPRESS,           /* page contains repeat values */
    RDMA_CONTROL_REGISTER_REQUEST,   /* dynamic page registration */
    RDMA_CONTROL_REGISTER_RESULT,    /* key to use after registration */
    RDMA_CONTROL_REGISTER_FINISHED,  /* current iteration finished */
};

const char *control_desc[] = {
        [RDMA_CONTROL_NONE] = "NONE",
        [RDMA_CONTROL_ERROR] = "ERROR",
        [RDMA_CONTROL_READY] = "READY",
        [RDMA_CONTROL_QEMU_FILE] = "QEMU FILE",
        [RDMA_CONTROL_RAM_BLOCKS_REQUEST] = "RAM BLOCKS REQUEST",
        [RDMA_CONTROL_RAM_BLOCKS_RESULT] = "RAM BLOCKS RESULT",
        [RDMA_CONTROL_COMPRESS] = "COMPRESS",
        [RDMA_CONTROL_REGISTER_REQUEST] = "REGISTER REQUEST",
        [RDMA_CONTROL_REGISTER_RESULT] = "REGISTER RESULT",
        [RDMA_CONTROL_REGISTER_FINISHED] = "REGISTER FINISHED",
};

/*
 * Memory and MR structures used to represent an IB Send/Recv work request.
 * This is *not* used for RDMA, only IB Send/Recv.
 */
typedef struct {
    uint8_t  control[RDMA_CONTROL_MAX_BUFFER]; /* actual buffer to register */
    struct   ibv_mr *control_mr;               /* registration metadata */
    size_t   control_len;                      /* length of the message */
    uint8_t *control_curr;                     /* start of unconsumed bytes */
} RDMAWorkRequestData;

/*
 * Negotiate RDMA capabilities during connection-setup time.
 */
typedef struct {
    uint32_t version;
    uint32_t flags;
} RDMACapabilities;

static void caps_to_network(RDMACapabilities *cap)
{
    cap->version = htonl(cap->version);
    cap->flags = htonl(cap->flags);
}

static void network_to_caps(RDMACapabilities *cap)
{
    cap->version = ntohl(cap->version);
    cap->flags = ntohl(cap->flags);
}

/*
 * Representation of a RAMBlock from an RDMA perspective.
 * This is not transmitted, only local.
 * This and subsequent structures cannot be linked lists
 * because we're using a single IB message to transmit
 * the information. It's small anyway, so a list is overkill.
 */
typedef struct RDMALocalBlock {
    uint8_t  *local_host_addr; /* local virtual address */
    uint64_t remote_host_addr; /* remote virtual address */
    uint64_t offset;
    uint64_t length;
    struct   ibv_mr **pmr;     /* MRs for chunk-level registration */
    struct   ibv_mr *mr;       /* MR for non-chunk-level registration */
    uint32_t *remote_keys;     /* rkeys for chunk-level registration */
    uint32_t remote_rkey;      /* rkeys for non-chunk-level registration */
    int      index;            /* which block are we */
} RDMALocalBlock;

/*
 * Also represents a RAMblock, but only on the dest.
 * This gets transmitted by the dest during connection-time
 * to the source / primary VM and then is used to populate the
 * corresponding RDMALocalBlock with
 * the information needed to perform the actual RDMA.
 */
typedef struct QEMU_PACKED RDMARemoteBlock {
    uint64_t remote_host_addr;
    uint64_t offset;
    uint64_t length;
    uint32_t remote_rkey;
    uint32_t padding;
} QEMU_PACKED RDMARemoteBlock;

/*
 * Virtual address of the above structures used for transmitting
 * the RAMBlock descriptions at connection-time.
 * This structure is *not* transmitted.
 */
typedef struct RDMALocalBlocks {
    int num_blocks;
    RDMALocalBlock *block;
} RDMALocalBlocks;

typedef struct RDMATransit {
    uintptr_t addr;
    int64_t len;
} RDMATransit;

/*
 * Main data structure for RDMA state.
 * While there is only one copy of this structure being allocated right now,
 * this is the place where one would start if you wanted to consider
 * having more than one RDMA connection open at the same time.
 */
typedef struct RDMAContext {
    char *host;
    int port;

    /* This is used by the migration protocol to transmit
     * control messages (such as device state and registration commands)
     *
     * WR #0 is for control channel ready messages from the destination.
     * WR #1 is for control channel data messages from the destination.
     * WR #2 is for control channel send messages.
     *
     * We could use more WRs, but we have enough for now.
     */
    RDMAWorkRequestData wr_data[RDMA_CONTROL_MAX_WR + 1];

    /*
     * This is used by *_exchange_send() to figure out whether or not
     * the initial "READY" message has already been received or not.
     * This is because other functions may potentially poll() and detect
     * the READY message before send() does, in which case we need to
     * know if it completed.
     */
    int control_ready_expected;

    /* number of outstanding signaled send */
    int num_signaled_send;

    /* store info about current buffer so that we can
       merge it with future sends */
    uint64_t current_offset;
    uint64_t current_length;
    /* index of ram block the current buffer belongs to */
    int current_index;
    /* index of the chunk in the current ram block */
    int current_chunk;

    bool pin_all;

    /*
     * infiniband-specific variables for opening the device
     * and maintaining connection state and so forth.
     *
     * cm_id also has ibv_context, rdma_event_channel, and ibv_qp in
     * cm_id->verbs, cm_id->channel, and cm_id->qp.
     */
    struct rdma_cm_id *cm_id;               /* connection manager ID */
    struct rdma_cm_id *listen_id;

    struct ibv_context *verbs;
    struct rdma_event_channel *channel;
    struct ibv_qp *qp;                      /* queue pair */
    struct ibv_comp_channel *comp_channel;  /* completion channel */
    struct ibv_pd *pd;                      /* protection domain */
    struct ibv_cq *cq;                      /* completion queue */

    /*
     * If a previous write failed (perhaps because of a failed
     * memory registration, then do not attempt any future work
     * and remember the error state.
     */
    int error_state;
    int error_reported;

    /*
     * Description of ram blocks used throughout the code.
     */
    RDMALocalBlocks local_ram_blocks;
    RDMARemoteBlock *block;

    /*
     * Migration on *destination* started.
     * Then use coroutine yield function.
     * Source runs in a thread, so we don't care.
     */
    int migration_started_on_destination;

    int total_registrations;

    /*
     * Circular array holding outsanding signaled work requests
     * used to detect whether or not a chunk is "in transit"
     * for an RDMA operation. Since RDMA operations can happen
     * out of order, we cannot issue a new operation unless a previous
     * operation for the same chunk start address has already completed.
     */
    RDMATransit in_transit[RDMA_SIGNALED_SEND_MAX];
    int nb_transit;
} RDMAContext;

/*
 * Interface to the rest of the migration call stack.
 */
typedef struct QEMUFileRDMA {
    RDMAContext *rdma;
    size_t len;
    void *file;
} QEMUFileRDMA;

#define RDMA_CONTROL_VERSION_CURRENT 1

/*
 * Main structure for IB Send/Recv control messages.
 * This gets prepended at the beginning of every Send/Recv.
 */
typedef struct QEMU_PACKED {
    uint32_t len;     /* Total length of data portion */
    uint32_t type;    /* which control command to perform */
    uint32_t repeat;  /* number of commands in data portion of same type */
    uint32_t padding;
} QEMU_PACKED RDMAControlHeader;

static void control_to_network(RDMAControlHeader *control)
{
    control->type = htonl(control->type);
    control->len = htonl(control->len);
    control->repeat = htonl(control->repeat);
}

static void network_to_control(RDMAControlHeader *control)
{
    control->type = ntohl(control->type);
    control->len = ntohl(control->len);
    control->repeat = ntohl(control->repeat);
}

/*
 * Register a single Chunk.
 * Information sent by the primary VM to inform the dest
 * to register an single chunk of memory before we can perform
 * the actual RDMA operation.
 */
typedef struct QEMU_PACKED {
    uint32_t len;           /* length of the chunk to be registered */
    uint32_t current_index; /* which ramblock the chunk belongs to */
    uint64_t offset;        /* offset into the ramblock of the chunk */
} QEMU_PACKED RDMARegister;

typedef struct QEMU_PACKED {
    uint32_t value;     /* if zero, we will madvise() */
    uint32_t block_idx; /* which ram block index */
    uint64_t offset;    /* where in the remote ramblock this chunk */
    uint64_t length;    /* length of the chunk */
} QEMU_PACKED RDMACompress;

/*
 * The result of the dest's memory registration produces an "rkey"
 * which the primary VM must reference in order to perform
 * the RDMA operation.
 */
typedef struct QEMU_PACKED {
    uint32_t rkey;
    uint32_t padding;
} QEMU_PACKED RDMARegisterResult;

static inline uint64_t ram_chunk_index(uint8_t *start, uint8_t *host)
{
    return ((uintptr_t) host - (uintptr_t) start) >> RDMA_REG_CHUNK_SHIFT;
}

static inline uint64_t ram_chunk_count(RDMALocalBlock *rdma_ram_block)
{
    return ram_chunk_index(rdma_ram_block->local_host_addr,
        rdma_ram_block->local_host_addr + rdma_ram_block->length) + 1UL;
}

static inline uint8_t *ram_chunk_start(RDMALocalBlock *rdma_ram_block,
                                       uint64_t i)
{
    return (uint8_t *) (((uintptr_t) rdma_ram_block->local_host_addr)
                                    + (i << RDMA_REG_CHUNK_SHIFT));
}

static inline uint8_t *ram_chunk_end(RDMALocalBlock *rdma_ram_block, uint64_t i)
{
    uint8_t *result = ram_chunk_start(rdma_ram_block, i) +
                                         (1UL << RDMA_REG_CHUNK_SHIFT);

    if (result > (rdma_ram_block->local_host_addr + rdma_ram_block->length)) {
        result = rdma_ram_block->local_host_addr + rdma_ram_block->length;
    }

    return result;
}


/*
 * Memory regions need to be registered with the device and queue pairs setup
 * in advanced before the migration starts. This tells us where the RAM blocks
 * are so that we can register them individually.
 */
static void qemu_rdma_init_one_block(void *host_addr,
    ram_addr_t offset, ram_addr_t length, void *opaque)
{
    RDMALocalBlocks *rdma_local_ram_blocks = opaque;
    int num_blocks = rdma_local_ram_blocks->num_blocks;

    rdma_local_ram_blocks->block[num_blocks].local_host_addr = host_addr;
    rdma_local_ram_blocks->block[num_blocks].offset = (uint64_t)offset;
    rdma_local_ram_blocks->block[num_blocks].length = (uint64_t)length;
    rdma_local_ram_blocks->block[num_blocks].index = num_blocks;

    DPRINTF("Block: %d, addr: %" PRIu64 ", offset: %" PRIu64
           " length: %" PRIu64 " end: %" PRIu64 "\n",
            num_blocks, (uint64_t) host_addr, offset, length,
            (uint64_t) (host_addr + length));

    rdma_local_ram_blocks->num_blocks++;

}

static void qemu_rdma_ram_block_counter(void *host_addr,
            ram_addr_t offset, ram_addr_t length, void *opaque)
{
    int *num_blocks = opaque;
    *num_blocks = *num_blocks + 1;
}

/*
 * Identify the RAMBlocks and their quantity. They will be references to
 * identify chunk boundaries inside each RAMBlock and also be referenced
 * during dynamic page registration.
 */
static int qemu_rdma_init_ram_blocks(RDMALocalBlocks *rdma_local_ram_blocks)
{
    int num_blocks = 0;

    qemu_ram_foreach_block(qemu_rdma_ram_block_counter, &num_blocks);

    memset(rdma_local_ram_blocks, 0, sizeof *rdma_local_ram_blocks);
    rdma_local_ram_blocks->block = g_malloc0(sizeof(RDMALocalBlock) *
                                    num_blocks);

    rdma_local_ram_blocks->num_blocks = 0;
    qemu_ram_foreach_block(qemu_rdma_init_one_block, rdma_local_ram_blocks);

    DPRINTF("Allocated %d local ram block structures\n",
                    rdma_local_ram_blocks->num_blocks);
    return 0;
}

/*
 * Put in the log file which RDMA device was opened and the details
 * associated with that device.
 */
static void qemu_rdma_dump_id(const char *who, struct ibv_context *verbs)
{
    printf("%s RDMA Device opened: kernel name %s "
           "uverbs device name %s, "
           "infiniband_verbs class device path %s,"
           " infiniband class device path %s\n",
                who,
                verbs->device->name,
                verbs->device->dev_name,
                verbs->device->dev_path,
                verbs->device->ibdev_path);
}

/*
 * Put in the log file the RDMA gid addressing information,
 * useful for folks who have trouble understanding the
 * RDMA device hierarchy in the kernel.
 */
static void qemu_rdma_dump_gid(const char *who, struct rdma_cm_id *id)
{
    char sgid[33];
    char dgid[33];
    inet_ntop(AF_INET6, &id->route.addr.addr.ibaddr.sgid, sgid, sizeof sgid);
    inet_ntop(AF_INET6, &id->route.addr.addr.ibaddr.dgid, dgid, sizeof dgid);
    DPRINTF("%s Source GID: %s, Dest GID: %s\n", who, sgid, dgid);
}

/*
 * Figure out which RDMA device corresponds to the requested IP hostname
 * Also create the initial connection manager identifiers for opening
 * the connection.
 */
static int qemu_rdma_resolve_host(RDMAContext *rdma, Error **errp)
{
    int ret;
    struct addrinfo *res;
    char port_str[16];
    struct rdma_cm_event *cm_event;
    char ip[40] = "unknown";

    if (rdma->host == NULL || !strcmp(rdma->host, "")) {
        ERROR(errp, "RDMA hostname has not been set\n");
        return -1;
    }

    /* create CM channel */
    rdma->channel = rdma_create_event_channel();
    if (!rdma->channel) {
        ERROR(errp, "could not create CM channel\n");
        return -1;
    }

    /* create CM id */
    ret = rdma_create_id(rdma->channel, &rdma->cm_id, NULL, RDMA_PS_TCP);
    if (ret) {
        ERROR(errp, "could not create channel id\n");
        goto err_resolve_create_id;
    }

    snprintf(port_str, 16, "%d", rdma->port);
    port_str[15] = '\0';

    ret = getaddrinfo(rdma->host, port_str, NULL, &res);
    if (ret < 0) {
        ERROR(errp, "could not getaddrinfo address %s\n", rdma->host);
        goto err_resolve_get_addr;
    }

    inet_ntop(AF_INET, &((struct sockaddr_in *) res->ai_addr)->sin_addr,
                                ip, sizeof ip);
    DPRINTF("%s => %s\n", rdma->host, ip);

    /* resolve the first address */
    ret = rdma_resolve_addr(rdma->cm_id, NULL, res->ai_addr,
            RDMA_RESOLVE_TIMEOUT_MS);
    if (ret) {
        ERROR(errp, "could not resolve address %s\n", rdma->host);
        goto err_resolve_get_addr;
    }

    qemu_rdma_dump_gid("source_resolve_addr", rdma->cm_id);

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        ERROR(errp, "could not perform event_addr_resolved\n");
        goto err_resolve_get_addr;
    }

    if (cm_event->event != RDMA_CM_EVENT_ADDR_RESOLVED) {
        ERROR(errp, "result not equal to event_addr_resolved %s\n",
                rdma_event_str(cm_event->event));
        perror("rdma_resolve_addr");
        goto err_resolve_get_addr;
    }
    rdma_ack_cm_event(cm_event);

    /* resolve route */
    ret = rdma_resolve_route(rdma->cm_id, RDMA_RESOLVE_TIMEOUT_MS);
    if (ret) {
        ERROR(errp, "could not resolve rdma route\n");
        goto err_resolve_get_addr;
    }

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        ERROR(errp, "could not perform event_route_resolved\n");
        goto err_resolve_get_addr;
    }
    if (cm_event->event != RDMA_CM_EVENT_ROUTE_RESOLVED) {
        ERROR(errp, "result not equal to event_route_resolved: %s\n",
                        rdma_event_str(cm_event->event));
        rdma_ack_cm_event(cm_event);
        goto err_resolve_get_addr;
    }
    rdma_ack_cm_event(cm_event);
    rdma->verbs = rdma->cm_id->verbs;
    qemu_rdma_dump_id("source_resolve_host", rdma->cm_id->verbs);
    qemu_rdma_dump_gid("source_resolve_host", rdma->cm_id);
    return 0;

err_resolve_get_addr:
    rdma_destroy_id(rdma->cm_id);
    rdma->cm_id = 0;
err_resolve_create_id:
    rdma_destroy_event_channel(rdma->channel);
    rdma->channel = NULL;

    return -1;
}

/*
 * Create protection domain and completion queues
 */
static int qemu_rdma_alloc_pd_cq(RDMAContext *rdma)
{
    /* allocate pd */
    rdma->pd = ibv_alloc_pd(rdma->verbs);
    if (!rdma->pd) {
        fprintf(stderr, "failed to allocate protection domain\n");
        return -1;
    }

    /* create completion channel */
    rdma->comp_channel = ibv_create_comp_channel(rdma->verbs);
    if (!rdma->comp_channel) {
        fprintf(stderr, "failed to allocate completion channel\n");
        goto err_alloc_pd_cq;
    }

    /*
     * Completion queue can be filled by both read and write work requests,
     * so must reflect the sum of both possible queue sizes.
     */
    rdma->cq = ibv_create_cq(rdma->verbs, (RDMA_SIGNALED_SEND_MAX * 3),
            NULL, rdma->comp_channel, 0);
    if (!rdma->cq) {
        fprintf(stderr, "failed to allocate completion queue\n");
        goto err_alloc_pd_cq;
    }

    return 0;

err_alloc_pd_cq:
    if (rdma->pd) {
        ibv_dealloc_pd(rdma->pd);
    }
    if (rdma->comp_channel) {
        ibv_destroy_comp_channel(rdma->comp_channel);
    }
    rdma->pd = NULL;
    rdma->comp_channel = NULL;
    return -1;

}

/*
 * Create queue pairs.
 */
static int qemu_rdma_alloc_qp(RDMAContext *rdma)
{
    struct ibv_qp_init_attr attr = { 0 };
    int ret;

    attr.cap.max_send_wr = RDMA_SIGNALED_SEND_MAX;
    attr.cap.max_recv_wr = 3;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    attr.send_cq = rdma->cq;
    attr.recv_cq = rdma->cq;
    attr.qp_type = IBV_QPT_RC;

    ret = rdma_create_qp(rdma->cm_id, rdma->pd, &attr);
    if (ret) {
        return -1;
    }

    rdma->qp = rdma->cm_id->qp;
    return 0;
}

static int qemu_rdma_reg_whole_ram_blocks(RDMAContext *rdma,
                                RDMALocalBlocks *rdma_local_ram_blocks)
{
    int i;
    uint64_t start = qemu_get_clock_ms(rt_clock);
    (void)start;

    for (i = 0; i < rdma_local_ram_blocks->num_blocks; i++) {
        rdma_local_ram_blocks->block[i].mr =
            ibv_reg_mr(rdma->pd,
                    rdma_local_ram_blocks->block[i].local_host_addr,
                    rdma_local_ram_blocks->block[i].length,
                    IBV_ACCESS_LOCAL_WRITE |
                    IBV_ACCESS_REMOTE_WRITE
                    );
        if (!rdma_local_ram_blocks->block[i].mr) {
            perror("Failed to register local dest ram block!\n");
            break;
        }
        rdma->total_registrations++;
    }

    DPRINTF("lock time: %" PRIu64 "\n", qemu_get_clock_ms(rt_clock) - start);

    if (i >= rdma_local_ram_blocks->num_blocks) {
        return 0;
    }

    for (i--; i >= 0; i--) {
        ibv_dereg_mr(rdma_local_ram_blocks->block[i].mr);
        rdma->total_registrations--;
    }

    return -1;

}

/*
 * Shutdown and clean things up.
 */
static void qemu_rdma_dereg_ram_blocks(RDMAContext *rdma,
                                       RDMALocalBlocks *rdma_local_ram_blocks)
{
    int i, j;
    for (i = 0; i < rdma_local_ram_blocks->num_blocks; i++) {
        int num_chunks;
        if (!rdma_local_ram_blocks->block[i].pmr) {
            continue;
        }
        num_chunks = ram_chunk_count(&(rdma_local_ram_blocks->block[i]));
        for (j = 0; j < num_chunks; j++) {
            if (!rdma_local_ram_blocks->block[i].pmr[j]) {
                continue;
            }
            ibv_dereg_mr(rdma_local_ram_blocks->block[i].pmr[j]);
            rdma->total_registrations--;
        }
        g_free(rdma_local_ram_blocks->block[i].pmr);
        rdma_local_ram_blocks->block[i].pmr = NULL;
    }
    for (i = 0; i < rdma_local_ram_blocks->num_blocks; i++) {
        if (!rdma_local_ram_blocks->block[i].mr) {
            continue;
        }
        ibv_dereg_mr(rdma_local_ram_blocks->block[i].mr);
        rdma->total_registrations--;
        rdma_local_ram_blocks->block[i].mr = NULL;
    }
}

/*
 * The protocol uses two different sets of rkeys (mutually exclusive):
 * 1. One key to represent the virtual address of the entire ram block.
 *    (dynamic chunk registration disabled - pin everything with one rkey.)
 * 2. One to represent individual chunks within a ram block.
 *    (dynamic chunk registration enabled - pin individual chunks.)
 *
 * Once the capability is successfully negotiated, the destination transmits
 * the keys to use (or sends them later) including the virtual addresses
 * and then propagates the remote ram block descriptions to his local copy.
 */
static int qemu_rdma_process_remote_blocks(RDMAContext *rdma, int num_blocks,
                                           Error **errp)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    int i, j;

    if (local->num_blocks != num_blocks) {
        ERROR(errp, "ram blocks mismatch #1! "
                    "Your QEMU command line parameters are probably "
                    "not identical on both the source and destination.\n");
        return -1;
    }

    for (i = 0; i < num_blocks; i++) {
        /* search local ram blocks */
        for (j = 0; j < local->num_blocks; j++) {
            if (rdma->block[i].offset != local->block[j].offset) {
                continue;
            }
            if (rdma->block[i].length != local->block[j].length) {
                ERROR(errp, "ram blocks mismatch #2! "
                            "Your QEMU command line parameters are probably "
                            "not identical on both the source and destination.\n");
                return -1;
            }
            local->block[j].remote_host_addr =
                rdma->block[i].remote_host_addr;
            local->block[j].remote_rkey = rdma->block[i].remote_rkey;
            break;
        }
        if (j >= local->num_blocks) {
            ERROR(errp, "ram blocks mismatch #3! "
                        "Your QEMU command line parameters are probably "
                        "not identical on both the source and destination.\n");
            return -1;
        }
    }

    return 0;
}

/*
 * Find the ram block that corresponds to the page requested to be
 * transmitted by QEMU.
 *
 * Once the block is found, also identify which 'chunk' within that
 * block that the page belongs to.
 *
 * This search cannot fail or the migration will fail.
 */
static int qemu_rdma_search_ram_block(uint64_t offset, uint64_t length,
        RDMALocalBlocks *blocks, int *block_index, int *chunk_index)
{
    int i;
    uint8_t *host_addr;

    for (i = 0; i < blocks->num_blocks; i++) {
        if (offset < blocks->block[i].offset) {
            continue;
        }
        if (offset + length >
                blocks->block[i].offset + blocks->block[i].length) {
            continue;
        }

        *block_index = i;
        host_addr = blocks->block[i].local_host_addr +
                (offset - blocks->block[i].offset);
        *chunk_index = ram_chunk_index(blocks->block[i].local_host_addr,
                        host_addr);
        return 0;
    }
    return -1;
}

/*
 * Register a chunk with IB. If the chunk was already registered
 * previously, then skip.
 *
 * Also return the keys associated with the registration needed
 * to perform the actual RDMA operation.
 */
static int qemu_rdma_register_and_get_keys(RDMAContext *rdma,
        RDMALocalBlock *block, uint8_t * host_addr,
        uint32_t *lkey, uint32_t *rkey)
{
    int chunk;
    if (block->mr) {
        if (lkey) {
            *lkey = block->mr->lkey;
        }
        if (rkey) {
            *rkey = block->mr->rkey;
        }
        return 0;
    }

    /* allocate memory to store chunk MRs */
    if (!block->pmr) {
        int num_chunks = ram_chunk_count(block);
        block->pmr = g_malloc0(num_chunks *
                sizeof(struct ibv_mr *));
        if (!block->pmr) {
            return -1;
        }
    }

    /*
     * If 'rkey', then we're the destination, so grant access to the source.
     *
     * If 'lkey', then we're the primary VM, so grant access only to ourselves.
     */
    chunk = ram_chunk_index(block->local_host_addr, host_addr);
    if (!block->pmr[chunk]) {
        uint8_t *start_addr = ram_chunk_start(block, chunk);
        uint8_t *end_addr = ram_chunk_end(block, chunk);

        block->pmr[chunk] = ibv_reg_mr(rdma->pd,
                start_addr,
                end_addr - start_addr,
                (rkey ? (IBV_ACCESS_LOCAL_WRITE |
                        IBV_ACCESS_REMOTE_WRITE) : 0));

        if (!block->pmr[chunk]) {
            perror("Failed to register chunk!");
            fprintf(stderr, "Chunk details: block: %d chunk index %d"
                            " start %" PRIu64 " end %" PRIu64 " host %" PRIu64
                            " local %" PRIu64 " registrations: %d\n",
                            block->index, chunk, (uint64_t) start_addr,
                            (uint64_t) end_addr, (uint64_t) host_addr,
                            (uint64_t) block->local_host_addr,
                            rdma->total_registrations);
            return -1;
        }
        rdma->total_registrations++;
    }

    if (lkey) {
        *lkey = block->pmr[chunk]->lkey;
    }
    if (rkey) {
        *rkey = block->pmr[chunk]->rkey;
    }
    return 0;
}

/*
 * Register (at connection time) the memory used for control
 * channel messages.
 */
static int qemu_rdma_reg_control(RDMAContext *rdma, int idx)
{
    rdma->wr_data[idx].control_mr = ibv_reg_mr(rdma->pd,
            rdma->wr_data[idx].control, RDMA_CONTROL_MAX_BUFFER,
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (rdma->wr_data[idx].control_mr) {
        rdma->total_registrations++;
        return 0;
    }
    fprintf(stderr, "qemu_rdma_reg_control failed!\n");
    return -1;
}

static int qemu_rdma_dereg_control(RDMAContext *rdma, int idx)
{
    rdma->total_registrations--;
    return ibv_dereg_mr(rdma->wr_data[idx].control_mr);
}

#if defined(DEBUG_RDMA_VERBOSE) && defined(DEBUG_RDMA_REALLY_VERBOSE)
static const char *print_wrid(int wrid)
{
    if (wrid >= RDMA_WRID_RECV_CONTROL) {
        return wrid_desc[RDMA_WRID_RECV_CONTROL];
    } else if (wrid >= RDMA_WRID_RDMA_WRITE_START
                && wrid <= RDMA_WRID_RDMA_WRITE_STOP) {
        return wrid_desc[RDMA_WRID_RDMA_WRITE_START];
    }
    return wrid_desc[wrid];
}
#endif

/*
 * Consult the connection manager to see a work request
 * (of any kind) has completed.
 * Return the work request ID that completed.
 */
static int qemu_rdma_poll(RDMAContext *rdma)
{
    int ret;
    struct ibv_wc wc;

    ret = ibv_poll_cq(rdma->cq, 1, &wc);

    if (!ret) {
        return RDMA_WRID_NONE;
    }

    if (ret < 0) {
        fprintf(stderr, "ibv_poll_cq return %d!\n", ret);
        return ret;
    }

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "ibv_poll_cq wc.status=%d %s!\n",
                        wc.status, ibv_wc_status_str(wc.status));
        fprintf(stderr, "ibv_poll_cq wrid=%s!\n", wrid_desc[wc.wr_id]);

        return -1;
    }

    if (rdma->control_ready_expected &&
        (wc.wr_id >= RDMA_WRID_RECV_CONTROL)) {
        DDDPRINTF("completion %s #%" PRId64 " received (%" PRId64 ")"
                  " left %d\n", wrid_desc[RDMA_WRID_RECV_CONTROL],
                  wc.wr_id - RDMA_WRID_RECV_CONTROL, wc.wr_id,
                  rdma->num_signaled_send);
        rdma->control_ready_expected = 0;
    }

    if ((wc.wr_id >= RDMA_WRID_RDMA_WRITE_START) &&
            (wc.wr_id <= RDMA_WRID_RDMA_WRITE_STOP)) {
        if (rdma->num_signaled_send > 0) {
            rdma->num_signaled_send--;
        }

        DDDPRINTF("completions %s (%" PRId64 ") left %d\n",
            print_wrid(wc.wr_id), wc.wr_id, rdma->num_signaled_send);
        rdma->in_transit[wc.wr_id - RDMA_WRID_RDMA_WRITE_START].addr = 0;
        rdma->in_transit[wc.wr_id - RDMA_WRID_RDMA_WRITE_START].len = 0;
    } else {
        DDDPRINTF("other completion %s (%" PRId64 ") received left %d\n",
            print_wrid(wc.wr_id), wc.wr_id, rdma->num_signaled_send);
    }

    return  (int)wc.wr_id;
}

/*
 * Block until the next work request has completed.
 *
 * First poll to see if a work request has already completed,
 * otherwise block.
 *
 * If we encounter completed work requests for IDs other than
 * the one we're interested in, then that's generally an error.
 *
 * The only exception is actual RDMA Write completions. These
 * completions only need to be recorded, but do not actually
 * need further processing.
 */
static int qemu_rdma_block_for_wrid(RDMAContext *rdma, int wrid_start,
                                    int wrid_stop)
{
    int num_cq_events = 0;
    int r = RDMA_WRID_NONE;
    struct ibv_cq *cq;
    void *cq_ctx;

    if (ibv_req_notify_cq(rdma->cq, 0)) {
        return -1;
    }
    /* poll cq first */
    while ((r < wrid_start) || ((wrid_stop != -1) && (r > wrid_stop))) {
        r = qemu_rdma_poll(rdma);
        if (r < 0) {
            return r;
        }
        if (r == RDMA_WRID_NONE) {
            break;
        }
        if ((r < wrid_start) || ((wrid_stop != -1)
                                && (r > wrid_stop))) {
            DDDPRINTF("A Wanted wrid %s (%d, %d) but got %s (%d)\n",
                print_wrid(wrid_start),
                        wrid_start, wrid_stop, print_wrid(r), r);
        }
    }

    if ((r >= wrid_start) && ((wrid_stop == -1) || (r <= wrid_stop))) {
        return 0;
    }

    while (1) {
        /*
         * Coroutine doesn't start until process_incoming_migration()
         * so don't yield unless we know we're running inside of a coroutine.
         */
        if (rdma->migration_started_on_destination) {
            yield_until_fd_readable(rdma->comp_channel->fd);
        }

        if (ibv_get_cq_event(rdma->comp_channel, &cq, &cq_ctx)) {
            perror("ibv_get_cq_event");
            goto err_block_for_wrid;
        }

        num_cq_events++;

        if (ibv_req_notify_cq(cq, 0)) {
            goto err_block_for_wrid;
        }

        while ((r < wrid_start) || ((wrid_stop != -1) && (r > wrid_stop))) {
            r = qemu_rdma_poll(rdma);
            if (r < 0) {
                goto err_block_for_wrid;
            }
            if (r == RDMA_WRID_NONE) {
                break;
            }
            if ((r < wrid_start) || ((wrid_stop != -1) && (r > wrid_stop))) {
                DDDPRINTF("B Wanted wrid %s (%d, %d) but got %s (%d)\n",
                    print_wrid(wrid_start), wrid_start,
                                        wrid_stop, print_wrid(r), r);
            }
        }

        if ((r >= wrid_start) && ((wrid_stop == -1) || (r <= wrid_stop))) {
            goto success_block_for_wrid;
        }
    }

success_block_for_wrid:
    if (num_cq_events) {
        ibv_ack_cq_events(cq, num_cq_events);
    }
    return 0;

err_block_for_wrid:
    if (num_cq_events) {
        ibv_ack_cq_events(cq, num_cq_events);
    }
    return -1;
}

/*
 * Post a SEND message work request for the control channel
 * containing some data and block until the post completes.
 */
static int qemu_rdma_post_send_control(RDMAContext *rdma, uint8_t *buf,
                                       RDMAControlHeader *head)
{
    int ret = 0;
    RDMAWorkRequestData *wr = &rdma->wr_data[RDMA_CONTROL_MAX_WR];
    struct ibv_send_wr *bad_wr;
    struct ibv_sge sge = {
                           .addr = (uint64_t)(wr->control),
                           .length = head->len + sizeof(RDMAControlHeader),
                           .lkey = wr->control_mr->lkey,
                         };
    struct ibv_send_wr send_wr = {
                                   .wr_id = RDMA_WRID_SEND_CONTROL,
                                   .opcode = IBV_WR_SEND,
                                   .send_flags = IBV_SEND_SIGNALED,
                                   .sg_list = &sge,
                                   .num_sge = 1,
                                };

    DDDPRINTF("CONTROL: sending %s..\n", control_desc[head->type]);

    /*
     * We don't actually need to do a memcpy() in here if we used
     * the "sge" properly, but since we're only sending control messages
     * (not RAM in a performance-critical path), then its OK for now.
     *
     * The copy makes the RDMAControlHeader simpler to manipulate
     * for the time being.
     */
    memcpy(wr->control, head, sizeof(RDMAControlHeader));
    control_to_network((void *) wr->control);

    if (buf) {
        memcpy(wr->control + sizeof(RDMAControlHeader), buf, head->len);
    }


    if (ibv_post_send(rdma->qp, &send_wr, &bad_wr)) {
        return -1;
    }

    if (ret < 0) {
        fprintf(stderr, "Failed to use post IB SEND for control!\n");
        return ret;
    }

    ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_SEND_CONTROL, -1);
    if (ret < 0) {
        fprintf(stderr, "rdma migration: send polling control error!\n");
    }

    return ret;
}

/*
 * Post a RECV work request in anticipation of some future receipt
 * of data on the control channel.
 */
static int qemu_rdma_post_recv_control(RDMAContext *rdma, int idx)
{
    struct ibv_recv_wr *bad_wr;
    struct ibv_sge sge = {
                            .addr = (uint64_t)(rdma->wr_data[idx].control),
                            .length = RDMA_CONTROL_MAX_BUFFER,
                            .lkey = rdma->wr_data[idx].control_mr->lkey,
                         };

    struct ibv_recv_wr recv_wr = {
                                    .wr_id = RDMA_WRID_RECV_CONTROL + idx,
                                    .sg_list = &sge,
                                    .num_sge = 1,
                                 };


    if (ibv_post_recv(rdma->qp, &recv_wr, &bad_wr)) {
        return -1;
    }

    return 0;
}

/*
 * Block and wait for a RECV control channel message to arrive.
 */
static int qemu_rdma_exchange_get_response(RDMAContext *rdma,
                RDMAControlHeader *head, int expecting, int idx)
{
    int ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_RECV_CONTROL + idx, -1);

    if (ret < 0) {
        fprintf(stderr, "rdma migration: recv polling control error!\n");
        return ret;
    }

    network_to_control((void *) rdma->wr_data[idx].control);
    memcpy(head, rdma->wr_data[idx].control, sizeof(RDMAControlHeader));

    DDDPRINTF("CONTROL: %s received\n", control_desc[expecting]);

    if ((expecting != RDMA_CONTROL_NONE && head->type != expecting)
            || head->type == RDMA_CONTROL_ERROR) {
        fprintf(stderr, "Was expecting a %s (%d) control message"
                ", but got: %s (%d), length: %d\n",
                control_desc[expecting], expecting,
                control_desc[head->type], head->type, head->len);
        return -EIO;
    }

    return 0;
}

/*
 * When a RECV work request has completed, the work request's
 * buffer is pointed at the header.
 *
 * This will advance the pointer to the data portion
 * of the control message of the work request's buffer that
 * was populated after the work request finished.
 */
static void qemu_rdma_move_header(RDMAContext *rdma, int idx,
                                  RDMAControlHeader *head)
{
    rdma->wr_data[idx].control_len = head->len;
    rdma->wr_data[idx].control_curr =
        rdma->wr_data[idx].control + sizeof(RDMAControlHeader);
}

/*
 * This is an 'atomic' high-level operation to deliver a single, unified
 * control-channel message.
 *
 * Additionally, if the user is expecting some kind of reply to this message,
 * they can request a 'resp' response message be filled in by posting an
 * additional work request on behalf of the user and waiting for an additional
 * completion.
 *
 * The extra (optional) response is used during registration to us from having
 * to perform an *additional* exchange of message just to provide a response by
 * instead piggy-backing on the acknowledgement.
 */
static int qemu_rdma_exchange_send(RDMAContext *rdma, RDMAControlHeader *head,
                                   uint8_t *data, RDMAControlHeader *resp,
                                   int *resp_idx)
{
    int ret = 0;
    int idx = 0;

    /*
     * Wait until the dest is ready before attempting to deliver the message
     * by waiting for a READY message.
     */
    if (rdma->control_ready_expected) {
        RDMAControlHeader resp;
        ret = qemu_rdma_exchange_get_response(rdma,
                                    &resp, RDMA_CONTROL_READY, idx);
        if (ret < 0) {
            return ret;
        }
    }

    /*
     * If the user is expecting a response, post a WR in anticipation of it.
     */
    if (resp) {
        ret = qemu_rdma_post_recv_control(rdma, idx + 1);
        if (ret) {
            fprintf(stderr, "rdma migration: error posting"
                    " extra control recv for anticipated result!");
            return ret;
        }
    }

    /*
     * Post a WR to replace the one we just consumed for the READY message.
     */
    ret = qemu_rdma_post_recv_control(rdma, idx);
    if (ret) {
        fprintf(stderr, "rdma migration: error posting first control recv!");
        return ret;
    }

    /*
     * Deliver the control message that was requested.
     */
    ret = qemu_rdma_post_send_control(rdma, data, head);

    if (ret < 0) {
        fprintf(stderr, "Failed to send control buffer!\n");
        return ret;
    }

    /*
     * If we're expecting a response, block and wait for it.
     */
    if (resp) {
        DDPRINTF("Waiting for response %s\n", control_desc[resp->type]);
        ret = qemu_rdma_exchange_get_response(rdma, resp, resp->type, idx + 1);

        if (ret < 0) {
            return ret;
        }

        qemu_rdma_move_header(rdma, idx + 1, resp);
        *resp_idx = idx + 1;
        DDPRINTF("Response %s received.\n", control_desc[resp->type]);
    }

    rdma->control_ready_expected = 1;

    return 0;
}

/*
 * This is an 'atomic' high-level operation to receive a single, unified
 * control-channel message.
 */
static int qemu_rdma_exchange_recv(RDMAContext *rdma, RDMAControlHeader *head,
                                int expecting)
{
    RDMAControlHeader ready = {
                                .len = 0,
                                .type = RDMA_CONTROL_READY,
                                .repeat = 1,
                              };
    int ret;

    /*
     * Inform the source that we're ready to receive a message.
     */
    ret = qemu_rdma_post_send_control(rdma, NULL, &ready);

    if (ret < 0) {
        fprintf(stderr, "Failed to send control buffer!\n");
        return ret;
    }

    /*
     * Block and wait for the message.
     */
    ret = qemu_rdma_exchange_get_response(rdma, head, expecting, 0);

    if (ret < 0) {
        return ret;
    }

    qemu_rdma_move_header(rdma, 0, head);

    /*
     * Post a new RECV work request to replace the one we just consumed.
     */
    ret = qemu_rdma_post_recv_control(rdma, 0);
    if (ret) {
        fprintf(stderr, "rdma migration: error posting second control recv!");
        return ret;
    }

    return 0;
}

/*
 * Write an actual chunk of memory using RDMA.
 *
 * If we're using dynamic registration on the dest-side, we have to
 * send a registration command first.
 */
static int qemu_rdma_write_one(QEMUFile *f, RDMAContext *rdma,
        int current_index, uint64_t offset, uint64_t length,
        enum ibv_send_flags flag)
{
    struct ibv_sge sge;
    struct ibv_send_wr send_wr = { 0 };
    struct ibv_send_wr *bad_wr;
    RDMALocalBlock *block = &(rdma->local_ram_blocks.block[current_index]);
    int chunk;
    int x;
    RDMARegister reg;
    RDMARegisterResult *reg_result;
    int reg_result_idx;
    RDMAControlHeader resp = { .type = RDMA_CONTROL_REGISTER_RESULT };
    RDMAControlHeader head = { .len = sizeof(RDMARegister),
                               .type = RDMA_CONTROL_REGISTER_REQUEST,
                               .repeat = 1,
                             };
    int ret;

    sge.addr = (uint64_t)(block->local_host_addr + (offset - block->offset));
    sge.length = length;

    /*
     * Search the existing work request identifiers to make sure the address of
     * this request (either a zero chunk or a regular chunk) does not overlap
     * with any of the address ranges outstanding on the wire.
     */
    for (x = RDMA_WRID_RDMA_WRITE_START; x < RDMA_WRID_RDMA_WRITE_STOP; x++) {
        int len = rdma->in_transit[x].len;
        uintptr_t start = rdma->in_transit[x].addr, end = start + len;

        if (!start && !len) {
            continue;
        }

        if ((sge.addr >= start) && (sge.addr < end)) {
            DPRINTF("Not clobbering: start %" PRIu64 " end %" PRIu64
                    " len %d current %" PRIu64 " len %" PRIu64 " wrid %d\n",
                    start, end, len, sge.addr, length, x);

            ret = qemu_rdma_block_for_wrid(rdma, x, -1);
            if (ret < 0) {
                fprintf(stderr, "Failed to Wait for previous write to complete "
                        "start %" PRIu64 " end %" PRIu64
                        " len %d current %" PRIu64 " len %" PRIu64 " wrid %d\n",
                        start, end, len, sge.addr, length, x);
                return ret;
            }
        }
    }

    if (!rdma->pin_all) {
        chunk = ram_chunk_index(block->local_host_addr, (uint8_t *) sge.addr);
        if (!block->remote_keys[chunk]) {
            /*
             * This page has not yet been registered, so first check to see
             * if the entire chunk is zero. If so, tell the other size to
             * memset() + madvise() the entire chunk without RDMA.
             */

            if (can_use_buffer_find_nonzero_offset((void *)sge.addr, length)
                   && buffer_find_nonzero_offset((void *)sge.addr,
                                                    length) == length) {
                RDMACompress comp = {
                                        .offset = offset,
                                        .value = 0,
                                        .block_idx = current_index,
                                        .length = length,
                                    };

                head.len = sizeof(comp);
                head.type = RDMA_CONTROL_COMPRESS;

                DDPRINTF("Entire chunk is zero, sending compress: %d for %d "
                    "bytes, index: %d, offset: %" PRId64 "...\n",
                    chunk, sge.length, current_index, offset);

                ret = qemu_rdma_exchange_send(rdma, &head,
                                (uint8_t *) &comp, NULL, NULL);

                if (ret < 0) {
                    return -EIO;
                }

                acct_update_position(f, sge.length, true);

                return 1;
            }

            /*
             * Otherwise, tell other side to register.
             */
            reg.len = sge.length;
            reg.current_index = current_index;
            reg.offset = offset;

            DDPRINTF("Sending registration request chunk %d for %d "
                    "bytes, index: %d, offset: %" PRId64 "...\n",
                    chunk, sge.length, current_index, offset);

            ret = qemu_rdma_exchange_send(rdma, &head, (uint8_t *) &reg,
                                    &resp, &reg_result_idx);
            if (ret < 0) {
                return ret;
            }

            /* try to overlap this single registration with the one we sent. */
            if (qemu_rdma_register_and_get_keys(rdma, block,
                                                (uint8_t *) sge.addr,
                                                &sge.lkey, NULL)) {
                fprintf(stderr, "cannot get lkey!\n");
                return -EINVAL;
            }

            reg_result = (RDMARegisterResult *)
                    rdma->wr_data[reg_result_idx].control_curr;

            DDPRINTF("Received registration result:"
                    " my key: %x their key %x, chunk %d\n",
                    block->remote_keys[chunk], reg_result->rkey, chunk);

            block->remote_keys[chunk] = reg_result->rkey;
        } else {
            /* already registered before */
            if (qemu_rdma_register_and_get_keys(rdma, block,
                                                (uint8_t *)sge.addr,
                                                &sge.lkey, NULL)) {
                fprintf(stderr, "cannot get lkey!\n");
                return -EINVAL;
            }
        }

        send_wr.wr.rdma.rkey = block->remote_keys[chunk];
    } else {
        send_wr.wr.rdma.rkey = block->remote_rkey;

        if (qemu_rdma_register_and_get_keys(rdma, block, (uint8_t *)sge.addr,
                                                     &sge.lkey, NULL)) {
            fprintf(stderr, "cannot get lkey!\n");
            return -EINVAL;
        }
    }

    /*
     * Before we select this new work request identifier, make sure there's
     * enough space available in the available work request ID tracking space
     * to use this identifier. Otherwise, block.
     */
    send_wr.wr_id = RDMA_WRID_RDMA_WRITE_START + rdma->nb_transit;

    if (rdma->in_transit[rdma->nb_transit].addr != 0 &&
        rdma->in_transit[rdma->nb_transit].len != 0) {
        DDPRINTF("no slots left! make more %d %" PRIu64 "\n",
                    rdma->nb_transit, send_wr.wr_id);

        ret = qemu_rdma_block_for_wrid(rdma, send_wr.wr_id, -1);
        if (ret < 0) {
            fprintf(stderr, "Slots are full. Failed to "
                "Wait for previous write to complete... %d %" PRIu64 "\n",
                rdma->nb_transit, send_wr.wr_id);
            return ret;
        }
    }

    rdma->in_transit[rdma->nb_transit].addr = sge.addr;
    rdma->in_transit[rdma->nb_transit].len = sge.length;

    rdma->nb_transit++;

    DDPRINTF("Next wrid: %" PRIu64 ", start: %d, max: %d\n", send_wr.wr_id,
            RDMA_WRID_RDMA_WRITE_START, RDMA_WRID_RDMA_WRITE_STOP);

    if (rdma->nb_transit == (RDMA_SIGNALED_SEND_MAX - 1)) {
        rdma->nb_transit = 0;
        DDPRINTF("Resetting nb_transit to zero\n");
    }


    send_wr.opcode = IBV_WR_RDMA_WRITE;
    send_wr.send_flags = flag;
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    send_wr.wr.rdma.remote_addr = block->remote_host_addr +
                                    (offset - block->offset);


    acct_update_position(f, sge.length, false);

    return ibv_post_send(rdma->qp, &send_wr, &bad_wr);
}

/*
 * Push out any unwritten RDMA operations.
 *
 * We support sending out multiple chunks at the same time.
 * Not all of them need to get signaled in the completion queue.
 */
static int qemu_rdma_write_flush(QEMUFile *f, RDMAContext *rdma)
{
    int ret;
    enum ibv_send_flags flags = IBV_SEND_SIGNALED;

    if (!rdma->current_length) {
        return 0;
    }

retry:
    ret = qemu_rdma_write_one(f, rdma,
            rdma->current_index,
            rdma->current_offset,
            rdma->current_length,
            flags);

    if (ret < 0) {
        if (ret == -ENOMEM) {
            DDPRINTF("send queue is full. wait a little....\n");
            ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_RDMA_WRITE_START,
                                       RDMA_WRID_RDMA_WRITE_STOP);
            if (ret >= 0) {
                goto retry;
            }
            if (ret < 0) {
                fprintf(stderr, "rdma migration: failed to make "
                                "room in full send queue! %d\n", ret);
                return ret;
            }
        }
        perror("write flush error");
        return ret;
    }

    if (ret == 0) {
        rdma->num_signaled_send++;
        DDDPRINTF("signaled total: %d\n", rdma->num_signaled_send);
    }

    rdma->current_length = 0;
    rdma->current_offset = 0;

    return 0;
}

static inline int qemu_rdma_buffer_mergable(RDMAContext *rdma,
                    uint64_t offset, uint64_t len)
{
    RDMALocalBlock *block =
        &(rdma->local_ram_blocks.block[rdma->current_index]);
    uint8_t *host_addr = block->local_host_addr + (offset - block->offset);
    uint8_t *chunk_end = ram_chunk_end(block, rdma->current_chunk);

    if (rdma->current_length == 0) {
        return 0;
    }

    /*
     * Only merge into chunk sequentially.
     */
    if (offset != (rdma->current_offset + rdma->current_length)) {
        return 0;
    }

    if (rdma->current_index < 0) {
        return 0;
    }

    if (offset < block->offset) {
        return 0;
    }

    if ((offset + len) > (block->offset + block->length)) {
        return 0;
    }

    if (rdma->current_chunk < 0) {
        return 0;
    }

    if ((host_addr + len) > chunk_end) {
        return 0;
    }

    return 1;
}

/*
 * We're not actually writing here, but doing three things:
 *
 * 1. Identify the chunk the buffer belongs to.
 * 2. If the chunk is full or the buffer doesn't belong to the current
 *    chunk, then start a new chunk and flush() the old chunk.
 * 3. To keep the hardware busy, we also group chunks into batches
 *    and only require that a batch gets acknowledged in the completion
 *    qeueue instead of each individual chunk.
 */
static int qemu_rdma_write(QEMUFile *f, RDMAContext *rdma,
                           uint64_t offset, uint64_t len)
{
    int index = rdma->current_index;
    int chunk_index = rdma->current_chunk;
    int ret;

    /* If we cannot merge it, we flush the current buffer first. */
    if (!qemu_rdma_buffer_mergable(rdma, offset, len)) {
        ret = qemu_rdma_write_flush(f, rdma);
        if (ret) {
            return ret;
        }
        rdma->current_length = 0;
        rdma->current_offset = offset;

        ret = qemu_rdma_search_ram_block(offset, len,
                    &rdma->local_ram_blocks, &index, &chunk_index);
        if (ret) {
            fprintf(stderr, "ram block search failed\n");
            return ret;
        }
        rdma->current_index = index;
        rdma->current_chunk = chunk_index;
    }

    /* merge it */
    rdma->current_length += len;

    /* flush it if buffer is too large */
    if (rdma->current_length >= RDMA_MERGE_MAX) {
        return qemu_rdma_write_flush(f, rdma);
    }

    return 0;
}

static void qemu_rdma_cleanup(RDMAContext *rdma)
{
    struct rdma_cm_event *cm_event;
    int ret, idx;

    if (rdma->cm_id) {
        if (rdma->error_state) {
            RDMAControlHeader head = { .len = 0,
                                       .type = RDMA_CONTROL_ERROR,
                                       .repeat = 1,
                                     };
            fprintf(stderr, "Early error. Sending error.\n");
            qemu_rdma_post_send_control(rdma, NULL, &head);
        }

        ret = rdma_disconnect(rdma->cm_id);
        if (!ret) {
            DDPRINTF("waiting for disconnect\n");
            ret = rdma_get_cm_event(rdma->channel, &cm_event);
            if (!ret) {
                rdma_ack_cm_event(cm_event);
            }
        }
        DDPRINTF("Disconnected.\n");
        rdma->cm_id = 0;
    }

    g_free(rdma->block);
    rdma->block = NULL;

    for (idx = 0; idx < (RDMA_CONTROL_MAX_WR + 1); idx++) {
        if (rdma->wr_data[idx].control_mr) {
            qemu_rdma_dereg_control(rdma, idx);
        }
        rdma->wr_data[idx].control_mr = NULL;
    }

    if (rdma->local_ram_blocks.block) {
        qemu_rdma_dereg_ram_blocks(rdma, &rdma->local_ram_blocks);

        if (!rdma->pin_all) {
            for (idx = 0; idx < rdma->local_ram_blocks.num_blocks; idx++) {
                RDMALocalBlock *block = &(rdma->local_ram_blocks.block[idx]);
                g_free(block->remote_keys);
                block->remote_keys = NULL;
            }
        }
        g_free(rdma->local_ram_blocks.block);
        rdma->local_ram_blocks.block = NULL;
    }

    if (rdma->qp) {
        ibv_destroy_qp(rdma->qp);
        rdma->qp = NULL;
    }
    if (rdma->cq) {
        ibv_destroy_cq(rdma->cq);
        rdma->cq = NULL;
    }
    if (rdma->comp_channel) {
        ibv_destroy_comp_channel(rdma->comp_channel);
        rdma->comp_channel = NULL;
    }
    if (rdma->pd) {
        ibv_dealloc_pd(rdma->pd);
        rdma->pd = NULL;
    }
    if (rdma->listen_id) {
        rdma_destroy_id(rdma->listen_id);
        rdma->listen_id = 0;
    }
    if (rdma->cm_id) {
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = 0;
    }
    if (rdma->channel) {
        rdma_destroy_event_channel(rdma->channel);
        rdma->channel = NULL;
    }

    rdma->nb_transit = 0;
}


static int qemu_rdma_source_init(RDMAContext *rdma, Error **errp, bool pin_all)
{
    int ret, idx;
    Error *local_err = NULL, **temp = &local_err;

    /*
     * Will be validated against destination's actual capabilities
     * after the connect() completes.
     */
    rdma->pin_all = pin_all;

    ret = qemu_rdma_resolve_host(rdma, temp);
    if (ret) {
        goto err_rdma_source_init;
    }

    ret = qemu_rdma_alloc_pd_cq(rdma);
    if (ret) {
        ERROR(temp, "rdma migration: error allocating pd and cq! Your mlock()"
                    " limits may be too low. Please check $ ulimit -a # and "
                    "search for 'ulimit -l' in the output\n");
        goto err_rdma_source_init;
    }

    ret = qemu_rdma_alloc_qp(rdma);
    if (ret) {
        ERROR(temp, "rdma migration: error allocating qp!\n");
        goto err_rdma_source_init;
    }

    ret = qemu_rdma_init_ram_blocks(&rdma->local_ram_blocks);
    if (ret) {
        ERROR(temp, "rdma migration: error initializing ram blocks!\n");
        goto err_rdma_source_init;
    }

    for (idx = 0; idx < (RDMA_CONTROL_MAX_WR + 1); idx++) {
        ret = qemu_rdma_reg_control(rdma, idx);
        if (ret) {
            ERROR(temp, "rdma migration: error registering %d control!\n",
                                                            idx);
            goto err_rdma_source_init;
        }
    }

    rdma->block = (RDMARemoteBlock *) g_malloc0(sizeof(RDMARemoteBlock) *
                        rdma->local_ram_blocks.num_blocks);
    return 0;

err_rdma_source_init:
    error_propagate(errp, local_err);
    qemu_rdma_cleanup(rdma);
    return -1;
}

static int qemu_rdma_connect(RDMAContext *rdma, Error **errp)
{
    RDMACapabilities cap = {
                                .version = RDMA_CONTROL_VERSION_CURRENT,
                                .flags = 0,
                           };
    struct rdma_conn_param conn_param = { .initiator_depth = 2,
                                          .retry_count = 5,
                                          .private_data = &cap,
                                          .private_data_len = sizeof(cap),
                                        };
    struct rdma_cm_event *cm_event;
    int ret;

    /*
     * Only negotiate the capability with destination if the user
     * on the source first requested the capability.
     */
    if (rdma->pin_all) {
        DPRINTF("Server pin-all memory requested.\n");
        cap.flags |= RDMA_CAPABILITY_PIN_ALL;
    }

    caps_to_network(&cap);

    ret = rdma_connect(rdma->cm_id, &conn_param);
    if (ret) {
        perror("rdma_connect");
        ERROR(errp, "connecting to destination!\n");
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = 0;
        goto err_rdma_source_connect;
    }

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        perror("rdma_get_cm_event after rdma_connect");
        ERROR(errp, "connecting to destination!\n");
        rdma_ack_cm_event(cm_event);
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = 0;
        goto err_rdma_source_connect;
    }

    if (cm_event->event != RDMA_CM_EVENT_ESTABLISHED) {
        perror("rdma_get_cm_event != EVENT_ESTABLISHED after rdma_connect");
        ERROR(errp, "connecting to destination!\n");
        rdma_ack_cm_event(cm_event);
        rdma_destroy_id(rdma->cm_id);
        rdma->cm_id = 0;
        goto err_rdma_source_connect;
    }

    memcpy(&cap, cm_event->param.conn.private_data, sizeof(cap));
    network_to_caps(&cap);

    /*
     * Verify that the *requested* capabilities are supported by the destination
     * and disable them otherwise.
     */
    if (rdma->pin_all && !(cap.flags & RDMA_CAPABILITY_PIN_ALL)) {
        ERROR(errp, "Server cannot support pinning all memory. "
                        "Will register memory dynamically.\n");
        rdma->pin_all = false;
    }

    DPRINTF("Pin all memory: %s\n", rdma->pin_all ? "enabled" : "disabled");

    rdma_ack_cm_event(cm_event);

    ret = qemu_rdma_post_recv_control(rdma, 0);
    if (ret) {
        ERROR(errp, "posting second control recv!\n");
        goto err_rdma_source_connect;
    }

    rdma->control_ready_expected = 1;
    rdma->num_signaled_send = 0;
    return 0;

err_rdma_source_connect:
    qemu_rdma_cleanup(rdma);
    return -1;
}

static int qemu_rdma_dest_init(RDMAContext *rdma, Error **errp)
{
    int ret = -EINVAL, idx;
    struct sockaddr_in sin;
    struct rdma_cm_id *listen_id;
    char ip[40] = "unknown";

    for (idx = 0; idx < RDMA_CONTROL_MAX_WR; idx++) {
        rdma->wr_data[idx].control_len = 0;
        rdma->wr_data[idx].control_curr = NULL;
    }

    if (rdma->host == NULL) {
        ERROR(errp, "RDMA host is not set!\n");
        rdma->error_state = -EINVAL;
        return -1;
    }
    /* create CM channel */
    rdma->channel = rdma_create_event_channel();
    if (!rdma->channel) {
        ERROR(errp, "could not create rdma event channel\n");
        rdma->error_state = -EINVAL;
        return -1;
    }

    /* create CM id */
    ret = rdma_create_id(rdma->channel, &listen_id, NULL, RDMA_PS_TCP);
    if (ret) {
        ERROR(errp, "could not create cm_id!\n");
        goto err_dest_init_create_listen_id;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(rdma->port);

    if (rdma->host && strcmp("", rdma->host)) {
        struct hostent *dest_addr;
        dest_addr = gethostbyname(rdma->host);
        if (!dest_addr) {
            ERROR(errp, "migration could not gethostbyname!\n");
            ret = -EINVAL;
            goto err_dest_init_bind_addr;
        }
        memcpy(&sin.sin_addr.s_addr, dest_addr->h_addr,
                dest_addr->h_length);
        inet_ntop(AF_INET, dest_addr->h_addr, ip, sizeof ip);
    } else {
        sin.sin_addr.s_addr = INADDR_ANY;
    }

    DPRINTF("%s => %s\n", rdma->host, ip);

    ret = rdma_bind_addr(listen_id, (struct sockaddr *)&sin);
    if (ret) {
        ERROR(errp, "Error: could not rdma_bind_addr!\n");
        goto err_dest_init_bind_addr;
    }

    rdma->listen_id = listen_id;
    if (listen_id->verbs) {
        rdma->verbs = listen_id->verbs;
    }
    qemu_rdma_dump_id("dest_init", rdma->verbs);
    qemu_rdma_dump_gid("dest_init", listen_id);
    return 0;

err_dest_init_bind_addr:
    rdma_destroy_id(listen_id);
err_dest_init_create_listen_id:
    rdma_destroy_event_channel(rdma->channel);
    rdma->channel = NULL;
    rdma->error_state = ret;
    return ret;

}

static int qemu_rdma_dest_prepare(RDMAContext *rdma, Error **errp)
{
    int ret;
    int idx;

    if (!rdma->verbs) {
        ERROR(errp, "no verbs context!\n");
        return 0;
    }

    ret = qemu_rdma_alloc_pd_cq(rdma);
    if (ret) {
        ERROR(errp, "allocating pd and cq!\n");
        goto err_rdma_dest_prepare;
    }

    ret = qemu_rdma_init_ram_blocks(&rdma->local_ram_blocks);
    if (ret) {
        ERROR(errp, "initializing ram blocks!\n");
        goto err_rdma_dest_prepare;
    }

    rdma->block = (RDMARemoteBlock *) g_malloc0(sizeof(RDMARemoteBlock) *
                        rdma->local_ram_blocks.num_blocks);

    /* Extra one for the send buffer */
    for (idx = 0; idx < (RDMA_CONTROL_MAX_WR + 1); idx++) {
        ret = qemu_rdma_reg_control(rdma, idx);
        if (ret) {
            ERROR(errp, "registering %d control!\n", idx);
            goto err_rdma_dest_prepare;
        }
    }

    ret = rdma_listen(rdma->listen_id, 5);
    if (ret) {
        ERROR(errp, "listening on socket!\n");
        goto err_rdma_dest_prepare;
    }

    return 0;

err_rdma_dest_prepare:
    qemu_rdma_cleanup(rdma);
    return -1;
}

static void *qemu_rdma_data_init(const char *host_port, Error **errp)
{
    RDMAContext *rdma = NULL;
    InetSocketAddress *addr;

    if (host_port) {
        rdma = g_malloc0(sizeof(RDMAContext));
        memset(rdma, 0, sizeof(RDMAContext));
        rdma->current_index = -1;
        rdma->current_chunk = -1;

        addr = inet_parse(host_port, NULL);
        if (addr != NULL) {
            rdma->port = atoi(addr->port);
            rdma->host = g_strdup(addr->host);
        } else {
            ERROR(errp, "bad RDMA migration address '%s'", host_port);
            g_free(rdma);
            return NULL;
        }
    }

    return rdma;
}

/*
 * QEMUFile interface to the control channel.
 * SEND messages for control only.
 * pc.ram is handled with regular RDMA messages.
 */
static int qemu_rdma_put_buffer(void *opaque, const uint8_t *buf,
                                int64_t pos, int size)
{
    QEMUFileRDMA *r = opaque;
    QEMUFile *f = r->file;
    RDMAContext *rdma = r->rdma;
    size_t remaining = size;
    uint8_t * data = (void *) buf;
    int ret;

    CHECK_ERROR_STATE();

    /*
     * Push out any writes that
     * we're queued up for pc.ram.
     */
    ret = qemu_rdma_write_flush(f, rdma);
    if (ret < 0) {
        rdma->error_state = ret;
        return ret;
    }

    while (remaining) {
        RDMAControlHeader head;

        r->len = MIN(remaining, RDMA_SEND_INCREMENT);
        remaining -= r->len;

        head.len = r->len;
        head.type = RDMA_CONTROL_QEMU_FILE;

        ret = qemu_rdma_exchange_send(rdma, &head, data, NULL, NULL);

        if (ret < 0) {
            rdma->error_state = ret;
            return ret;
        }

        data += r->len;
    }

    return size;
}

static size_t qemu_rdma_fill(RDMAContext *rdma, uint8_t *buf,
                             int size, int idx)
{
    size_t len = 0;

    if (rdma->wr_data[idx].control_len) {
        DDDPRINTF("RDMA %" PRId64 " of %d bytes already in buffer\n",
                    rdma->wr_data[idx].control_len, size);

        len = MIN(size, rdma->wr_data[idx].control_len);
        memcpy(buf, rdma->wr_data[idx].control_curr, len);
        rdma->wr_data[idx].control_curr += len;
        rdma->wr_data[idx].control_len -= len;
    }

    return len;
}

/*
 * QEMUFile interface to the control channel.
 * RDMA links don't use bytestreams, so we have to
 * return bytes to QEMUFile opportunistically.
 */
static int qemu_rdma_get_buffer(void *opaque, uint8_t *buf,
                                int64_t pos, int size)
{
    QEMUFileRDMA *r = opaque;
    RDMAContext *rdma = r->rdma;
    RDMAControlHeader head;
    int ret = 0;

    CHECK_ERROR_STATE();

    /*
     * First, we hold on to the last SEND message we
     * were given and dish out the bytes until we run
     * out of bytes.
     */
    r->len = qemu_rdma_fill(r->rdma, buf, size, 0);
    if (r->len) {
        return r->len;
    }

    /*
     * Once we run out, we block and wait for another
     * SEND message to arrive.
     */
    ret = qemu_rdma_exchange_recv(rdma, &head, RDMA_CONTROL_QEMU_FILE);

    if (ret < 0) {
        rdma->error_state = ret;
        return ret;
    }

    /*
     * SEND was received with new bytes, now try again.
     */
    return qemu_rdma_fill(r->rdma, buf, size, 0);
}

/*
 * Block until all the outstanding chunks have been delivered by the hardware.
 */
static int qemu_rdma_drain_cq(QEMUFile *f, RDMAContext *rdma)
{
    int ret;

    if (qemu_rdma_write_flush(f, rdma) < 0) {
        return -EIO;
    }

    while (rdma->num_signaled_send) {
        ret = qemu_rdma_block_for_wrid(rdma, RDMA_WRID_RDMA_WRITE_START,
                                       RDMA_WRID_RDMA_WRITE_STOP);
        if (ret < 0) {
            fprintf(stderr, "rdma migration: complete polling error!\n");
            return -EIO;
        }
    }

    return 0;
}

static int qemu_rdma_close(void *opaque)
{
    DPRINTF("Shutting down connection.\n");
    QEMUFileRDMA *r = opaque;
    if (r->rdma) {
        qemu_rdma_cleanup(r->rdma);
        g_free(r->rdma);
    }
    g_free(r);
    return 0;
}

static size_t qemu_rdma_save_page(QEMUFile *f, void *opaque,
                                  ram_addr_t block_offset, ram_addr_t offset,
                                  size_t size, int *bytes_sent)
{
    ram_addr_t current_addr = block_offset + offset;
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    int ret;

    CHECK_ERROR_STATE();

    qemu_fflush(f);

    /*
     * Add this page to the current 'chunk'. If the chunk
     * is full, or the page doen't belong to the current chunk,
     * an actual RDMA write will occur and a new chunk will be formed.
     */
    ret = qemu_rdma_write(f, rdma, current_addr, size);
    if (ret < 0) {
        rdma->error_state = ret;
        fprintf(stderr, "rdma migration: write error! %d\n", ret);
        return ret;
    }

    /*
     * Drain the Completion Queue if possible, but do not block,
     * just poll.
     *
     * If nothing to poll, the end of the iteration will do this
     * again to make sure we don't overflow the request queue.
     */
    while (1) {
        int ret = qemu_rdma_poll(rdma);
        if (ret == RDMA_WRID_NONE) {
            break;
        }
        if (ret < 0) {
            rdma->error_state = ret;
            fprintf(stderr, "rdma migration: polling error! %d\n", ret);
            return ret;
        }
    }

    /*
     * We always return 0 bytes because the RDMA
     * protocol is completely asynchronous. We do not yet know whether an
     * identified chunk is zero or not because we're waiting for other pages to
     * potentially be merged with the current chunk.
     * So, we have to call qemu_update_position() later on when the actual write
     * occurs.
     */
    *bytes_sent = 1;
    return RAM_SAVE_CONTROL_DELAYED;
}

static int qemu_rdma_accept(RDMAContext *rdma)
{
    RDMACapabilities cap;
    struct rdma_conn_param conn_param = {
                                            .responder_resources = 2,
                                            .private_data = &cap,
                                            .private_data_len = sizeof(cap),
                                         };
    struct rdma_cm_event *cm_event;
    struct ibv_context *verbs;
    int ret = -EINVAL;

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        goto err_rdma_dest_wait;
    }

    if (cm_event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }

    memcpy(&cap, cm_event->param.conn.private_data, sizeof(cap));

    network_to_caps(&cap);

    if (cap.version < 1 || cap.version > RDMA_CONTROL_VERSION_CURRENT) {
            fprintf(stderr, "Unknown source RDMA version: %d, bailing...\n",
                            cap.version);
            rdma_ack_cm_event(cm_event);
            goto err_rdma_dest_wait;
    }

    /*
     * Respond with only the capabilities this version of QEMU knows about.
     */
    cap.flags &= known_capabilities;

    /*
     * Enable the ones that we do know about.
     * Add other checks here as new ones are introduced.
     */
    if (cap.flags & RDMA_CAPABILITY_PIN_ALL) {
        rdma->pin_all = true;
    }

    rdma->cm_id = cm_event->id;
    verbs = cm_event->id->verbs;

    rdma_ack_cm_event(cm_event);

    DPRINTF("Memory pin all: %s\n", rdma->pin_all ? "enabled" : "disabled");

    caps_to_network(&cap);

    DPRINTF("verbs context after listen: %p\n", verbs);

    if (!rdma->verbs) {
        rdma->verbs = verbs;
        /*
         * Cannot propagate errp, as there is no error pointer
         * to be propagated.
         */
        ret = qemu_rdma_dest_prepare(rdma, NULL);
        if (ret) {
            fprintf(stderr, "rdma migration: error preparing dest!\n");
            goto err_rdma_dest_wait;
        }
    } else if (rdma->verbs != verbs) {
            fprintf(stderr, "ibv context not matching %p, %p!\n",
                    rdma->verbs, verbs);
            goto err_rdma_dest_wait;
    }

    qemu_set_fd_handler2(rdma->channel->fd, NULL, NULL, NULL, NULL);

    ret = qemu_rdma_alloc_qp(rdma);
    if (ret) {
        fprintf(stderr, "rdma migration: error allocating qp!\n");
        goto err_rdma_dest_wait;
    }

    ret = rdma_accept(rdma->cm_id, &conn_param);
    if (ret) {
        fprintf(stderr, "rdma_accept returns %d!\n", ret);
        goto err_rdma_dest_wait;
    }

    ret = rdma_get_cm_event(rdma->channel, &cm_event);
    if (ret) {
        fprintf(stderr, "rdma_accept get_cm_event failed %d!\n", ret);
        goto err_rdma_dest_wait;
    }

    if (cm_event->event != RDMA_CM_EVENT_ESTABLISHED) {
        fprintf(stderr, "rdma_accept not event established!\n");
        rdma_ack_cm_event(cm_event);
        goto err_rdma_dest_wait;
    }

    rdma_ack_cm_event(cm_event);

    ret = qemu_rdma_post_recv_control(rdma, 0);
    if (ret) {
        fprintf(stderr, "rdma migration: error posting second control recv!\n");
        goto err_rdma_dest_wait;
    }

    qemu_rdma_dump_gid("dest_connect", rdma->cm_id);

    return 0;

err_rdma_dest_wait:
    rdma->error_state = ret;
    qemu_rdma_cleanup(rdma);
    return ret;
}

/*
 * During each iteration of the migration, we listen for instructions
 * by the primary VM to perform dynamic page registrations before they
 * can perform RDMA operations.
 *
 * We respond with the 'rkey'.
 *
 * Keep doing this until the primary tells us to stop.
 */
static int qemu_rdma_registration_handle(QEMUFile *f, void *opaque,
                                         uint64_t flags)
{
    RDMAControlHeader resp = { .len = sizeof(RDMARegisterResult),
                               .type = RDMA_CONTROL_REGISTER_RESULT,
                               .repeat = 0,
                             };
    RDMAControlHeader blocks = { .type = RDMA_CONTROL_RAM_BLOCKS_RESULT, .repeat = 1 };
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    RDMAControlHeader head;
    RDMARegister *reg, *registers;
    RDMACompress *comp;
    RDMARegisterResult *reg_result;
    static RDMARegisterResult results[RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE];
    RDMALocalBlock *block;
    void *host_addr;
    int ret = 0;
    int idx = 0;
    int count = 0;
    int i = 0;

    CHECK_ERROR_STATE();

    do {
        DDDPRINTF("Waiting for next registration %" PRIu64 "...\n", flags);

        ret = qemu_rdma_exchange_recv(rdma, &head, RDMA_CONTROL_NONE);

        if (ret < 0) {
            break;
        }

        if (head.repeat > RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE) {
            fprintf(stderr, "Too many requests in this message (%d)."
                            "Bailing.\n", head.repeat);
            ret = -EIO;
            break;
        }

        switch (head.type) {
        case RDMA_CONTROL_COMPRESS:
            comp = (RDMACompress *) rdma->wr_data[idx].control_curr;

            DDPRINTF("Zapping zero chunk: %" PRId64
                    " bytes, index %d, offset %" PRId64 "\n",
                    comp->length, comp->block_idx, comp->offset);
            comp = (RDMACompress *) rdma->wr_data[idx].control_curr;
            block = &(rdma->local_ram_blocks.block[comp->block_idx]);

            host_addr = block->local_host_addr +
                            (comp->offset - block->offset);

            ram_handle_compressed(host_addr, comp->value, comp->length);
            break;

        case RDMA_CONTROL_REGISTER_FINISHED:
            DDDPRINTF("Current registrations complete.\n");
            goto out;

        case RDMA_CONTROL_RAM_BLOCKS_REQUEST:
            DPRINTF("Initial setup info requested.\n");

            if (rdma->pin_all) {
                ret = qemu_rdma_reg_whole_ram_blocks(rdma, &rdma->local_ram_blocks);
                if (ret) {
                    fprintf(stderr, "rdma migration: error dest "
                                    "registering ram blocks!\n");
                    goto out;
                }
            }

            /*
             * Dest uses this to prepare to transmit the RAMBlock descriptions
             * to the primary VM after connection setup.
             * Both sides use the "remote" structure to communicate and update
             * their "local" descriptions with what was sent.
             */
            for (i = 0; i < local->num_blocks; i++) {
                rdma->block[i].remote_host_addr =
                    (uint64_t)(local->block[i].local_host_addr);

                if (rdma->pin_all) {
                    rdma->block[i].remote_rkey = local->block[i].mr->rkey;
                }

                rdma->block[i].offset = local->block[i].offset;
                rdma->block[i].length = local->block[i].length;
            }

            blocks.len = rdma->local_ram_blocks.num_blocks 
                                                * sizeof(RDMARemoteBlock);

            ret = qemu_rdma_post_send_control(rdma, 
                                        (uint8_t *) rdma->block, &blocks);

            if (ret < 0) {
                fprintf(stderr, "rdma migration: error sending remote info!\n");
                goto out;
            }

            break;
        case RDMA_CONTROL_REGISTER_REQUEST:
            DDPRINTF("There are %d registration requests\n", head.repeat);

            resp.repeat = head.repeat;
            registers = (RDMARegister *) rdma->wr_data[idx].control_curr;

            for (count = 0; count < head.repeat; count++) {
                reg = &registers[count];
                reg_result = &results[count];

                DDPRINTF("Registration request (%d): %d"
                    " bytes, index %d, offset %" PRIu64 "\n",
                    count, reg->len, reg->current_index, reg->offset);

                block = &(rdma->local_ram_blocks.block[reg->current_index]);
                host_addr = (block->local_host_addr +
                            (reg->offset - block->offset));
                if (qemu_rdma_register_and_get_keys(rdma, block,
                            (uint8_t *)host_addr, NULL, &reg_result->rkey)) {
                    fprintf(stderr, "cannot get rkey!\n");
                    ret = -EINVAL;
                    goto out;
                }

                DDPRINTF("Registered rkey for this request: %x\n",
                                reg_result->rkey);
            }

            ret = qemu_rdma_post_send_control(rdma,
                            (uint8_t *) results, &resp);

            if (ret < 0) {
                fprintf(stderr, "Failed to send control buffer!\n");
                goto out;
            }
            break;
        case RDMA_CONTROL_REGISTER_RESULT:
            fprintf(stderr, "Invalid RESULT message at dest.\n");
            ret = -EIO;
            goto out;
        default:
            fprintf(stderr, "Unknown control message %s\n",
                                control_desc[head.type]);
            ret = -EIO;
            goto out;
        }
    } while (1);
out:
    if (ret < 0) {
        rdma->error_state = ret;
    }
    return ret;
}

static int qemu_rdma_registration_start(QEMUFile *f, void *opaque,
                                        uint64_t flags)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;

    CHECK_ERROR_STATE();

    DDDPRINTF("start section: %" PRIu64 "\n", flags);
    qemu_put_be64(f, RAM_SAVE_FLAG_HOOK);
    qemu_fflush(f);

    return 0;
}

/*
 * Inform dest that dynamic registrations are done for now.
 * First, flush writes, if any.
 */
static int qemu_rdma_registration_stop(QEMUFile *f, void *opaque,
                                       uint64_t flags)
{
    Error *local_err = NULL, **errp = &local_err;
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    RDMAControlHeader head = { .len = 0, .repeat = 1 };
    RDMAControlHeader resp = {.type = RDMA_CONTROL_RAM_BLOCKS_RESULT };
    int reg_result_idx;
    int ret = 0;

    CHECK_ERROR_STATE();

    qemu_fflush(f);
    ret = qemu_rdma_drain_cq(f, rdma);

    if (ret < 0) {
        goto err;
    }

    if (flags == RAM_CONTROL_SETUP) {
        head.type = RDMA_CONTROL_RAM_BLOCKS_REQUEST;
        DPRINTF("Sending registration setup for ram blocks...\n");

        ret = qemu_rdma_exchange_send(rdma, &head, NULL, &resp, &reg_result_idx);
        if (ret < 0) {
            ERROR(errp, "receiving remote info!\n");
            return ret;
        }

        qemu_rdma_move_header(rdma, reg_result_idx, &resp);
        memcpy(rdma->block, rdma->wr_data[reg_result_idx].control_curr, resp.len);

        ret = qemu_rdma_process_remote_blocks(rdma,
                        (resp.len / sizeof(RDMARemoteBlock)), errp);
        if (ret) {
            ERROR(errp, "processing remote blocks!\n");
            return ret;
        }

        if (rdma->pin_all) {
            ret = qemu_rdma_reg_whole_ram_blocks(rdma, &rdma->local_ram_blocks);
            if (ret) {
                fprintf(stderr, "rdma migration: error source "
                                "registering ram blocks!\n");
                return ret;
            }
        } else {
            int x = 0;
            for (x = 0; x < rdma->local_ram_blocks.num_blocks; x++) {
                RDMALocalBlock *block = &(rdma->local_ram_blocks.block[x]);
                int num_chunks = ram_chunk_count(block);
                block->remote_keys = g_malloc0(num_chunks * sizeof(uint32_t));
            }
        }
    }

    DDDPRINTF("Sending registration finish %" PRIu64 "...\n", flags);

    head.type = RDMA_CONTROL_REGISTER_FINISHED;
    ret = qemu_rdma_exchange_send(rdma, &head, NULL, NULL, NULL);

    if (ret < 0) {
        goto err;
    }

    return 0;
err:
    rdma->error_state = ret;
    return ret;
}

static int qemu_rdma_get_fd(void *opaque)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;

    return rdma->comp_channel->fd;
}

const QEMUFileOps rdma_read_ops = {
    .get_buffer    = qemu_rdma_get_buffer,
    .get_fd        = qemu_rdma_get_fd,
    .close         = qemu_rdma_close,
    .hook_ram_load = qemu_rdma_registration_handle,
};

const QEMUFileOps rdma_write_ops = {
    .put_buffer           = qemu_rdma_put_buffer,
    .close                = qemu_rdma_close,
    .before_ram_iterate   = qemu_rdma_registration_start,
    .after_ram_iterate    = qemu_rdma_registration_stop,
    .save_page            = qemu_rdma_save_page,
};

static void *qemu_fopen_rdma(RDMAContext *rdma, const char *mode)
{
    QEMUFileRDMA *r = g_malloc0(sizeof(QEMUFileRDMA));

    if (qemu_file_mode_is_not_valid(mode)) {
        return NULL;
    }

    r->rdma = rdma;

    if (mode[0] == 'w') {
        r->file = qemu_fopen_ops(r, &rdma_write_ops);
    } else {
        r->file = qemu_fopen_ops(r, &rdma_read_ops);
    }

    return r->file;
}

static void rdma_accept_incoming_migration(void *opaque)
{
    RDMAContext *rdma = opaque;
    int ret;
    QEMUFile *f;
    Error *local_err = NULL, **errp = &local_err;

    DPRINTF("Accepting rdma connection...\n");
    ret = qemu_rdma_accept(rdma);

    if (ret) {
        ERROR(errp, "RDMA Migration initialization failed!\n");
        return;
    }

    DPRINTF("Accepted migration\n");

    f = qemu_fopen_rdma(rdma, "rb");
    if (f == NULL) {
        ERROR(errp, "could not qemu_fopen_rdma!\n");
        qemu_rdma_cleanup(rdma);
        return;
    }

    rdma->migration_started_on_destination = 1;
    process_incoming_migration(f);
}

void rdma_start_incoming_migration(const char *host_port, Error **errp)
{
    int ret;
    RDMAContext *rdma;
    Error *local_err = NULL;

    DPRINTF("Starting RDMA-based incoming migration\n");
    rdma = qemu_rdma_data_init(host_port, &local_err);

    if (rdma == NULL) {
        goto err;
    }

    ret = qemu_rdma_dest_init(rdma, &local_err);

    if (ret) {
        goto err;
    }

    DPRINTF("qemu_rdma_dest_init success\n");
    ret = qemu_rdma_dest_prepare(rdma, &local_err);

    if (ret) {
        goto err;
    }

    DPRINTF("qemu_rdma_dest_prepare success\n");

    qemu_set_fd_handler2(rdma->channel->fd, NULL,
                         rdma_accept_incoming_migration, NULL,
                            (void *)(intptr_t) rdma);
    return;
err:
    error_propagate(errp, local_err);
    g_free(rdma);
}

void rdma_start_outgoing_migration(void *opaque,
                            const char *host_port, Error **errp)
{
    MigrationState *s = opaque;
    Error *local_err = NULL, **temp = &local_err;
    RDMAContext *rdma = qemu_rdma_data_init(host_port, &local_err);
    int ret = 0;

    if (rdma == NULL) {
        ERROR(temp, "Failed to initialize RDMA data structures! %d\n", ret);
        goto err;
    }

    ret = qemu_rdma_source_init(rdma, &local_err,
        s->enabled_capabilities[MIGRATION_CAPABILITY_X_RDMA_PIN_ALL]);

    if (ret) {
        goto err;
    }

    DPRINTF("qemu_rdma_source_init success\n");
    ret = qemu_rdma_connect(rdma, &local_err);

    if (ret) {
        goto err;
    }

    DPRINTF("qemu_rdma_source_connect success\n");

    s->file = qemu_fopen_rdma(rdma, "wb");
    s->total_time = qemu_get_clock_ms(rt_clock);
    migrate_fd_connect(s);
    return;
err:
    error_propagate(errp, local_err);
    g_free(rdma);
    migrate_fd_error(s);
}
