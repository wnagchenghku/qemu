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
#include "qemu/error-report.h"
#include "qemu/main-loop.h"
#include "qemu/sockets.h"
#include "qemu/bitmap.h"
#include "block/coroutine.h"
#include "trace.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <rdma/rdma_cma.h>
#include <sys/resource.h>

/*
 * Print and error on both the Monitor and the Log file.
 */
#define ERROR(errp, fmt, ...) \
    do { \
        Error **e = errp; \
        error_report("RDMA ERROR: " fmt, ## __VA_ARGS__); \
        if (e && ((*e) == NULL)) { \
            error_setg(e, "RDMA ERROR: " fmt, ## __VA_ARGS__); \
        } \
    } while (0)

#define SET_ERROR(rdma, err) if (!rdma->error_state) rdma->error_state = err

#define RDMA_RESOLVE_TIMEOUT_MS 10000

/* Do not merge data if larger than this. */
#define RDMA_MERGE_MAX (2 * 1024 * 1024)
#define RDMA_SEND_MAX (RDMA_MERGE_MAX / 4096)

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
#define RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE 4096

#define RDMA_CONTROL_VERSION_CURRENT 1
/*
 * Capabilities for negotiation.
 */
#define RDMA_CAPABILITY_PIN_ALL 0x01
#define RDMA_CAPABILITY_KEEPALIVE 0x02

/*
 * Max # missed keepalive before we assume remote side is unavailable.
 */
#define RDMA_CONNECTION_INTERVAL_MS 300
#define RDMA_KEEPALIVE_INTERVAL_MS 300
#define RDMA_KEEPALIVE_FIRST_MISSED_OFFSET 1000
#define RDMA_MAX_LOST_KEEPALIVE 10
#define RDMA_MAX_STARTUP_MISSED_KEEPALIVE 400

/*
 * Add the other flags above to this list of known capabilities
 * as they are introduced.
 */
static uint32_t known_capabilities = RDMA_CAPABILITY_PIN_ALL
                                   | RDMA_CAPABILITY_KEEPALIVE
                                   ;
static QEMUTimer *connection_timer = NULL;
static QEMUTimer *keepalive_timer = NULL;

#define CHECK_ERROR_STATE() \
    do { \
        if (rdma->error_state) { \
            if (!rdma->error_reported) { \
                error_report("RDMA is in an error state waiting migration" \
                                " to abort!"); \
                rdma->error_reported = 1; \
            } \
            return rdma->error_state; \
        } \
    } while (0);

/*
 * A work request ID is 64-bits and we split up these bits
 * into 3 parts:
 *
 * bits 0-15 : type of control message, 2^16
 * bits 16-29: ram block index, 2^14
 * bits 30-63: ram block chunk number, 2^34
 *
 * The last two bit ranges are only used for RDMA writes,
 * in order to track their completion and potentially
 * also track unregistration status of the message.
 */
#define RDMA_WRID_TYPE_SHIFT  0UL
#define RDMA_WRID_BLOCK_SHIFT 16UL
#define RDMA_WRID_CHUNK_SHIFT 30UL

#define RDMA_WRID_TYPE_MASK \
    ((1UL << RDMA_WRID_BLOCK_SHIFT) - 1UL)

#define RDMA_WRID_BLOCK_MASK \
    (~RDMA_WRID_TYPE_MASK & ((1UL << RDMA_WRID_CHUNK_SHIFT) - 1UL))

#define RDMA_WRID_CHUNK_MASK (~RDMA_WRID_BLOCK_MASK & ~RDMA_WRID_TYPE_MASK)

/*
 * RDMA migration protocol:
 * 1. RDMA Writes (data messages, i.e. RAM)
 * 2. IB Send/Recv (control channel messages)
 */
enum {
    RDMA_WRID_NONE = 0,
    RDMA_WRID_RDMA_WRITE_REMOTE = 1,
    RDMA_WRID_RDMA_WRITE_LOCAL = 2,
    RDMA_WRID_RDMA_KEEPALIVE = 3,
    RDMA_WRID_SEND_CONTROL = 2000,
    RDMA_WRID_RECV_CONTROL = 4000,
};

static const char *wrid_desc[] = {
    [RDMA_WRID_NONE] = "NONE",
    [RDMA_WRID_RDMA_WRITE_REMOTE] = "WRITE RDMA REMOTE",
    [RDMA_WRID_RDMA_WRITE_LOCAL] = "WRITE RDMA LOCAL",
    [RDMA_WRID_RDMA_KEEPALIVE] = "KEEPALIVE",
    [RDMA_WRID_SEND_CONTROL] = "CONTROL SEND",
    [RDMA_WRID_RECV_CONTROL] = "CONTROL RECV",
};

/*
 * Work request IDs for IB SEND messages only (not RDMA writes).
 * This is used by the migration protocol to transmit
 * control messages (such as device state and registration commands)
 *
 * We could use more WRs, but we have enough for now.
 */
enum {
    RDMA_WRID_READY = 0,
    RDMA_WRID_DATA,
    RDMA_WRID_CONTROL,
    RDMA_WRID_MAX,
};

/*
 * SEND/RECV IB Control Messages.
 */
enum {
    RDMA_CONTROL_NONE = 0,
    RDMA_CONTROL_ERROR,
    RDMA_CONTROL_READY,               /* ready to receive */
    RDMA_CONTROL_QEMU_FILE,           /* QEMUFile-transmitted bytes */
    RDMA_CONTROL_RAM_BLOCKS_REQUEST,  /* RAMBlock synchronization */
    RDMA_CONTROL_RAM_BLOCKS_RESULT,   /* RAMBlock synchronization */
    RDMA_CONTROL_COMPRESS,            /* page contains repeat values */
    RDMA_CONTROL_REGISTER_REQUEST,    /* dynamic page registration */
    RDMA_CONTROL_REGISTER_RESULT,     /* key to use after registration */
    RDMA_CONTROL_REGISTER_FINISHED,   /* current iteration finished */
    RDMA_CONTROL_UNREGISTER_REQUEST,  /* dynamic UN-registration */
    RDMA_CONTROL_UNREGISTER_FINISHED, /* unpinning finished */
};

static const char *control_desc[] = {
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
    [RDMA_CONTROL_UNREGISTER_REQUEST] = "UNREGISTER REQUEST",
    [RDMA_CONTROL_UNREGISTER_FINISHED] = "UNREGISTER FINISHED",
};

/*
 * Memory and MR structures used to represent an IB Send/Recv work request.
 * This is *not* used for RDMA writes, only IB Send/Recv.
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
typedef struct QEMU_PACKED RDMACapabilities {
    uint32_t version;
    uint32_t flags;
    uint32_t keepalive_rkey;
    uint64_t keepalive_addr;
} RDMACapabilities;

static uint64_t htonll(uint64_t v)
{
    union { uint32_t lv[2]; uint64_t llv; } u;
    u.lv[0] = htonl(v >> 32);
    u.lv[1] = htonl(v & 0xFFFFFFFFULL);
    return u.llv;
}

static uint64_t ntohll(uint64_t v) {
    union { uint32_t lv[2]; uint64_t llv; } u;
    u.llv = v;
    return ((uint64_t)ntohl(u.lv[0]) << 32) | (uint64_t) ntohl(u.lv[1]);
}

static void caps_to_network(RDMACapabilities *cap)
{
    cap->version = htonl(cap->version);
    cap->flags = htonl(cap->flags);
    cap->keepalive_rkey = htonl(cap->keepalive_rkey);
    cap->keepalive_addr = htonll(cap->keepalive_addr);
}

static void network_to_caps(RDMACapabilities *cap)
{
    cap->version = ntohl(cap->version);
    cap->flags = ntohl(cap->flags);
    cap->keepalive_rkey = ntohl(cap->keepalive_rkey);
    cap->keepalive_addr = ntohll(cap->keepalive_addr);
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
    struct ibv_mr **pmr;      /* MRs for remote chunk-level registration */
    struct ibv_mr *mr;        /* MR for non-chunk-level registration */
    struct ibv_mr **pmr_src;  /* MRs for copy chunk-level registration */
    struct ibv_mr *mr_src;    /* MR for copy non-chunk-level registration */
    struct ibv_mr **pmr_dest; /* MRs for copy chunk-level registration */
    struct ibv_mr *mr_dest;   /* MR for copy non-chunk-level registration */
    uint32_t *remote_keys;    /* rkeys for chunk-level registration */
    uint32_t remote_rkey;     /* rkeys for non-chunk-level registration */
    int      index;           /* which block are we */
    bool     is_ram_block;
    int      nb_chunks;
    unsigned long *transit_bitmap;
    unsigned long *unregister_bitmap;
} RDMALocalBlock;

/*
 * Also represents a RAMblock, but only on the dest.
 * This gets transmitted by the dest during connection-time
 * to the source VM and then is used to populate the
 * corresponding RDMALocalBlock with
 * the information needed to perform the actual RDMA.
 */
typedef struct QEMU_PACKED RDMADestBlock {
    uint64_t remote_host_addr;
    uint64_t offset;
    uint64_t length;
    uint32_t remote_rkey;
    uint32_t padding;
} RDMADestBlock;

static void dest_block_to_network(RDMADestBlock *db)
{
    db->remote_host_addr = htonll(db->remote_host_addr);
    db->offset = htonll(db->offset);
    db->length = htonll(db->length);
    db->remote_rkey = htonl(db->remote_rkey);
}

static void network_to_dest_block(RDMADestBlock *db)
{
    db->remote_host_addr = ntohll(db->remote_host_addr);
    db->offset = ntohll(db->offset);
    db->length = ntohll(db->length);
    db->remote_rkey = ntohl(db->remote_rkey);
}

/*
 * Virtual address of the above structures used for transmitting
 * the RAMBlock descriptions at connection-time.
 * This structure is *not* transmitted.
 */
typedef struct RDMALocalBlocks {
    int nb_blocks;
    bool     init;             /* main memory init complete */
    RDMALocalBlock *block;
} RDMALocalBlocks;

/*
 * We provide RDMA to QEMU by way of 2 mechanisms:
 *
 * 1. Local copy to remote copy
 * 2. Local copy to local copy - like memcpy().
 *
 * Three instances of this structure are maintained inside of RDMAContext
 * to manage both mechanisms.
 */
typedef struct RDMACurrentChunk {
    /* store info about current buffer so that we can
       merge it with future sends */
    uint64_t current_addr;
    uint64_t current_length;
    /* index of ram block the current buffer belongs to */
    int current_block_idx;
    /* index of the chunk in the current ram block */
    int current_chunk;

    uint64_t block_offset;
    uint64_t offset;

    /* parameters for qemu_rdma_write() */
    uint64_t chunk_idx;
    uint8_t *chunk_start;
    uint8_t *chunk_end;
    RDMALocalBlock *block;
    uint8_t *addr;
    uint64_t chunks;
} RDMACurrentChunk;

/* structure to exchange data which is needed to connect the QPs */
struct cm_con_data_t
{
    uint32_t qp_num;
    uint16_t lid;
    uint8_t gid[16];
}__attribute__ ((packed));

/*
 * Three copies of the following strucuture are used to hold the infiniband
 * connection variables for each of the aformentioned mechanisms, one for
 * remote copy and two local copy.
 */
typedef struct RDMALocalContext {
    bool source;
    bool dest;
    bool connected;
    char *host;
    int port;
    struct rdma_cm_id *cm_id;
    struct rdma_cm_id *listen_id;
    struct rdma_event_channel *channel;
    struct ibv_context *verbs;
    struct ibv_pd *pd;
    struct ibv_comp_channel *comp_chan;
    struct ibv_cq *cq;
    struct ibv_qp *qp;
    int nb_sent;
    int64_t start_time;
    int max_nb_sent;
    const char * id_str;

    int sock;
    int ib_port;
    char *dev_name;
    struct ibv_port_attr port_attr;
    struct cm_con_data_t remote_props;
    int gid_idx;
} RDMALocalContext;

/*
 * Main data structure for RDMA state.
 * While there is only one copy of this structure being allocated right now,
 * this is the place where one would start if you wanted to consider
 * having more than one RDMA connection open at the same time.
 *
 * It is used for performing both local and remote RDMA operations
 * with a single RDMA connection.
 *
 * Local operations are done by allocating separate queue pairs after
 * the initial RDMA remote connection is initalized.
 */
typedef struct RDMAContext {
    RDMAWorkRequestData wr_data[RDMA_WRID_MAX];

    /*
     * This is used by *_exchange_send() to figure out whether or not
     * the initial "READY" message has already been received or not.
     * This is because other functions may potentially poll() and detect
     * the READY message before send() does, in which case we need to
     * know if it completed.
     */
    int control_ready_expected;

    /* number of posts */
    int nb_sent;

    RDMACurrentChunk chunk_remote;
    RDMACurrentChunk chunk_local_src;
    RDMACurrentChunk chunk_local_dest;

    bool pin_all;
    bool do_keepalive;

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
    RDMADestBlock  *dest_blocks;

    /*
     * Migration on *destination* started.
     * Then use coroutine yield function.
     * Source runs in a thread, so we don't care.
     */
    bool migration_started;

    int total_registrations;
    int total_writes;

    int unregister_current, unregister_next;
    uint64_t unregistrations[RDMA_SEND_MAX];

    GHashTable *blockmap;

    uint64_t keepalive;
    uint64_t last_keepalive;
    uint64_t nb_missed_keepalive;
    uint64_t next_keepalive;
    struct ibv_mr *keepalive_mr;
    struct ibv_mr *next_keepalive_mr;
    uint32_t keepalive_rkey;
    uint64_t keepalive_addr;
    bool keepalive_startup;

    RDMALocalContext lc_src;
    RDMALocalContext lc_dest;
    RDMALocalContext lc_remote;

    /* who are we? */
    bool source;
    bool dest;
} RDMAContext;

static void close_ibv(RDMAContext *rdma, RDMALocalContext *lc)
{

    if (lc->qp) {
        struct ibv_qp_attr attr = {.qp_state = IBV_QPS_ERR };
        ibv_modify_qp(lc->qp, &attr, IBV_QP_STATE);
        rdma_destroy_qp(lc->cm_id);
        lc->qp = NULL;
    }

    if (lc->cq) {
        ibv_destroy_cq(lc->cq);
        lc->cq = NULL;
    }

    if (lc->comp_chan) {
        ibv_destroy_comp_channel(lc->comp_chan);
        lc->comp_chan = NULL;
    }

    if (lc->pd) {
        ibv_dealloc_pd(lc->pd);
        lc->pd = NULL;
    }

    if (lc->verbs) {
        ibv_close_device(lc->verbs);
        lc->verbs = NULL;
    }

    if (lc->cm_id) {

        rdma_destroy_id(lc->cm_id);
        rdma->lc_remote.cm_id = NULL;
    }

    if (lc->listen_id) {
        rdma_destroy_id(lc->listen_id);
        lc->listen_id = NULL;
    }

    if (lc->channel) {
        rdma_destroy_event_channel(lc->channel);
        lc->channel = NULL;
    }

    g_free(lc->host);
    lc->host = NULL;
}

/*
 * Create protection domain and completion queues
 */
static int qemu_rdma_alloc_pd_cq_qp(RDMAContext *rdma, RDMALocalContext *lc)
{
    struct rlimit r = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY };
    struct ibv_qp_init_attr attr = { 0 };
    int ret;

    if (getrlimit(RLIMIT_MEMLOCK, &r) < 0) {
        perror("getrlimit");
        ERROR(NULL, "getrlimit(RLIMIT_MEMLOCK)");
        goto err_alloc;
    }

    trace_qemu_rdma_alloc_pd_cq_qp_limits(r.rlim_cur, r.rlim_max);

    lc->pd = ibv_alloc_pd(lc->verbs);
    if (!lc->pd) {
        ERROR(NULL, "allocate protection domain");
        goto err_alloc;
    }

    /* create completion channel */
    lc->comp_chan = ibv_create_comp_channel(lc->verbs);
    if (!lc->comp_chan) {
        ERROR(NULL, "allocate completion channel");
        goto err_alloc;
    }

    /*
     * Completion queue can be filled by both read and write work requests,
     * so must reflect the sum of both possible queue sizes.
     */
    lc->cq = ibv_create_cq(lc->verbs, (RDMA_SEND_MAX * 3), NULL,
                           lc->comp_chan, 0);
    if (!lc->cq) {
        ERROR(NULL, "allocate completion queue");
        goto err_alloc;
    }

    attr.cap.max_send_wr = RDMA_SEND_MAX;
    attr.cap.max_recv_wr = 3;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    attr.send_cq = lc->cq;
    attr.recv_cq = lc->cq;
    attr.qp_type = IBV_QPT_RC;

    ret = rdma_create_qp(lc->cm_id, lc->pd, &attr);
    if (ret) {
        ERROR(NULL, "alloc queue pair");
        goto err_alloc;
    }

    lc->qp = lc->cm_id->qp;

    return 0;

err_alloc:
    ERROR(NULL, "allocating pd and cq and qp! Your mlock()"
                " limits may be too low. Please check $ ulimit -a # and "
                "search for 'ulimit -l' in the output");
    close_ibv(rdma, lc);
    return -EINVAL;
}

/*
 * Interface to the rest of the migration call stack.
 */
typedef struct QEMUFileRDMA {
    RDMAContext *rdma;
    size_t len;
    void *file;
} QEMUFileRDMA;

/*
 * Main structure for IB Send/Recv control messages.
 * This gets prepended at the beginning of every Send/Recv.
 */
typedef struct QEMU_PACKED {
    uint32_t len;     /* Total length of data portion */
    uint32_t type;    /* which control command to perform */
    uint32_t repeat;  /* number of commands in data portion of same type */
    uint32_t padding;
} RDMAControlHeader;

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
 * Information sent by the source VM to inform the dest
 * to register an single chunk of memory before we can perform
 * the actual RDMA operation.
 */
typedef struct QEMU_PACKED {
    union QEMU_PACKED {
        uint64_t current_addr;  /* offset into the ramblock of the chunk */
        uint64_t chunk;         /* chunk to lookup if unregistering */
    } key;
    uint32_t current_block_idx;     /* which ramblock the chunk belongs to */
    uint32_t padding;
    uint64_t chunks;            /* how many sequential chunks to register */
} RDMARegister;

static void register_to_network(RDMARegister *reg)
{
    reg->key.current_addr = htonll(reg->key.current_addr);
    reg->current_block_idx = htonl(reg->current_block_idx);
    reg->chunks = htonll(reg->chunks);
}

static void network_to_register(RDMARegister *reg)
{
    reg->key.current_addr = ntohll(reg->key.current_addr);
    reg->current_block_idx = ntohl(reg->current_block_idx);
    reg->chunks = ntohll(reg->chunks);
}

typedef struct QEMU_PACKED {
    uint32_t value;     /* if zero, we will madvise() */
    uint32_t block_idx; /* which ram block index */
    uint64_t offset;    /* where in the remote ramblock this chunk */
    uint64_t length;    /* length of the chunk */
} RDMACompress;

static void compress_to_network(RDMACompress *comp)
{
    comp->value = htonl(comp->value);
    comp->block_idx = htonl(comp->block_idx);
    comp->offset = htonll(comp->offset);
    comp->length = htonll(comp->length);
}

static void network_to_compress(RDMACompress *comp)
{
    comp->value = ntohl(comp->value);
    comp->block_idx = ntohl(comp->block_idx);
    comp->offset = ntohll(comp->offset);
    comp->length = ntohll(comp->length);
}

/*
 * The result of the dest's memory registration produces an "rkey"
 * which the source VM must reference in order to perform
 * the RDMA operation.
 */
typedef struct QEMU_PACKED {
    uint32_t rkey;
    uint32_t padding;
    uint64_t host_addr;
} RDMARegisterResult;

static void result_to_network(RDMARegisterResult *result)
{
    result->rkey = htonl(result->rkey);
    result->host_addr = htonll(result->host_addr);
};

static void network_to_result(RDMARegisterResult *result)
{
    result->rkey = ntohl(result->rkey);
    result->host_addr = ntohll(result->host_addr);
};

const char *print_wrid(int wrid);
static int qemu_rdma_exchange_send(RDMAContext *rdma, RDMAControlHeader *head,
                                   uint8_t *data, RDMAControlHeader *resp,
                                   int *resp_idx,
                                   int (*callback)(RDMAContext *rdma));

static inline uint64_t ram_chunk_index(const uint8_t *start,
                                       const uint8_t *host)
{
    return ((uintptr_t) host - (uintptr_t) start) >> RDMA_REG_CHUNK_SHIFT;
}

static inline uint8_t *ram_chunk_start(const RDMALocalBlock *rdma_ram_block,
                                       uint64_t i)
{
    return (uint8_t *)(uintptr_t)(rdma_ram_block->local_host_addr +
                                  (i << RDMA_REG_CHUNK_SHIFT));
}

static inline uint8_t *ram_chunk_end(const RDMALocalBlock *rdma_ram_block,
                                     uint64_t i)
{
    uint8_t *result = ram_chunk_start(rdma_ram_block, i) +
                                         (1UL << RDMA_REG_CHUNK_SHIFT);

    if (result > (rdma_ram_block->local_host_addr + rdma_ram_block->length)) {
        result = rdma_ram_block->local_host_addr + rdma_ram_block->length;
    }

    return result;
}

static int add_block(RDMAContext *rdma, void *host_addr,
                         ram_addr_t block_offset, uint64_t length)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    RDMALocalBlock *block = g_hash_table_lookup(rdma->blockmap,
        (void *)(uintptr_t)block_offset);
    RDMALocalBlock *old = local->block;

    assert(block == NULL);

    local->block = g_malloc0(sizeof(RDMALocalBlock) * (local->nb_blocks + 1));

    if (local->nb_blocks) {
        int x;

        for (x = 0; x < local->nb_blocks; x++) {
            g_hash_table_remove(rdma->blockmap, (void *)(uintptr_t)old[x].offset);
            g_hash_table_insert(rdma->blockmap, (void *)(uintptr_t)old[x].offset,
                                                &local->block[x]);
        }
        memcpy(local->block, old, sizeof(RDMALocalBlock) * local->nb_blocks);
        g_free(old);
    }

    block = &local->block[local->nb_blocks];

    block->local_host_addr = host_addr;
    block->offset = block_offset;
    block->length = length;
    block->index = local->nb_blocks;
    block->nb_chunks = ram_chunk_index(host_addr, host_addr + length) + 1UL;
    block->transit_bitmap = bitmap_new(block->nb_chunks);
    bitmap_clear(block->transit_bitmap, 0, block->nb_chunks);
    block->unregister_bitmap = bitmap_new(block->nb_chunks);
    bitmap_clear(block->unregister_bitmap, 0, block->nb_chunks);
    block->remote_keys = g_malloc0(block->nb_chunks * sizeof(uint32_t));

    block->is_ram_block = local->init ? false : true;

    g_hash_table_insert(rdma->blockmap, (void *) (uintptr_t) block_offset, block);

    //trace_qemu_rdma_add_block(local->nb_blocks, block->local_host_addr, block->offset, block->length, (block->local_host_addr + block->length), BITS_TO_LONGS(block->nb_chunks) * sizeof(unsigned long) * 8, block->nb_chunks);

    local->nb_blocks++;

    return 0;
}

/*
 * Memory regions need to be registered with the device and queue pairs setup
 * in advanced before the migration starts. This tells us where the RAM blocks
 * are so that we can register them individually.
 */
static int qemu_rdma_init_one_block(const char *block_name, void *host_addr,
    ram_addr_t block_offset, ram_addr_t length, void *opaque)
{
    return add_block(opaque, host_addr, block_offset, length);
}

/*
 * Identify the RAMBlocks and their quantity. They will be references to
 * identify chunk boundaries inside each RAMBlock and also be referenced
 * during dynamic page registration.
 */
static int qemu_rdma_init_ram_blocks(RDMAContext *rdma)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;

    assert(rdma->blockmap == NULL);
    rdma->blockmap = g_hash_table_new(g_direct_hash, g_direct_equal);
    memset(local, 0, sizeof *local);
    qemu_ram_foreach_block(qemu_rdma_init_one_block, rdma);
    trace_qemu_rdma_init_ram_blocks(local->nb_blocks);
    rdma->dest_blocks = (RDMADestBlock *) g_malloc0(sizeof(RDMADestBlock) *
                        rdma->local_ram_blocks.nb_blocks);
    local->init = true;
    return 0;
}

static void qemu_rdma_free_pmrs(RDMAContext *rdma, RDMALocalBlock *block,
                               struct ibv_mr ***mrs)
{
    if (*mrs) {
        int j;

        for (j = 0; j < block->nb_chunks; j++) {
            if (!(*mrs)[j]) {
                continue;
            }
            ibv_dereg_mr((*mrs)[j]);
            rdma->total_registrations--;
        }
        g_free(*mrs);

        *mrs = NULL;
    }
}

static void qemu_rdma_free_mr(RDMAContext *rdma, struct ibv_mr **mr)
{
    if (*mr) {
        ibv_dereg_mr(*mr);
        rdma->total_registrations--;
        *mr = NULL;
    }
}

static int delete_block(RDMAContext *rdma, ram_addr_t block_offset)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    RDMALocalBlock *block = g_hash_table_lookup(rdma->blockmap,
        (void *) (uintptr_t) block_offset);
    RDMALocalBlock *old = local->block;
    int x;

    assert(block);

    qemu_rdma_free_pmrs(rdma, block, &block->pmr);
    qemu_rdma_free_pmrs(rdma, block, &block->pmr_src);
    qemu_rdma_free_pmrs(rdma, block, &block->pmr_dest);

    qemu_rdma_free_mr(rdma, &block->mr);
    qemu_rdma_free_mr(rdma, &block->mr_src);
    qemu_rdma_free_mr(rdma, &block->mr_dest);

    g_free(block->transit_bitmap);
    block->transit_bitmap = NULL;

    g_free(block->unregister_bitmap);
    block->unregister_bitmap = NULL;

    g_free(block->remote_keys);
    block->remote_keys = NULL;

    for (x = 0; x < local->nb_blocks; x++) {
        g_hash_table_remove(rdma->blockmap, (void *)(uintptr_t)old[x].offset);
    }

    if (local->nb_blocks > 1) {

        local->block = g_malloc0(sizeof(RDMALocalBlock) *
                                    (local->nb_blocks - 1));

        if (block->index) {
            memcpy(local->block, old, sizeof(RDMALocalBlock) * block->index);
        }

        if (block->index < (local->nb_blocks - 1)) {
            RDMALocalBlock * end = old + (block->index + 1);
            for (x = 0; x < (local->nb_blocks - (block->index + 1)); x++) {
                end[x].index--;
            }

            memcpy(local->block + block->index, end,
                sizeof(RDMALocalBlock) *
                    (local->nb_blocks - (block->index + 1)));
        }
    } else {
        assert(block == local->block);
        local->block = NULL;
    }

    g_free(old);

    local->nb_blocks--;

    //trace_qemu_rdma_delete_block(local->nb_blocks, (uint64_t)block->local_host_addr, block->offset, block->length, (uint64_t)(block->local_host_addr + block->length), BITS_TO_LONGS(block->nb_chunks) * sizeof(unsigned long) * 8, block->nb_chunks);

    if (local->nb_blocks) {
        for (x = 0; x < local->nb_blocks; x++) {
            g_hash_table_insert(rdma->blockmap, (void *)(uintptr_t)local->block[x].offset,
                                                &local->block[x]);
        }
    }

    return 0;
}

/*
 * Put in the log file which RDMA device was opened and the details
 * associated with that device.
 */
static void qemu_rdma_dump_id(const char *who, struct ibv_context *verbs)
{
    struct ibv_port_attr port;

    if (ibv_query_port(verbs, 1, &port)) {
        error_report("Failed to query port information");
        return;
    }

    printf("%s RDMA Device opened: kernel name %s "
           "uverbs device name %s, "
           "infiniband_verbs class device path %s, "
           "infiniband class device path %s, "
           "transport: (%d) %s\n",
                who,
                verbs->device->name,
                verbs->device->dev_name,
                verbs->device->dev_path,
                verbs->device->ibdev_path,
                port.link_layer,
                (port.link_layer == IBV_LINK_LAYER_INFINIBAND) ? "Infiniband" :
                 ((port.link_layer == IBV_LINK_LAYER_ETHERNET)
                    ? "Ethernet" : "Unknown"));
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
    trace_qemu_rdma_dump_gid(who, sgid, dgid);
}

/*
 * As of now, IPv6 over RoCE / iWARP is not supported by linux.
 * We will try the next addrinfo struct, and fail if there are
 * no other valid addresses to bind against.
 *
 * If user is listening on '[::]', then we will not have a opened a device
 * yet and have no way of verifying if the device is RoCE or not.
 *
 * In this case, the source VM will throw an error for ALL types of
 * connections (both IPv4 and IPv6) if the destination machine does not have
 * a regular infiniband network available for use.
 *
 * The only way to guarantee that an error is thrown for broken kernels is
 * for the management software to choose a *specific* interface at bind time
 * and validate what time of hardware it is.
 *
 * Unfortunately, this puts the user in a fix:
 *
 *  If the source VM connects with an IPv4 address without knowing that the
 *  destination has bound to '[::]' the migration will unconditionally fail
 *  unless the management software is explicitly listening on the the IPv4
 *  address while using a RoCE-based device.
 *
 *  If the source VM connects with an IPv6 address, then we're OK because we can
 *  throw an error on the source (and similarly on the destination).
 *
 *  But in mixed environments, this will be broken for a while until it is fixed
 *  inside linux.
 *
 * We do provide a *tiny* bit of help in this function: We can list all of the
 * devices in the system and check to see if all the devices are RoCE or
 * Infiniband.
 *
 * If we detect that we have a *pure* RoCE environment, then we can safely
 * thrown an error even if the management software has specified '[::]' as the
 * bind address.
 *
 * However, if there is are multiple hetergeneous devices, then we cannot make
 * this assumption and the user just has to be sure they know what they are
 * doing.
 *
 * Patches are being reviewed on linux-rdma.
 */
static int qemu_rdma_broken_ipv6_kernel(Error **errp, struct ibv_context *verbs)
{
    struct ibv_port_attr port_attr;

    /* This bug only exists in linux, to our knowledge. */
#ifdef CONFIG_LINUX

    /*
     * Verbs are only NULL if management has bound to '[::]'.
     *
     * Let's iterate through all the devices and see if there any pure IB
     * devices (non-ethernet).
     *
     * If not, then we can safely proceed with the migration.
     * Otherwise, there are no guarantees until the bug is fixed in linux.
     */
    if (!verbs) {
        int num_devices, x;
        struct ibv_device ** dev_list = ibv_get_device_list(&num_devices);
        bool roce_found = false;
        bool ib_found = false;

        for (x = 0; x < num_devices; x++) {
            verbs = ibv_open_device(dev_list[x]);
            if (!verbs) {
                if (errno == EPERM) {
                    continue;
                } else {
                    return -EINVAL;
                }
            }

            if (ibv_query_port(verbs, 1, &port_attr)) {
                ibv_close_device(verbs);
                ERROR(errp, "Could not query initial IB port");
                return -EINVAL;
            }

            if (port_attr.link_layer == IBV_LINK_LAYER_INFINIBAND) {
                ib_found = true;
            } else if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
                roce_found = true;
            }

            ibv_close_device(verbs);

        }

        if (roce_found) {
            if (ib_found) {
                fprintf(stderr, "WARN: migrations may fail:"
                                " IPv6 over RoCE / iWARP in linux"
                                " is broken. But since you appear to have a"
                                " mixed RoCE / IB environment, be sure to only"
                                " migrate over the IB fabric until the kernel "
                                " fixes the bug.\n");
            } else {
                ERROR(errp, "You only have RoCE / iWARP devices in your systems"
                            " and your management software has specified '[::]'"
                            ", but IPv6 over RoCE / iWARP is not supported in Linux.");
                return -ENONET;
            }
        }

        return 0;
    }

    /*
     * If we have a verbs context, that means that some other than '[::]' was
     * used by the management software for binding. In which case we can
     * warn the user about a potential broken kernel;
     */

    /* IB ports start with 1, not 0 */
    if (ibv_query_port(verbs, 1, &port_attr)) {
        ERROR(errp, "Could not query initial IB port");
        return -EINVAL;
    }

    if (port_attr.link_layer == IBV_LINK_LAYER_ETHERNET) {
        ERROR(errp, "Linux kernel's RoCE / iWARP does not support IPv6 "
                    "(but patches on linux-rdma in progress)");
        return -ENONET;
    }

#endif

    return 0;
}

static int qemu_rdma_reg_keepalive(RDMAContext *rdma)
{
    rdma->keepalive_mr = ibv_reg_mr(rdma->lc_remote.pd,
            &rdma->keepalive, sizeof(rdma->keepalive),
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    if (!rdma->keepalive_mr) {
        perror("Failed to register keepalive location!");
        SET_ERROR(rdma, -ENOMEM);
        goto err_alloc;
    }

    rdma->next_keepalive_mr = ibv_reg_mr(rdma->lc_remote.pd,
            &rdma->next_keepalive, sizeof(rdma->next_keepalive),
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);

    if (!rdma->next_keepalive_mr) {
        perror("Failed to register next keepalive location!");
        SET_ERROR(rdma, -ENOMEM);
        goto err_alloc;
    }

    return 0;

err_alloc:

    if (rdma->keepalive_mr) {
        ibv_dereg_mr(rdma->keepalive_mr);
        rdma->keepalive_mr = NULL;
    }

    if (rdma->next_keepalive_mr) {
        ibv_dereg_mr(rdma->next_keepalive_mr);
        rdma->next_keepalive_mr = NULL;
    }

    return -1;
}

static int qemu_rdma_reg_whole_mr(RDMAContext *rdma,
                                  struct ibv_pd *pd,
                                  struct ibv_mr **mr,
                                  int index)
{
    RDMALocalBlocks *local = &rdma->local_ram_blocks;

    *mr = ibv_reg_mr(pd,
                local->block[index].local_host_addr,
                local->block[index].length,
                IBV_ACCESS_LOCAL_WRITE |
                IBV_ACCESS_REMOTE_WRITE
                );
    if (!(*mr)) {
        perror("Failed to register local dest ram block!\n");
        return -1;
    }
    rdma->total_registrations++;

    return 0;
};

static int qemu_rdma_reg_whole_ram_blocks(RDMAContext *rdma)
{
    int i;
    RDMALocalBlocks *local = &rdma->local_ram_blocks;

    for (i = 0; i < local->nb_blocks; i++) {
        if (qemu_rdma_reg_whole_mr(rdma, rdma->lc_remote.pd, &local->block[i].mr, i)) {
            break;
        }

        if (migrate_use_mc_rdma_copy()) {
            if (rdma->source) {
                if (qemu_rdma_reg_whole_mr(rdma, rdma->lc_src.pd,
                        &local->block[i].mr_src, i)) {
                    break;
                }
            } else {
                if (qemu_rdma_reg_whole_mr(rdma, rdma->lc_dest.pd,
                        &local->block[i].mr_dest, i)) {
                    break;
                }
            }
        }
    }

    if (i >= local->nb_blocks) {
        return 0;
    }

    for (i--; i >= 0; i--) {
        qemu_rdma_free_mr(rdma, &local->block[i].mr);
        if (migrate_use_mc_rdma_copy()) {
            qemu_rdma_free_mr(rdma, rdma->source ?
                                &local->block[i].mr_src :
                                &local->block[i].mr_dest);
        }
    }

    return -1;

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
static int qemu_rdma_search_ram_block(RDMAContext *rdma,
                                      uintptr_t block_offset,
                                      uint64_t offset,
                                      uint64_t length,
                                      uint64_t *block_index,
                                      uint64_t *chunk_index)
{
    uint64_t current_addr = block_offset + offset;
    RDMALocalBlock *block = g_hash_table_lookup(rdma->blockmap,
                                                (void *) block_offset);
    assert(block);
    assert(current_addr >= block->offset);
    assert((current_addr + length) <= (block->offset + block->length));

    *block_index = block->index;
    *chunk_index = ram_chunk_index(block->local_host_addr,
                block->local_host_addr + (current_addr - block->offset));

    return 0;
}

/*
 * Register a chunk with IB. If the chunk was already registered
 * previously, then skip.
 *
 * Also return the keys associated with the registration needed
 * to perform the actual RDMA operation.
 */
static int qemu_rdma_register_and_get_keys(RDMAContext *rdma,
                                           RDMACurrentChunk *cc,
                                           RDMALocalContext *lc,
                                           bool copy,
                                           uint32_t *lkey,
                                           uint32_t *rkey)
{
    struct ibv_mr ***pmr = copy ? (rdma->source ? &cc->block->pmr_src :
                           &cc->block->pmr_dest) : &cc->block->pmr;
    struct ibv_mr **mr = copy ? (rdma->source ? &cc->block->mr_src :
                         &cc->block->mr_dest) : &cc->block->mr;

    /*
     * Use pre-registered keys for the entire VM, if available.
     */
    if (*mr) {
        if (lkey) {
            *lkey = (*mr)->lkey;
        }
        if (rkey) {
            *rkey = (*mr)->rkey;
        }
        return 0;
    }

    /* allocate memory to store chunk MRs */
    if (!(*pmr)) {
        *pmr = g_malloc0(cc->block->nb_chunks * sizeof(struct ibv_mr *));
        if (!(*pmr)) {
            return -1;
        }
    }

    /*
     * If 'rkey', then we're the destination, so grant access to the source.
     *
     * If 'lkey', then we're the source, so grant access only to ourselves.
     */
    if (!(*pmr)[cc->chunk_idx]) {
        uint64_t len = cc->chunk_end - cc->chunk_start;

        trace_qemu_rdma_register_and_get_keys(len, cc->chunk_start);

        (*pmr)[cc->chunk_idx] = ibv_reg_mr(lc->pd, cc->chunk_start, len,
                    (rkey ? (IBV_ACCESS_LOCAL_WRITE |
                            IBV_ACCESS_REMOTE_WRITE) : 0));

        if (!(*pmr)[cc->chunk_idx]) {
            perror("Failed to register chunk!");
            /*
            error_report("Chunk details: block: %d chunk index %" PRIuPTR
                            " start %" PRIuPTR
                            " end %" PRIuPTR
                            " host %" PRIuPTR
                            " local %" PRIuPTR
                            " registrations: %d",
                            cc->block->index, cc->chunk_idx, (uintptr_t) cc->chunk_start,
                            (uintptr_t) cc->chunk_end, (uintptr_t) cc->addr,
                            (uintptr_t) cc->block->local_host_addr,
                            rdma->total_registrations);
            */
            return -1;
        }

        rdma->total_registrations++;
    }

    if (lkey) {
        *lkey = (*pmr)[cc->chunk_idx]->lkey;
    }
    if (rkey) {
        *rkey = (*pmr)[cc->chunk_idx]->rkey;
    }
    return 0;
}

/*
 * Register (at connection time) the memory used for control
 * channel messages.
 */
static int qemu_rdma_reg_control(RDMAContext *rdma, int idx)
{
    rdma->wr_data[idx].control_mr = ibv_reg_mr(rdma->lc_remote.pd,
            rdma->wr_data[idx].control, RDMA_CONTROL_MAX_BUFFER,
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (rdma->wr_data[idx].control_mr) {
        rdma->total_registrations++;
        return 0;
    }
    error_report("qemu_rdma_reg_control failed");
    return -1;
}

const char *print_wrid(int wrid)
{
    if (wrid >= RDMA_WRID_RECV_CONTROL) {
        return wrid_desc[RDMA_WRID_RECV_CONTROL];
    }
    return wrid_desc[wrid];
}

/*
 * RDMA requires memory registration (mlock/pinning), but this is not good for
 * overcommitment.
 *
 * In preparation for the future where LRU information or workload-specific
 * writable writable working set memory access behavior is available to QEMU
 * it would be nice to have in place the ability to UN-register/UN-pin
 * particular memory regions from the RDMA hardware when it is determine that
 * those regions of memory will likely not be accessed again in the near future.
 *
 * While we do not yet have such information right now, the following
 * compile-time option allows us to perform a non-optimized version of this
 * behavior.
 *
 * By uncommenting this option, you will cause *all* RDMA transfers to be
 * unregistered immediately after the transfer completes on both sides of the
 * connection. This has no effect in 'rdma-pin-all' mode, only regular mode.
 *
 * This will have a terrible impact on migration performance, so until future
 * workload information or LRU information is available, do not attempt to use
 * this feature except for basic testing.
 */
//#define RDMA_UNREGISTRATION_EXAMPLE

/*
 * Perform a non-optimized memory unregistration after every transfer
 * for demonsration purposes, only if pin-all is not requested.
 *
 * Potential optimizations:
 * 1. Start a new thread to run this function continuously
        - for bit clearing
        - and for receipt of unregister messages
 * 2. Use an LRU.
 * 3. Use workload hints.
 */
static int qemu_rdma_unregister_waiting(RDMAContext *rdma)
{
    while (rdma->unregistrations[rdma->unregister_current]) {
        int ret;
        uint64_t wr_id = rdma->unregistrations[rdma->unregister_current];
        uint64_t chunk =
            (wr_id & RDMA_WRID_CHUNK_MASK) >> RDMA_WRID_CHUNK_SHIFT;
        uint64_t block_index =
            (wr_id & RDMA_WRID_BLOCK_MASK) >> RDMA_WRID_BLOCK_SHIFT;
        RDMALocalBlock *block =
            &(rdma->local_ram_blocks.block[block_index]);
        RDMARegister reg = { .current_block_idx = block_index };
        RDMAControlHeader resp = { .type = RDMA_CONTROL_UNREGISTER_FINISHED,
                                 };
        RDMAControlHeader head = { .len = sizeof(RDMARegister),
                                   .type = RDMA_CONTROL_UNREGISTER_REQUEST,
                                   .repeat = 1,
                                 };

        //trace_qemu_rdma_unregister_waiting_proc(chunk, rdma->unregister_current);

        rdma->unregistrations[rdma->unregister_current] = 0;
        rdma->unregister_current++;

        if (rdma->unregister_current == RDMA_SEND_MAX) {
            rdma->unregister_current = 0;
        }


        /*
         * Unregistration is speculative (because migration is single-threaded
         * and we cannot break the protocol's inifinband message ordering).
         * Thus, if the memory is currently being used for transmission,
         * then abort the attempt to unregister and try again
         * later the next time a completion is received for this memory.
         */
        clear_bit(chunk, block->unregister_bitmap);

        if (test_bit(chunk, block->transit_bitmap)) {
            //trace_qemu_rdma_unregister_waiting_inflight(chunk);
            continue;
        }

        //trace_qemu_rdma_unregister_waiting_send(chunk);

        ret = ibv_dereg_mr(block->pmr[chunk]);
        block->pmr[chunk] = NULL;
        block->remote_keys[chunk] = 0;

        if (ret != 0) {
            perror("unregistration chunk failed");
            return -ret;
        }
        rdma->total_registrations--;

        reg.key.chunk = chunk;
        register_to_network(&reg);
        ret = qemu_rdma_exchange_send(rdma, &head, (uint8_t *) &reg,
                                &resp, NULL, NULL);
        if (ret < 0) {
            return ret;
        }

        //trace_qemu_rdma_unregister_waiting_complete(chunk);
    }

    return 0;
}

static uint64_t qemu_rdma_make_wrid(uint64_t wr_id, uint64_t index,
                                         uint64_t chunk)
{
    uint64_t result = wr_id & RDMA_WRID_TYPE_MASK;

    result |= (index << RDMA_WRID_BLOCK_SHIFT);
    result |= (chunk << RDMA_WRID_CHUNK_SHIFT);

    return result;
}

/*
 * Set bit for unregistration in the next iteration.
 * We cannot transmit right here, but will unpin later.
 */
static void qemu_rdma_signal_unregister(RDMAContext *rdma, uint64_t index,
                                        uint64_t chunk, uint64_t wr_id)
{
    if (rdma->unregistrations[rdma->unregister_next] != 0) {
        ERROR(NULL, "queue is full!");
    } else {
        RDMALocalBlock *block = &(rdma->local_ram_blocks.block[index]);

        if (!test_and_set_bit(chunk, block->unregister_bitmap)) {
            //trace_qemu_rdma_signal_unregister_append(chunk, rdma->unregister_next);

            rdma->unregistrations[rdma->unregister_next++] =
                    qemu_rdma_make_wrid(wr_id, index, chunk);

            if (rdma->unregister_next == RDMA_SEND_MAX) {
                rdma->unregister_next = 0;
            }
        } else {
            //trace_qemu_rdma_signal_unregister_already(chunk);
        }
    }
}

/*
 * Consult the connection manager to see a work request
 * (of any kind) has completed.
 * Return the work request ID that completed.
 */
static uint64_t qemu_rdma_poll(RDMAContext *rdma,
                               RDMALocalContext *lc,
                               uint64_t *wr_id_out,
                               uint32_t *byte_len)
{
    int ret;
    struct ibv_wc wc;
    uint64_t wr_id;

    if (!lc->start_time) {
        lc->start_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    }

    ret = ibv_poll_cq(lc->cq, 1, &wc);

    if (!ret) {
        *wr_id_out = RDMA_WRID_NONE;
        return 0;
    }

    if (ret < 0) {
        error_report("ibv_poll_cq return %d (%s)!", ret, lc->id_str);
        return ret;
    }

    wr_id = wc.wr_id & RDMA_WRID_TYPE_MASK;

    if (wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "ibv_poll_cq wc.status=%d %s! (%s)\n",
                        wc.status, ibv_wc_status_str(wc.status), lc->id_str);
        fprintf(stderr, "ibv_poll_cq wrid=%s! (%s)\n", wrid_desc[wr_id],
                                                        lc->id_str);

        return -1;
    }

    if (rdma->control_ready_expected &&
        (wr_id >= RDMA_WRID_RECV_CONTROL)) {
        /*
        trace_qemu_rdma_poll_recv(wrid_desc[RDMA_WRID_RECV_CONTROL],
                   wr_id - RDMA_WRID_RECV_CONTROL, wr_id, rdma->nb_sent,
                   lc->nb_sent, lc->id_str);
        */
        rdma->control_ready_expected = 0;
    }

    if (wr_id == RDMA_WRID_RDMA_WRITE_REMOTE) {
        uint64_t chunk =
            (wc.wr_id & RDMA_WRID_CHUNK_MASK) >> RDMA_WRID_CHUNK_SHIFT;
        uint64_t block_idx =
            (wc.wr_id & RDMA_WRID_BLOCK_MASK) >> RDMA_WRID_BLOCK_SHIFT;
        RDMALocalBlock *block = &(rdma->local_ram_blocks.block[block_idx]);

        clear_bit(chunk, block->transit_bitmap);

        if (rdma->nb_sent > 0) {
            rdma->nb_sent--;
        }

        /*
        trace_qemu_rdma_poll_write(print_wrid(wr_id), wr_id, rdma->nb_sent,
                 lc->nb_sent, block_idx, chunk,
                 block->local_host_addr, (void *)block->remote_host_addr,
                 lc->id_str);
        */

        if (!rdma->pin_all) {
            /*
             * FYI: If one wanted to signal a specific chunk to be unregistered
             * using LRU or workload-specific information, this is the function
             * you would call to do so. That chunk would then get asynchronously
             * unregistered later.
             */
#ifdef RDMA_UNREGISTRATION_EXAMPLE
             if (block->pmr[chunk]) {
                 qemu_rdma_signal_unregister(rdma, block_idx, chunk, wc.wr_id);
             }
#endif
        }
    } else {
        /*
        trace_qemu_rdma_poll_other(print_wrid(wr_id), wr_id, rdma->nb_sent,
            lc->nb_sent, lc->id_str);
        */
    }

    *wr_id_out = wc.wr_id;
    if (byte_len) {
        *byte_len = wc.byte_len;
    }

    return  0;
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
static int qemu_rdma_block_for_wrid(RDMAContext *rdma,
                                    RDMALocalContext *lc,
                                    int wrid_requested,
                                    uint32_t *byte_len)
{
    int num_cq_events = 0, ret = 0;
    struct ibv_cq *cq;
    void *cq_ctx;
    uint64_t wr_id = RDMA_WRID_NONE, wr_id_in;

    ret = ibv_req_notify_cq(lc->cq, 0);
    if (ret) {
        perror("ibv_req_notify_cq");
        return -ret;
    }

    /* poll cq first */
    while (wr_id != wrid_requested) {
        ret = qemu_rdma_poll(rdma, lc, &wr_id_in, byte_len);
        if (ret < 0) {
            return ret;
        }

        wr_id = wr_id_in & RDMA_WRID_TYPE_MASK;

        if (wr_id == RDMA_WRID_NONE) {
            break;
        }
        if (wr_id != wrid_requested) {
            /*
            trace_qemu_rdma_block_for_wrid_miss(print_wrid(wrid_requested),
                wrid_requested, print_wrid(wr_id), wr_id, lc->id_str);
            */
        }
    }

    if (wr_id == wrid_requested) {
        return 0;
    }

    while (1) {
        /*
         * Coroutine doesn't start until process_incoming_migration()
         * so don't yield unless we know we're running inside of a coroutine.
         */
        if (qemu_in_coroutine()) {
            yield_until_fd_readable(lc->comp_chan->fd);
        }

        ret = ibv_get_cq_event(lc->comp_chan, &cq, &cq_ctx);
        if (ret < 0) {
            perror("ibv_get_cq_event");
            goto err_block_for_wrid;
        }

        num_cq_events++;

        ret = ibv_req_notify_cq(cq, 0);
        if (ret) {
            ret = -ret;
            perror("ibv_req_notify_cq");
            goto err_block_for_wrid;
        }

        while (wr_id != wrid_requested) {
            ret = qemu_rdma_poll(rdma, lc, &wr_id_in, byte_len);
            if (ret < 0) {
                goto err_block_for_wrid;
            }

            wr_id = wr_id_in & RDMA_WRID_TYPE_MASK;

            if (wr_id == RDMA_WRID_NONE) {
                break;
            }
            if (wr_id != wrid_requested) {
                /*
                trace_qemu_rdma_block_for_wrid_miss(print_wrid(wrid_requested),
                                   wrid_requested, print_wrid(wr_id), wr_id, lc->id_str);
                */
            }
        }

        if (wr_id == wrid_requested) {
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
    return ret;
}

/*
 * Post a SEND message work request for the control channel
 * containing some data and block until the post completes.
 */
static int qemu_rdma_post_send_control(RDMAContext *rdma, uint8_t *buf,
                                       RDMAControlHeader *head)
{
    int ret = 0;
    RDMAWorkRequestData *wr = &rdma->wr_data[RDMA_WRID_CONTROL];
    struct ibv_send_wr *bad_wr;
    struct ibv_sge sge = {
                           .addr = (uintptr_t)(wr->control),
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

    trace_qemu_rdma_post_send_control(control_desc[head->type]);

    /*
     * We don't actually need to do a memcpy() in here if we used
     * the "sge" properly, but since we're only sending control messages
     * (not RAM in a performance-critical path), then its OK for now.
     *
     * The copy makes the RDMAControlHeader simpler to manipulate
     * for the time being.
     */
    assert(head->len <= RDMA_CONTROL_MAX_BUFFER - sizeof(*head));
    memcpy(wr->control, head, sizeof(RDMAControlHeader));
    control_to_network((void *) wr->control);

    if (buf) {
        memcpy(wr->control + sizeof(RDMAControlHeader), buf, head->len);
    }

    ret = ibv_post_send(rdma->lc_remote.qp, &send_wr, &bad_wr);

    if (ret > 0) {
        ERROR(NULL, "Failed to use post IB SEND for control!");
        return -ret;
    }

    ret = qemu_rdma_block_for_wrid(rdma, &rdma->lc_remote,
                                   RDMA_WRID_SEND_CONTROL, NULL);
    if (ret < 0) {
        ERROR(NULL, "send polling control!");
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
                            .addr = (uintptr_t)(rdma->wr_data[idx].control),
                            .length = RDMA_CONTROL_MAX_BUFFER,
                            .lkey = rdma->wr_data[idx].control_mr->lkey,
                         };

    struct ibv_recv_wr recv_wr = {
                                    .wr_id = RDMA_WRID_RECV_CONTROL + idx,
                                    .sg_list = &sge,
                                    .num_sge = 1,
                                 };


    if (ibv_post_recv(rdma->lc_remote.qp, &recv_wr, &bad_wr)) {
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
    uint32_t byte_len;
    int ret = qemu_rdma_block_for_wrid(rdma, &rdma->lc_remote,
                                       RDMA_WRID_RECV_CONTROL + idx,
                                       &byte_len);

    if (ret < 0) {
        ERROR(NULL, "recv polling control!");
        return ret;
    }

    network_to_control((void *) rdma->wr_data[idx].control);
    memcpy(head, rdma->wr_data[idx].control, sizeof(RDMAControlHeader));

    trace_qemu_rdma_exchange_get_response_start(control_desc[expecting]);

    if (expecting == RDMA_CONTROL_NONE) {
        trace_qemu_rdma_exchange_get_response_none(control_desc[head->type],
                                             head->type);
    } else if (head->type != expecting || head->type == RDMA_CONTROL_ERROR) {
        error_report("Was expecting a %s (%d) control message"
                ", but got: %s (%d), length: %d",
                control_desc[expecting], expecting,
                control_desc[head->type], head->type, head->len);
        return -EIO;
    }
    if (head->len > RDMA_CONTROL_MAX_BUFFER - sizeof(*head)) {
        error_report("too long length: %d", head->len);
        return -EINVAL;
    }
    if (sizeof(*head) + head->len != byte_len) {
        error_report("Malformed length: %d byte_len %d",
                head->len, byte_len);
        return -EINVAL;
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
                                   int *resp_idx,
                                   int (*callback)(RDMAContext *rdma))
{
    int ret = 0;

    /*
     * Wait until the dest is ready before attempting to deliver the message
     * by waiting for a READY message.
     */
    if (rdma->control_ready_expected) {
        RDMAControlHeader resp;
        ret = qemu_rdma_exchange_get_response(rdma,
                                    &resp, RDMA_CONTROL_READY, RDMA_WRID_READY);
        if (ret < 0) {
            return ret;
        }
    }

    /*
     * If the user is expecting a response, post a WR in anticipation of it.
     */
    if (resp) {
        ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_DATA);
        if (ret) {
            ERROR(NULL, "posting extra control recv for anticipated result!");
            return ret;
        }
    }

    /*
     * Post a WR to replace the one we just consumed for the READY message.
     */
    ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_READY);
    if (ret) {
        ERROR(NULL, "posting first control recv!");
        return ret;
    }

    /*
     * Deliver the control message that was requested.
     */
    ret = qemu_rdma_post_send_control(rdma, data, head);

    if (ret < 0) {
        ERROR(NULL, "sending control buffer!");
        return ret;
    }

    /*
     * If we're expecting a response, block and wait for it.
     */
    if (resp) {
        if (callback) {
            trace_qemu_rdma_exchange_send_issue_callback();
            ret = callback(rdma);
            if (ret < 0) {
                return ret;
            }
        }

        trace_qemu_rdma_exchange_send_waiting(control_desc[resp->type]);
        ret = qemu_rdma_exchange_get_response(rdma, resp,
                                              resp->type, RDMA_WRID_DATA);

        if (ret < 0) {
            return ret;
        }

        qemu_rdma_move_header(rdma, RDMA_WRID_DATA, resp);
        if (resp_idx) {
            *resp_idx = RDMA_WRID_DATA;
        }
        trace_qemu_rdma_exchange_send_received(control_desc[resp->type]);
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
        error_report("Failed to send control buffer!");
        return ret;
    }

    /*
     * Block and wait for the message.
     */
    ret = qemu_rdma_exchange_get_response(rdma, head,
                                          expecting, RDMA_WRID_READY);

    if (ret < 0) {
        return ret;
    }

    qemu_rdma_move_header(rdma, RDMA_WRID_READY, head);

    /*
     * Post a new RECV work request to replace the one we just consumed.
     */
    ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_READY);
    if (ret) {
        ERROR(NULL, "posting second control recv!");
        return ret;
    }

    return 0;
}

static inline void install_boundaries(RDMAContext *rdma, RDMACurrentChunk *cc)
{
    uint64_t len = cc->block->is_ram_block ?
                   cc->current_length : cc->block->length;

    cc->chunks = len / (1UL << RDMA_REG_CHUNK_SHIFT);

    if (cc->chunks && ((len % (1UL << RDMA_REG_CHUNK_SHIFT)) == 0)) {
        cc->chunks--;
    }

    cc->addr = cc->block->local_host_addr + (cc->current_addr - cc->block->offset);

    cc->chunk_idx = ram_chunk_index(cc->block->local_host_addr, cc->addr);
    cc->chunk_start = ram_chunk_start(cc->block, cc->chunk_idx);
    cc->chunk_end = ram_chunk_end(cc->block, cc->chunk_idx + cc->chunks);

    trace_qemu_rdma_install_boundaries(cc->block->index, cc->chunk_idx, cc->chunks + 1, (cc->chunks + 1) *
                    (1UL << RDMA_REG_CHUNK_SHIFT) / 1024 / 1024);

}

/*
 * Push out any unwritten RDMA operations.
 */
static int qemu_rdma_write(QEMUFile *f, RDMAContext *rdma,
                                 RDMACurrentChunk *src,
                                 RDMACurrentChunk *dest)
{
    struct ibv_sge sge;
    struct ibv_send_wr send_wr = { 0 };
    struct ibv_send_wr *bad_wr;
    int reg_result_idx, ret, count = 0;
    bool copy;
    RDMALocalContext *lc;
    RDMARegister reg;
    RDMARegisterResult *reg_result;
    RDMAControlHeader resp = { .type = RDMA_CONTROL_REGISTER_RESULT };
    RDMAControlHeader head = { .len = sizeof(RDMARegister),
                               .type = RDMA_CONTROL_REGISTER_REQUEST,
                               .repeat = 1,
                             };

    if (!src->current_length) {
        return 0;
    }

    if (dest == src) {
        dest = NULL;
    }

    copy = dest ? true : false;

    lc = (migrate_use_mc_rdma_copy() && copy) ?
        (rdma->source ? &rdma->lc_src : &rdma->lc_dest) : &rdma->lc_remote;

retry:
    src->block = &(rdma->local_ram_blocks.block[src->current_block_idx]);
    install_boundaries(rdma, src);

    if (dest) {
        dest->block = &(rdma->local_ram_blocks.block[dest->current_block_idx]);
        install_boundaries(rdma, dest);
    }

    if (!rdma->pin_all) {
#ifdef RDMA_UNREGISTRATION_EXAMPLE
        qemu_rdma_unregister_waiting(rdma);
#endif
    }

    while (test_bit(src->chunk_idx, src->block->transit_bitmap)) {
        (void)count;

        /*
        trace_qemu_rdma_write_one_block(count++, src->current_block_index, src->chunk_idx,
                 (uint64_t) sge.addr, src->current_length, rdma->nb_sent,
                 lc->nb_sent, src->block->nb_chunks, lc->id_str);
        */

        ret = qemu_rdma_block_for_wrid(rdma, lc,
                                       RDMA_WRID_RDMA_WRITE_REMOTE, NULL);

        if (ret < 0) {
            /*
            error_report("Failed to Wait for previous write to complete "
                    "block %d chunk %" PRIu64
                    " current_addr %" PRIu64 " len %" PRIu64
                    " left %d (per qp left %d) (%s)",
                    src->current_block_idx, src->chunk_idx, (uint64_t) src->addr,
                    src->current_length, rdma->nb_sent, lc->nb_sent, lc->id_str);
            */
            return ret;
        }
    }

    if (!rdma->pin_all || !src->block->is_ram_block) {
        if (!src->block->remote_keys[src->chunk_idx]) {
            /*
             * This chunk has not yet been registered, so first check to see
             * if the entire chunk is zero. If so, tell the other size to
             * memset() + madvise() the entire chunk without RDMA.
             */

            if (src->block->is_ram_block &&
                   can_use_buffer_find_nonzero_offset((void *)(uintptr_t)src->addr,
                   src->current_length)
                   && buffer_find_nonzero_offset((void *)(uintptr_t)src->addr,
                   src->current_length) == src->current_length) {

                RDMACompress comp = {
                                        .offset = src->current_addr,
                                        .value = 0,
                                        .block_idx = src->current_block_idx,
                                        .length = src->current_length,
                                    };

                head.len = sizeof(comp);
                head.type = RDMA_CONTROL_COMPRESS;

                /*
                trace_qemu_rdma_write_one_zero(src->chunk_idx,
                    src->current_length, src->current_block_idx, src->current_addr,
                    lc->id_str);
                */

                compress_to_network(&comp);
                ret = qemu_rdma_exchange_send(rdma, &head,
                                (uint8_t *) &comp, NULL, NULL, NULL);

                if (ret < 0) {
                    return -EIO;
                }

                acct_update_position(f, src->current_length, true);

                return 1;
            }

            /*
             * Otherwise, tell other side to register. (Only for remote RDMA)
             */
            if (!dest) {
                reg.current_block_idx = src->current_block_idx;
                if (src->block->is_ram_block) {
                    reg.key.current_addr = src->current_addr;
                } else {
                    reg.key.chunk = src->chunk_idx;
                }
                reg.chunks = src->chunks;

                /*
                trace_qemu_rdma_write_one_sendreg(src->chunk_idx,
                    src->current_length, src->current_block_idx, src->current_addr,
                    lc->id_str);
                */

                register_to_network(&reg);
                ret = qemu_rdma_exchange_send(rdma, &head, (uint8_t *) &reg,
                                        &resp, &reg_result_idx, NULL);
                if (ret < 0) {
                    return ret;
                }
            }

            /* try to overlap this single registration with the one we sent. */
            if (qemu_rdma_register_and_get_keys(rdma, src, lc, copy,
                                                &sge.lkey, NULL)) {
                error_report("cannot get lkey!");
                return -EINVAL;
            }

            if (!dest) {
                reg_result = (RDMARegisterResult *)
                        rdma->wr_data[reg_result_idx].control_curr;

                network_to_result(reg_result);

                /*
                trace_qemu_rdma_write_one_recvregres(src->block->remote_keys[src->chunk_idx],
                    reg_result->rkey, src->chunk_idx, lc->id_str);
                */

                src->block->remote_keys[src->chunk_idx] = reg_result->rkey;
                src->block->remote_host_addr = reg_result->host_addr;
            }
        } else {
            /* already registered before */
            if (qemu_rdma_register_and_get_keys(rdma, src, lc, copy,
                                                &sge.lkey, NULL)) {
                error_report("cannot get lkey!");
                return -EINVAL;
            }
        }

        send_wr.wr.rdma.rkey = src->block->remote_keys[src->chunk_idx];
    } else {
        send_wr.wr.rdma.rkey = src->block->remote_rkey;

        if (qemu_rdma_register_and_get_keys(rdma, src, lc, copy,
                                            &sge.lkey, NULL)) {
            error_report("cannot get lkey!");
            return -EINVAL;
        }
    }

    if (migrate_use_mc_rdma_copy() && dest) {
        if (qemu_rdma_register_and_get_keys(rdma, dest,
                                            &rdma->lc_dest, copy,
                                            NULL, &send_wr.wr.rdma.rkey)) {
            fprintf(stderr, "cannot get rkey!\n");
            return -EINVAL;
        }
    }

    /*
     * Encode the ram block index and chunk within this wrid.
     * We will use this information at the time of completion
     * to figure out which bitmap to check against and then which
     * chunk in the bitmap to look for.
     */
    send_wr.wr_id = qemu_rdma_make_wrid(RDMA_WRID_RDMA_WRITE_REMOTE,
                                        src->current_block_idx, src->chunk_idx);

    sge.length = src->current_length;
    sge.addr = (uintptr_t) src->addr;
    send_wr.opcode = IBV_WR_RDMA_WRITE;
    send_wr.send_flags = IBV_SEND_SIGNALED;
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    send_wr.wr.rdma.remote_addr = (dest ? (uint32_t) (uintptr_t) dest->addr :
                (src->block->remote_host_addr +
                    (src->current_addr - src->block->offset)));

    /*
    trace_qemu_rdma_write_one_post(src->chunk_idx, sge.addr,
            send_wr.wr.rdma.remote_addr,
            sge.length, sge.lkey, send_wr.wr.rdma.rkey,
            lc->id_str);
    */

    /*
     * ibv_post_send() does not return negative error numbers,
     * per the specification they are positive - no idea why.
     */
    ret = ibv_post_send(lc->qp, &send_wr, &bad_wr);

    if (ret == ENOMEM) {
        //trace_qemu_rdma_write_one_queue_full();
        ret = qemu_rdma_block_for_wrid(rdma, lc,
                                       RDMA_WRID_RDMA_WRITE_REMOTE, NULL);
        if (ret < 0) {
            ERROR(NULL, "could not make room in full send queue! %d", ret);
            return ret;
        }

        goto retry;

    } else if (ret > 0) {
        perror("rdma migration: post rdma write failed");
        return -ret;
    }

    set_bit(src->chunk_idx, src->block->transit_bitmap);

    if (!dest) {
        acct_update_position(f, sge.length, false);
    }

    rdma->total_writes++;
    rdma->nb_sent++;
    lc->nb_sent++;

    //trace_qemu_rdma_write_flush(rdma->nb_sent, lc->nb_sent, lc->id_str);

    src->current_length = 0;
    src->current_addr = 0;

    if (dest) {
        dest->current_length = 0;
        dest->current_addr = 0;
    }

    return 0;
}

static inline int qemu_rdma_buffer_mergable(RDMAContext *rdma,
                                            RDMACurrentChunk *cc,
                                            uint64_t current_addr,
                                            uint64_t len)
{
    RDMALocalBlock *block;
    uint8_t *host_addr;
    uint8_t *chunk_end;

    if (cc->current_block_idx < 0) {
        return 0;
    }

    if (cc->current_chunk < 0) {
        return 0;
    }

    block = &(rdma->local_ram_blocks.block[cc->current_block_idx]);
    host_addr = block->local_host_addr + (current_addr - block->offset);
    chunk_end = ram_chunk_end(block, cc->current_chunk);

    if (cc->current_length == 0) {
        return 0;
    }

    /*
     * Only merge into chunk sequentially.
     */
    if (current_addr != (cc->current_addr + cc->current_length)) {
        return 0;
    }

    if (current_addr < block->offset) {
        return 0;
    }

    if ((current_addr + len) > (block->offset + block->length)) {
        return 0;
    }

    if ((host_addr + len) > chunk_end) {
        return 0;
    }

    return 1;
}

static int write_start(RDMAContext *rdma,
                        RDMACurrentChunk *cc,
                        uint64_t len,
                        uint64_t current_addr)
{
    int ret;
    uint64_t block_idx, chunk;

    cc->current_addr = current_addr;
    block_idx = cc->current_block_idx;
    chunk = cc->current_chunk;

    ret = qemu_rdma_search_ram_block(rdma, cc->block_offset,
                                     cc->offset, len, &block_idx, &chunk);
    if (ret) {
        ERROR(NULL, "ram block search failed");
        return ret;
    }

    cc->current_block_idx = block_idx;
    cc->current_chunk = chunk;

    return 0;
}

/*
 * If we cannot merge it, we flush the current buffer first.
 */
static int qemu_rdma_flush_unmergable(RDMAContext *rdma,
                                      RDMACurrentChunk *src,
                                      RDMACurrentChunk *dest,
                                      QEMUFile *f, uint64_t len)
{
    uint64_t current_addr_src = 0;
    uint64_t current_addr_dest = 0;
    int ret;

    current_addr_src = src->block_offset + src->offset;

    if (dest) {
        current_addr_dest = dest->block_offset + dest->offset;
    }

    if (qemu_rdma_buffer_mergable(rdma, src, current_addr_src, len)) {
        if (dest) {
            if (qemu_rdma_buffer_mergable(rdma, dest, current_addr_dest, len)) {
                goto merge;
            }
        } else {
            goto merge;
        }
    }

    ret = qemu_rdma_write(f, rdma, src, dest);

    if (ret) {
        return ret;
    }

    ret = write_start(rdma, src, len, current_addr_src);

    if (ret) {
        return ret;
    }

    if (dest) {
        ret = write_start(rdma, dest, len, current_addr_dest);

        if (ret) {
            return ret;
        }
    }

merge:
    src->current_length += len;
    if (dest) {
        dest->current_length += len;
    }

    return 0;
}

static void disconnect_ibv(RDMAContext *rdma, RDMALocalContext *lc, bool force)
{
    struct rdma_cm_event *cm_event;
    int ret;

    if (!lc->cm_id || !lc->connected) {
        return;
    }

    if ((lc == (&rdma->lc_remote)) && rdma->error_state) {
        if (rdma->error_state != -ENETUNREACH) {
            RDMAControlHeader head = { .len = 0,
                                       .type = RDMA_CONTROL_ERROR,
                                       .repeat = 1,
                                     };
            error_report("Early error. Sending error.");
            qemu_rdma_post_send_control(rdma, NULL, &head);
        } else {
            error_report("Early error.");
            rdma_disconnect(lc->cm_id);
            goto finish;
        }
    }

    ret = rdma_disconnect(lc->cm_id);
    if (!ret && !force) {
        trace_qemu_rdma_cleanup_waiting_for_disconnect();
        ret = rdma_get_cm_event(lc->channel, &cm_event);
        if (!ret) {
            rdma_ack_cm_event(cm_event);
        }
    }

finish:

    trace_qemu_rdma_cleanup_disconnect();
    lc->verbs = NULL;
    lc->connected = false;
}

static void qemu_rdma_cleanup(RDMAContext *rdma, bool force)
{
    int idx;

    if (connection_timer) {
        timer_del(connection_timer);
        timer_free(connection_timer);
        connection_timer = NULL;
    }

    if (keepalive_timer) {
        timer_del(keepalive_timer);
        timer_free(keepalive_timer);
        keepalive_timer = NULL;
    }

    disconnect_ibv(rdma, &rdma->lc_remote, force);
    if (migrate_use_mc_rdma_copy()) {
        disconnect_ibv(rdma, &rdma->lc_src, force);
        disconnect_ibv(rdma, &rdma->lc_dest, force);
    }

    g_free(rdma->dest_blocks);
    rdma->dest_blocks = NULL;

    for (idx = 0; idx < RDMA_WRID_MAX; idx++) {
        if (rdma->wr_data[idx].control_mr) {
            rdma->total_registrations--;
            ibv_dereg_mr(rdma->wr_data[idx].control_mr);
        }
        rdma->wr_data[idx].control_mr = NULL;
    }

    if (rdma->local_ram_blocks.block) {
        while (rdma->local_ram_blocks.nb_blocks) {
            delete_block(rdma, rdma->local_ram_blocks.block->offset);
        }
    }

    close_ibv(rdma, &rdma->lc_remote);
    if (migrate_use_mc_rdma_copy()) {
        close_ibv(rdma, &rdma->lc_src);
        close_ibv(rdma, &rdma->lc_dest);
    }

    if (rdma->keepalive_mr) {
        ibv_dereg_mr(rdma->keepalive_mr);
        rdma->keepalive_mr = NULL;
    }
    if (rdma->next_keepalive_mr) {
        ibv_dereg_mr(rdma->next_keepalive_mr);
        rdma->next_keepalive_mr = NULL;
    }
}

static int resources_create(RDMAContext *rdma, RDMALocalContext *lc)
{
    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr attr = { 0 };
    struct ibv_device *ib_dev = NULL;

    int num_devices;
    int rc = 0;
    int i;

    fprintf(stdout, "searching for IB devices in host\n");

    /* get device names in the system */
    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list)
    {
        fprintf(stderr, "failed to get IB devices list\n");
        rc = 1;
        goto resources_create_exit;
    }

    /* if there isn't any IB device in host */
    if (!num_devices)
    {
        fprintf(stderr, "found %d device(s)\n", num_devices);
        rc = 1;
        goto resources_create_exit;
    }

    fprintf(stdout, "found %d device(s)\n", num_devices);

    /* search for the specific device we want to work with */
    for (i = 0; i < num_devices; i++)
    {
        if (!lc->dev_name)
        {
            lc->dev_name = strdup(ibv_get_device_name(dev_list[i]));
            fprintf(stdout, "device not specified, using first one found: %s\n", lc->dev_name);
        }

        if (!strcmp(ibv_get_device_name(dev_list[i]), lc->dev_name))
        {
            ib_dev = dev_list[i];
            break;
        }
    }

    /* if the device wasn't found in host */
    if (!ib_dev)
    {
        fprintf(stderr, "IB device %s wasn't found\n", lc->dev_name);
        rc = 1;
        goto resources_create_exit;
    }


    /* get device handle */
    lc->verbs = ibv_open_device(ib_dev);
    if (!lc->verbs)
    {
        fprintf(stderr, "failed to open device %s\n", lc->dev_name);
        rc = 1;
        goto resources_create_exit;
    }

    /* We are now done with device list, free it */

    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ib_dev = NULL;

    /* query port properties */
    if (ibv_query_port(lc->verbs, lc->ib_port, &lc->port_attr))
    {
        fprintf(stderr, "ibv_query_port on port %u failed\n", lc->ib_port);
        rc = 1;
        goto resources_create_exit;
    }

    /* allocate Protection Domain */
    lc->pd = ibv_alloc_pd(lc->verbs);
    if (!lc->pd)
    {
        fprintf(stderr, "ibv_alloc_pd failed\n");
        rc = 1;
        goto resources_create_exit;
    }

    /* create completion channel */
    lc->comp_chan = ibv_create_comp_channel(lc->verbs);
    if (!lc->comp_chan) {
        ERROR(NULL, "allocate completion channel");
        rc = 1;
        goto resources_create_exit;
    }

    /*
     * Completion queue can be filled by both read and write work requests,
     * so must reflect the sum of both possible queue sizes.
     */
    lc->cq = ibv_create_cq(lc->verbs, (RDMA_SEND_MAX * 3), NULL,
                           lc->comp_chan, 0);
    if (!lc->cq) {
        ERROR(NULL, "allocate completion queue");
        rc = 1;
        goto resources_create_exit;
    }

    attr.cap.max_send_wr = RDMA_SEND_MAX;
    attr.cap.max_recv_wr = 3;
    attr.cap.max_send_sge = 1;
    attr.cap.max_recv_sge = 1;
    attr.send_cq = lc->cq;
    attr.recv_cq = lc->cq;
    attr.qp_type = IBV_QPT_RC;

    lc->qp = ibv_create_qp(lc->pd, &attr);
    if (!lc->qp)
    {
        ERROR(NULL, "alloc queue pair");
        rc = 1;
        goto resources_create_exit;
    }

    fprintf(stdout, "QP was created, QP number=0x%x\n", lc->qp->qp_num);

resources_create_exit:
    if (rc)
    {
        /* Error encountered, cleanup */
        if (lc->qp)
        {
            ibv_destroy_qp(lc->qp);
        }

        if (lc->cq)
        {
            ibv_destroy_cq(lc->cq);
            lc->cq = NULL;
        }

        if (lc->pd)
        {
            ibv_dealloc_pd(lc->pd);
            lc->pd = NULL;
        }

        if (lc->verbs)
        {
            ibv_close_device(lc->verbs);
            lc->verbs = NULL;
        }

        if (dev_list)
        {
            ibv_free_device_list(dev_list);
            dev_list = NULL;
        }
    }

    return rc;
}

static int sock_connect(RDMAContext *rdma, const char *servername, int port);

static int qemu_rdma_device_init(RDMAContext *rdma, Error **errp,
                                 RDMALocalContext *lc)
{
    if (lc->source)
    {
        lc->sock = sock_connect(rdma, lc->host, lc->port);
        if (lc->sock < 0)
        {
            fprintf(stderr, "failed to establish TCP connection to server %s, port %d\n", lc->host, lc->port);
        }
        fprintf(stdout, "TCP connection was established\n");
    }
    else
    {
        fprintf(stdout, "waiting on port %d for TCP connection\n", lc->port);
        lc->sock = sock_connect(rdma, NULL, lc->port);
        if (lc->sock < 0)
        {
            fprintf(stderr, "failed to establish TCP connection with client on port %d\n", lc->port);
        }
    }

    if (lc->source) {
        resources_create(rdma, lc);
    }

    // struct rdma_cm_event *cm_event;
    // int ret;
    // char ip[40] = "unknown";
    // struct rdma_addrinfo *res, *e;
    // char port_str[16];

    // if (!lc->host || !lc->host[0]) {
    //     ERROR(errp, "RDMA host is not set!");
    //     SET_ERROR(rdma, -EINVAL);
    //     return -1;
    // }

    // /* create CM channel */
    // lc->channel = rdma_create_event_channel();
    // if (!lc->channel) {
    //     ERROR(errp, "could not create rdma event channel (%s)", lc->id_str);
    //     SET_ERROR(rdma, -EINVAL);
    //     return -1;
    // }

    // /* create CM id */
    // if (lc->listen_id) {
    //     lc->cm_id = lc->listen_id;
    // } else {
    //     ret = rdma_create_id(lc->channel, &lc->cm_id, NULL, RDMA_PS_TCP);
    //     if (ret) {
    //         ERROR(errp, "could not create cm_id! (%s)", lc->id_str);
    //         goto err_device_init_create_id;
    //     }
    // }

    // snprintf(port_str, 16, "%d", lc->port);
    // port_str[15] = '\0';

    // ret = rdma_getaddrinfo(lc->host, port_str, NULL, &res);
    // if (ret < 0) {
    //     ERROR(errp, "could not rdma_getaddrinfo address %s (%s)",
    //                 lc->host, lc->id_str);
    //     goto err_device_init_bind_addr;
    // }

    // for (e = res; e != NULL; e = e->ai_next) {
    //     inet_ntop(e->ai_family,
    //         &((struct sockaddr_in *) e->ai_dst_addr)->sin_addr, ip, sizeof ip);
    //     //trace_qemu_rdma_resolve_host_trying(lc->host, ip, port_str, lc->id_str);

    //     if (lc->dest) {
    //         ret = rdma_bind_addr(lc->cm_id, e->ai_dst_addr);
    //     } else {
    //         ret = rdma_resolve_addr(lc->cm_id, NULL, e->ai_dst_addr,
    //             RDMA_RESOLVE_TIMEOUT_MS);
    //     }

    //     if (ret) {
    //         continue;
    //     }

    //     if (e->ai_family == AF_INET6) {
    //         ret = qemu_rdma_broken_ipv6_kernel(errp, lc->cm_id->verbs);
    //         if (ret) {
    //             continue;
    //         }
    //     }

    //     break;
    // }

    // if (!e) {
    //     ERROR(errp, "initialize/bind/resolve device! (%s)", lc->id_str);
    //     goto err_device_init_bind_addr;
    // }

    // qemu_rdma_dump_gid("device_init", lc->cm_id);

    // if(lc->source) {
    //     ret = rdma_get_cm_event(lc->channel, &cm_event);
    //     if (ret) {
    //         ERROR(errp, "could not perform event_addr_resolved (%s)", lc->id_str);
    //         goto err_device_init_bind_addr;
    //     }

    //     if (cm_event->event != RDMA_CM_EVENT_ADDR_RESOLVED) {
    //         ERROR(errp, "result not equal to event_addr_resolved %s (%s)",
    //                 rdma_event_str(cm_event->event), lc->id_str);
    //         perror("rdma_resolve_addr");
    //         rdma_ack_cm_event(cm_event);
    //         ret = -EINVAL;
    //         goto err_device_init_bind_addr;
    //     }

    //     rdma_ack_cm_event(cm_event);

    //     /* resolve route */
    //     ret = rdma_resolve_route(lc->cm_id, RDMA_RESOLVE_TIMEOUT_MS);
    //     if (ret) {
    //         ERROR(errp, "could not resolve rdma route");
    //         goto err_device_init_bind_addr;
    //     }

    //     ret = rdma_get_cm_event(lc->channel, &cm_event);
    //     if (ret) {
    //         ERROR(errp, "could not perform event_route_resolved");
    //         goto err_device_init_bind_addr;
    //     }

    //     if (cm_event->event != RDMA_CM_EVENT_ROUTE_RESOLVED) {
    //         ERROR(errp, "result not equal to event_route_resolved: %s",
    //                         rdma_event_str(cm_event->event));
    //         rdma_ack_cm_event(cm_event);
    //         ret = -EINVAL;
    //         goto err_device_init_bind_addr;
    //     }

    //     lc->verbs = lc->cm_id->verbs;
    //     printf("verbs: %p (%s)\n", lc->verbs, lc->id_str);

    //     rdma_ack_cm_event(cm_event);

    //     ret = qemu_rdma_alloc_pd_cq_qp(rdma, lc);
    //     if (ret) {
    //         goto err_device_init_bind_addr;
    //     }

    //     qemu_rdma_dump_id("rdma_accept_start", lc->verbs);
    // } else {
    //     lc->listen_id = lc->cm_id;
    //     lc->cm_id = NULL;

    //     ret = rdma_listen(lc->listen_id, 1);

    //     if (ret) {
    //         perror("rdma_listen");
    //         ERROR(errp, "listening on socket! (%s)", lc->id_str);
    //         goto err_device_init_bind_addr;
    //     }

    //     trace_qemu_rdma_device_init_listen_success();
    // }

    // trace_qemu_rdma_device_init_success();
    return 0;

// err_device_init_bind_addr:
//     if (lc->cm_id) {
//         rdma_destroy_id(lc->cm_id);
//         lc->cm_id = NULL;
//     }
//     if (lc->listen_id) {
//         rdma_destroy_id(lc->listen_id);
//         lc->listen_id = NULL;
//     }
// err_device_init_create_id:
//     if (lc->channel) {
//         rdma_destroy_event_channel(lc->channel);
//         lc->channel = NULL;
//     }
//     SET_ERROR(rdma, ret);
}

static int qemu_rdma_init_outgoing(RDMAContext *rdma,
                                 Error **errp,
                                 MigrationState *s)
{
    int ret, idx;
    Error *local_err = NULL, **temp = &local_err;

    /*
     * Will be validated against destination's actual capabilities
     * after the connect() completes.
     */
    rdma->pin_all = s->enabled_capabilities[MIGRATION_CAPABILITY_RDMA_PIN_ALL];
    rdma->do_keepalive = s->enabled_capabilities[MIGRATION_CAPABILITY_RDMA_KEEPALIVE];

    for (idx = 0; idx < RDMA_WRID_MAX; idx++) {
        rdma->wr_data[idx].control_len = 0;
        rdma->wr_data[idx].control_curr = NULL;
    }

    rdma->source = true;
    rdma->dest = false;
    rdma->lc_remote.source = true;
    rdma->lc_remote.dest = false;

    ret = qemu_rdma_device_init(rdma, temp, &rdma->lc_remote);
    if (ret) {
        goto err_rdma_init_outgoing;
    }

    ret = qemu_rdma_reg_keepalive(rdma);

    if (ret) {
        ERROR(temp, "allocating keepalive structures");
        goto err_rdma_init_outgoing;
    }

    ret = qemu_rdma_init_ram_blocks(rdma);
    if (ret) {
        ERROR(temp, "initializing ram blocks!");
        goto err_rdma_init_outgoing;
    }

    for (idx = 0; idx < RDMA_WRID_MAX; idx++) {
        ret = qemu_rdma_reg_control(rdma, idx);
        if (ret) {
            ERROR(temp, "registering %d control!", idx);
            goto err_rdma_init_outgoing;
        }
    }

    return 0;

err_rdma_init_outgoing:
    error_propagate(errp, local_err);
    qemu_rdma_cleanup(rdma, false);
    return -1;
}

static int qemu_rdma_connect_finish(RDMAContext *rdma,
                                    RDMALocalContext *lc,
                                    Error **errp,
                                    struct rdma_cm_event **return_event)
{
    // int ret = 0;
    // struct rdma_cm_event *cm_event;

    // ret = rdma_get_cm_event(lc->channel, &cm_event);
    // if (ret) {
    //     perror("rdma_get_cm_event after rdma_connect");
    //     rdma_ack_cm_event(cm_event);
    //     goto err;
    // }

    // if (cm_event->event != RDMA_CM_EVENT_ESTABLISHED) {
    //     perror("rdma_get_cm_event != EVENT_ESTABLISHED after rdma_connect");
    //     rdma_ack_cm_event(cm_event);
    //     ret = -1;
    //     goto err;
    // }

    /*
     * The rdmacm "private data area" may contain information from the receiver,
     * just as we may have done the same from the sender side. If so, we cannot
     * ack this CM event until we have processed/copied this small data
     * out of the cm_event structure, otherwise, the ACK will free the structure
     * and we will lose the data.
     *
     * Thus, we allow the caller to ACK this event if there is important
     * information inside. Otherwise, we will ACK by ourselves.
     */
    // if (return_event) {
    //     *return_event = cm_event;
    // } else {
    //     rdma_ack_cm_event(cm_event);
    // }

    lc->connected = true;

    return 0;
// err:
//     ERROR(errp, "connecting to destination!");
//     rdma_destroy_id(lc->cm_id);
//     lc->cm_id = NULL;
//     return ret;
}

static int modify_qp_to_init(struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;

    memset(&attr, 0, sizeof(attr));

    attr.qp_state = IBV_QPS_INIT;
    attr.port_num = 1; // ib_port
    attr.pkey_index = 0;
    attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

    flags = IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS;

    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
        fprintf(stderr, "failed to modify QP state to INIT\n");

    return rc;
}

static int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint16_t dlid, uint8_t *dgid)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;

    memset(&attr, 0, sizeof(attr));

    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_256;
    attr.dest_qp_num = remote_qpn;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 0x12;
    attr.ah_attr.is_global = 0;
    attr.ah_attr.dlid = dlid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = 1; // ib_port

    attr.ah_attr.is_global = 1;
    attr.ah_attr.port_num = 1;
    memcpy(&attr.ah_attr.grh.dgid, dgid, 16);
    attr.ah_attr.grh.flow_label = 0;
    attr.ah_attr.grh.hop_limit = 1;
    attr.ah_attr.grh.sgid_index = 0; // gid_idx
    attr.ah_attr.grh.traffic_class = 0;

    flags = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
        fprintf(stderr, "failed to modify QP state to RTR\n");

    return rc;
}

static int modify_qp_to_rts(struct ibv_qp *qp)
{
    struct ibv_qp_attr attr;
    int flags;
    int rc;

    memset(&attr, 0, sizeof(attr));

    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 0x12;
    attr.retry_cnt = 6;
    attr.rnr_retry = 0;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;

    flags = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    rc = ibv_modify_qp(qp, &attr, flags);
    if (rc)
        fprintf(stderr, "failed to modify QP state to RTS\n");

    return rc;
}

static int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;

    rc = write(sock, local_data, xfer_size);
    if (rc < xfer_size)
        fprintf(stderr, "Failed writing data during sock_sync_data\n");
    else
        rc = 0;

    while(!rc && total_read_bytes < xfer_size)
    {
        read_bytes = read(sock, remote_data, xfer_size);
        if(read_bytes > 0)
            total_read_bytes += read_bytes;
        else
            rc = read_bytes;
    }

    return rc;
}

static int connect_qp(RDMALocalContext *lc)
{
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    int rc = 0;
    union ibv_gid my_gid;

    if (lc->gid_idx >= 0)
    {
        rc = ibv_query_gid(lc->verbs, lc->ib_port, lc->gid_idx, &my_gid);
        if (rc)
        {
            fprintf(stderr, "could not get gid for port %d, index %d\n", lc->ib_port, lc->gid_idx);
            return rc;
        }
    }
    else
        memset(&my_gid, 0, sizeof my_gid);

    /* exchange using TCP sockets info required to connect QPs */
    local_con_data.qp_num = htonl(lc->qp->qp_num);
    local_con_data.lid = htons(lc->port_attr.lid);
    memcpy(local_con_data.gid, &my_gid, 16);

    fprintf(stdout, "\nLocal LID = 0x%x\n", lc->port_attr.lid);
    if (sock_sync_data(lc->sock, sizeof(struct cm_con_data_t), (char *) &local_con_data, (char *) &tmp_con_data) < 0)
    {
        fprintf(stderr, "failed to exchange connection data between sides\n");
        rc = 1;
        goto connect_qp_exit;
    }

    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    /* save the remote side attributes, we will need it for the post SR */
    lc->remote_props = remote_con_data;

    fprintf(stdout, "Remote QP number = 0x%x\n", remote_con_data.qp_num);
    fprintf(stdout, "Remote LID = 0x%x\n", remote_con_data.lid);
    if (lc->gid_idx >= 0)
    {
        uint8_t *p = remote_con_data.gid;
        fprintf(stdout, "Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n", p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
    }

    /* modify the QP to init */
    rc = modify_qp_to_init(lc->qp);
    if (rc)
    {
        fprintf(stderr, "change QP state to INIT failed\n");
        goto connect_qp_exit;
    }

    /* modify the QP to RTR */
    rc = modify_qp_to_rtr(lc->qp, remote_con_data.qp_num, remote_con_data.lid, remote_con_data.gid);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }

    rc = modify_qp_to_rts(lc->qp);
    if (rc)
    {
        fprintf(stderr, "failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }

    fprintf(stdout, "QP state was change to RTS\n");

connect_qp_exit:
    return rc;
}

static int qemu_rdma_connect(RDMAContext *rdma, Error **errp)
{
    // RDMACapabilities cap = {
    //                             .version = RDMA_CONTROL_VERSION_CURRENT,
    //                             .flags = 0,
    //                             .keepalive_rkey = rdma->keepalive_mr->rkey,
    //                             .keepalive_addr = (uint64_t) (uintptr_t) &rdma->keepalive,
    //                        };
    // struct rdma_conn_param conn_param = { .initiator_depth = 2,
    //                                       .retry_count = 5,
    //                                       .private_data = &cap,
    //                                       .private_data_len = sizeof(cap),
    //                                     };

    struct rdma_cm_event *cm_event = NULL;
    int ret;

    /*
     * Only negotiate the capability with destination if the user
     * on the source first requested the capability.
     */
    // if (rdma->pin_all) {
    //     trace_qemu_rdma_connect_pin_all_requested();
    //     cap.flags |= RDMA_CAPABILITY_PIN_ALL;
    // }

    // if (rdma->do_keepalive) {
    //     trace_qemu_rdma_connect_requested();
    //     cap.flags |= RDMA_CAPABILITY_KEEPALIVE;
    // }

    // trace_qemu_rdma_connect_send_keepalive(cap.keepalive_rkey, cap.keepalive_addr);

    // caps_to_network(&cap);

    // ret = rdma_connect(rdma->lc_remote.cm_id, &conn_param);
    // if (ret) {
    //     perror("rdma_connect");
    //     goto err_rdma_source_connect;
    // }

    ret = connect_qp(&rdma->lc_remote);
    if (ret) {
        /* code */
    }

    ret = qemu_rdma_connect_finish(rdma, &rdma->lc_remote, errp, &cm_event);

    if (ret) {
        goto err_rdma_source_connect;
    }

    // memcpy(&cap, cm_event->param.conn.private_data, sizeof(cap));
    // network_to_caps(&cap);

    // rdma->keepalive_rkey = cap.keepalive_rkey;
    // rdma->keepalive_addr = cap.keepalive_addr;

    // trace_qemu_rdma_connect_receive_keepalive(cap.keepalive_rkey, cap.keepalive_addr);

    /*
     * Verify that the *requested* capabilities are supported by the destination
     * and disable them otherwise.
     */
    // if (rdma->pin_all && !(cap.flags & RDMA_CAPABILITY_PIN_ALL)) {
    //     ERROR(errp, "Server cannot support pinning all memory. "
    //                     "Will register memory dynamically.");
    //     rdma->pin_all = false;
    // }

    // if (rdma->do_keepalive && !(cap.flags & RDMA_CAPABILITY_KEEPALIVE)) {
    //     ERROR(errp, "Server cannot support keepalives. "
    //                     "Will not check for them.");
    //     rdma->do_keepalive = false;
    // }

    // trace_qemu_rdma_connect_pin_all_outcome(rdma->pin_all ? "enabled" : "disabled");
    // trace_qemu_rdma_connect_keepalive_outcome(rdma->do_keepalive ? "enabled" : "disabled");

    // rdma_ack_cm_event(cm_event);

    ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_READY);
    if (ret) {
        ERROR(errp, "posting second control recv!");
        goto err_rdma_source_connect;
    }

    rdma->control_ready_expected = 1;
    rdma->nb_sent = 0;
    return 0;

err_rdma_source_connect:
    SET_ERROR(rdma, ret);
    qemu_rdma_cleanup(rdma, false);
    return rdma->error_state;
}

static void send_keepalive(void *opaque)
{
    RDMAContext *rdma = opaque;
    struct ibv_sge sge;
    struct ibv_send_wr send_wr = { 0 };
    struct ibv_send_wr *bad_wr;
    int ret;

    if (!rdma->migration_started) {
        goto reset;
    }

    rdma->next_keepalive++;
retry:

    sge.addr = (uintptr_t) &rdma->next_keepalive;
    sge.length = sizeof(rdma->next_keepalive);
    sge.lkey = rdma->next_keepalive_mr->lkey;
    send_wr.wr_id = RDMA_WRID_RDMA_KEEPALIVE;
    send_wr.opcode = IBV_WR_RDMA_WRITE;
    send_wr.send_flags = 0;
    send_wr.sg_list = &sge;
    send_wr.num_sge = 1;
    send_wr.wr.rdma.remote_addr = rdma->keepalive_addr;
    send_wr.wr.rdma.rkey = rdma->keepalive_rkey;

    //trace_qemu_rdma_send_keepalive_post(sge.addr, send_wr.wr.rdma.remote_addr, sge.length);

    ret = ibv_post_send(rdma->lc_remote.qp, &send_wr, &bad_wr);

    if (ret == ENOMEM) {
        //trace_qemu_rdma_send_keepalive_queue_full();
        g_usleep(RDMA_KEEPALIVE_INTERVAL_MS * 1000);
        goto retry;
    } else if (ret > 0) {
        perror("rdma migration: post keepalive");
        SET_ERROR(rdma, -ret);
        return;
    }

reset:
    timer_mod(keepalive_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                    RDMA_KEEPALIVE_INTERVAL_MS);
}

static void check_qp_state(void *opaque)
{
    RDMAContext *rdma = opaque;
    int first_missed = 0;

    if (!rdma->migration_started) {
        goto reset;
    }

    if (rdma->last_keepalive == rdma->keepalive) {
        rdma->nb_missed_keepalive++;
        if (rdma->nb_missed_keepalive == 1) {
            first_missed = RDMA_KEEPALIVE_FIRST_MISSED_OFFSET;
            trace_qemu_rdma_check_qp_state_missed_first();
        } else {
            trace_qemu_rdma_check_qp_state_missed(rdma->nb_missed_keepalive);
        }
    } else {
        rdma->keepalive_startup = true;
        rdma->nb_missed_keepalive = 0;
    }

    rdma->last_keepalive = rdma->keepalive;

    if (rdma->keepalive_startup) {
        if (rdma->nb_missed_keepalive > RDMA_MAX_LOST_KEEPALIVE) {
            struct ibv_qp_attr attr = {.qp_state = IBV_QPS_ERR };
            SET_ERROR(rdma, -ENETUNREACH);
            ERROR(NULL, "peer keepalive failed.");

            if (ibv_modify_qp(rdma->lc_remote.qp, &attr, IBV_QP_STATE)) {
                ERROR(NULL, "modify QP to RTR");
                return;
            }
            return;
        }
    } else if (rdma->nb_missed_keepalive < RDMA_MAX_STARTUP_MISSED_KEEPALIVE) {
        trace_qemu_rdma_check_qp_state_waiting(rdma->nb_missed_keepalive);
    } else {
        trace_qemu_rdma_check_qp_state_too_long();
        rdma->keepalive_startup = true;
    }

reset:
    timer_mod(connection_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                    RDMA_KEEPALIVE_INTERVAL_MS + first_missed);
}

static void qemu_rdma_keepalive_start(void)
{
    trace_qemu_rdma_keepalive_start();
    timer_mod(connection_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                    RDMA_CONNECTION_INTERVAL_MS);
    timer_mod(keepalive_timer, qemu_clock_get_ms(QEMU_CLOCK_REALTIME) +
                    RDMA_KEEPALIVE_INTERVAL_MS);
}

static void *qemu_rdma_data_init(const char *host_port, Error **errp)
{
    RDMAContext *rdma = NULL;
    InetSocketAddress *addr;

    if (host_port) {
        rdma = g_malloc0(sizeof(RDMAContext));
        memset(rdma, 0, sizeof(RDMAContext));
        rdma->chunk_remote.current_block_idx = -1;
        rdma->chunk_remote.current_chunk = -1;
        rdma->chunk_local_src.current_block_idx = -1;
        rdma->chunk_local_src.current_chunk = -1;
        rdma->chunk_local_dest.current_block_idx = -1;
        rdma->chunk_local_dest.current_chunk = -1;

        addr = inet_parse(host_port, NULL);
        if (addr != NULL) {
            rdma->lc_remote.port = atoi(addr->port);
            rdma->lc_remote.host = g_strdup(addr->host);
        } else {
            ERROR(errp, "bad RDMA migration address '%s'", host_port);
            g_free(rdma);
            rdma = NULL;
        }

        qapi_free_InetSocketAddress(addr);
    }

    rdma->keepalive_startup = false;
    connection_timer = timer_new_ms(QEMU_CLOCK_REALTIME, check_qp_state, rdma);
    keepalive_timer = timer_new_ms(QEMU_CLOCK_REALTIME, send_keepalive, rdma);
    rdma->lc_dest.id_str = "local destination";
    rdma->lc_src.id_str = "local src";
    rdma->lc_remote.id_str = "remote";

    return rdma;
}

/*
 * QEMUFile interface to the control channel.
 * SEND messages for control only.
 * VM's ram is handled with regular RDMA messages.
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
     * we're queued up for VM's ram.
     */
    ret = qemu_rdma_write(f, rdma, &rdma->chunk_remote, NULL);
    if (ret < 0) {
        SET_ERROR(rdma, ret);
        return ret;
    }

    while (remaining) {
        RDMAControlHeader head;

        r->len = MIN(remaining, RDMA_SEND_INCREMENT);
        remaining -= r->len;

        head.len = r->len;
        head.type = RDMA_CONTROL_QEMU_FILE;

        ret = qemu_rdma_exchange_send(rdma, &head, data, NULL, NULL, NULL);

        if (ret < 0) {
            SET_ERROR(rdma, ret);
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
        trace_qemu_rdma_fill(rdma->wr_data[idx].control_len, size);

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
        SET_ERROR(rdma, ret);
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
static int qemu_rdma_drain_cq(QEMUFile *f, RDMAContext *rdma,
                              RDMACurrentChunk *src,
                              RDMACurrentChunk *dest)
{
    int ret;
    RDMALocalContext *lc = (migrate_use_mc_rdma_copy() && dest && dest != src) ?
            (rdma->source ? &rdma->lc_src : &rdma->lc_dest) : &rdma->lc_remote;

    if (qemu_rdma_write(f, rdma, src, dest) < 0) {
        return -EIO;
    }

    while (lc->nb_sent) {
        ret = qemu_rdma_block_for_wrid(rdma, lc,
                                       RDMA_WRID_RDMA_WRITE_REMOTE, NULL);
        if (ret < 0) {
            ERROR(NULL, "complete polling!");
            return -EIO;
        }
    }

    qemu_rdma_unregister_waiting(rdma);

    return 0;
}

static int qemu_rdma_close(void *opaque)
{
    trace_qemu_rdma_close();
    QEMUFileRDMA *r = opaque;
    if (r->rdma) {
        qemu_rdma_cleanup(r->rdma, false);
        g_free(r->rdma);
    }
    g_free(r);
    return 0;
}

static int qemu_rdma_instruct_unregister(RDMAContext *rdma, QEMUFile *f,
                                         ram_addr_t block_offset,
                                         ram_addr_t offset, long size)
{
    int ret;
    uint64_t block, chunk;

    if (size < 0) {
        ret = qemu_rdma_drain_cq(f, rdma, &rdma->chunk_remote, NULL);
        if (ret < 0) {
            fprintf(stderr, "rdma: failed to synchronously drain"
                            " completion queue before unregistration.\n");
            return ret;
        }
    }

    ret = qemu_rdma_search_ram_block(rdma, block_offset,
                                     offset, size, &block, &chunk);

    if (ret) {
        error_report("ram block search failed");
        return ret;
    }

    qemu_rdma_signal_unregister(rdma, block, chunk, 0);

    /*
     * Synchronous, gauranteed unregistration (should not occur during
     * fast-path). Otherwise, unregisters will process on the next call to
     * qemu_rdma_drain_cq()
     */
    if (size < 0) {
        qemu_rdma_unregister_waiting(rdma);
    }

    return 0;
}


static int qemu_rdma_poll_until_empty(RDMAContext *rdma, RDMALocalContext *lc)
{
    uint64_t wr_id, wr_id_in;
    int ret;

    /*
     * Drain the Completion Queue if possible, but do not block,
     * just poll.
     *
     * If nothing to poll, the end of the iteration will do this
     * again to make sure we don't overflow the request queue.
     */
    while (1) {
        ret = qemu_rdma_poll(rdma, lc, &wr_id_in, NULL);
        if (ret < 0) {
            ERROR(NULL, "empty polling error! %d", ret);
            return ret;
        }

        wr_id = wr_id_in & RDMA_WRID_TYPE_MASK;

        if (wr_id == RDMA_WRID_NONE) {
            break;
        }
    }

    return 0;
}

/*
 * Parameters:
 *    @offset_{source|dest} == 0 :
 *        This means that 'block_offset' is a full virtual address that does not
 *        belong to a RAMBlock of the virtual machine and instead
 *        represents a private malloc'd memory area that the caller wishes to
 *        transfer. Source and dest can be different (either real RAMBlocks or
 *        private).
 *
 *    @offset != 0 :
 *        Offset is an offset to be added to block_offset and used
 *        to also lookup the corresponding RAMBlock. Source and dest can be different
 *        (either real RAMBlocks or private).
 *
 *    @size > 0 :
 *        Amount of memory to copy locally using RDMA.
 *
 *    @size == 0 :
 *        A 'hint' or 'advice' that means that we wish to speculatively
 *        and asynchronously unregister either the source or destination memory.
 *        In this case, there is no gaurantee that the unregister will actually happen,
 *        for example, if the memory is being actively copied. Additionally, the memory
 *        may be re-registered at any future time if a copy within the same
 *        range was requested again, even if you attempted to unregister it here.
 *
 *    @size < 0 : TODO, not yet supported
 *        Unregister the memory NOW. This means that the caller does not
 *        expect there to be any future RDMA copies and we just want to clean
 *        things up. This is used in case the upper layer owns the memory and
 *        cannot wait for qemu_fclose() to occur.
 */
static int qemu_rdma_copy_page(QEMUFile *f, void *opaque,
                                  ram_addr_t block_offset_dest,
                                  ram_addr_t offset_dest,
                                  ram_addr_t block_offset_source,
                                  ram_addr_t offset_source,
                                  long size)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    int ret;
    RDMACurrentChunk *src = &rdma->chunk_local_src;
    RDMACurrentChunk *dest = &rdma->chunk_local_dest;

    CHECK_ERROR_STATE();

    qemu_fflush(f);

    if (size > 0) {
        /*
         * Add this page to the current 'chunk'. If the chunk
         * is full, or the page doen't belong to the current chunk,
         * an actual RDMA write will occur and a new chunk will be formed.
         */
        src->block_offset = block_offset_source;
        src->offset = offset_source;
        dest->block_offset = block_offset_dest;
        dest->offset = offset_dest;

        //trace_qemu_rdma_copy_page((void *) block_offset_source, offset_source, (void *) block_offset_dest, offset_dest);

        ret = qemu_rdma_flush_unmergable(rdma, src, dest, f, size);

        if (ret) {
            ERROR(NULL, "local copy flush");
            goto err;
        }

        if ((src->current_length >= RDMA_MERGE_MAX) ||
            (dest->current_length >= RDMA_MERGE_MAX)) {
            ret = qemu_rdma_write(f, rdma, src, dest);

            if (ret < 0) {
                goto err;
            }
        } else {
            ret = 0;
        }
    } else {
        ret = qemu_rdma_instruct_unregister(rdma, f, block_offset_source,
                                                  offset_source, size);
        if (ret) {
            goto err;
        }

        ret = qemu_rdma_instruct_unregister(rdma, f, block_offset_dest,
                                                  offset_dest, size);

        if (ret) {
            goto err;
        }
    }

    ret = qemu_rdma_poll_until_empty(rdma,
                rdma->source ? &rdma->lc_src : &rdma->lc_dest);

    if (ret) {
        goto err;
    }

    return RAM_COPY_CONTROL_DELAYED;
err:
    SET_ERROR(rdma, ret);
    return ret;
}

/*
 * Parameters:
 *    @offset == 0 :
 *        This means that 'block_offset' is a full virtual address that does not
 *        belong to a RAMBlock of the virtual machine and instead
 *        represents a private malloc'd memory area that the caller wishes to
 *        transfer.
 *
 *        This allows callers to initiate RDMA transfers of arbitrary memory
 *        areas and not just only by migration itself.
 *
 *        If this is true, then the virtual address specified by 'block_offset'
 *        below must have been pre-registered with us in advance by calling the
 *        new QEMUFileOps->add()/remove() functions on both sides of the
 *        connection.
 *
 *        Also note: add()/remove() must been called in the *same sequence* and
 *        against the *same size* private virtual memory on both sides of the
 *        connection for this to work, regardless whether or not transfer of
 *        this private memory was initiated by the migration code or a private
 *        caller.
 *
 *    @offset != 0 :
 *        Offset is an offset to be added to block_offset and used
 *        to also lookup the corresponding RAMBlock.
 *
 *    @size > 0 :
 *        Initiate an transfer this size.
 *
 *    @size == 0 :
 *        A 'hint' that means that we wish to speculatively
 *        and asynchronously unregister this memory. In this case, there is no
 *        guarantee that the unregister will actually happen, for example,
 *        if the memory is being actively transmitted. Additionally, the memory
 *        may be re-registered at any future time if a write within the same
 *        chunk was requested again, even if you attempted to unregister it
 *        here.
 *
 *    @size < 0 : TODO, not yet supported
 *        Unregister the memory NOW. This means that the caller does not
 *        expect there to be any future RDMA transfers and we just want to clean
 *        things up. This is used in case the upper layer owns the memory and
 *        cannot wait for qemu_fclose() to occur.
 *
 *    @bytes_sent : User-specificed pointer to indicate how many bytes were
 *                  sent. Usually, this will not be more than a few bytes of
 *                  the protocol because most transfers are sent asynchronously.
 */
static int qemu_rdma_save_page(QEMUFile *f, void *opaque,
                                  ram_addr_t block_offset,
                                  uint8_t *host_addr,
                                  ram_addr_t offset,
                                  long size, uint64_t *bytes_sent)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    RDMACurrentChunk *cc = &rdma->chunk_remote;
    int ret;

    CHECK_ERROR_STATE();

    qemu_fflush(f);

    if (size > 0) {
        /*
         * Add this page to the current 'chunk'. If the chunk
         * is full, or the page doen't belong to the current chunk,
         * an actual RDMA write will occur and a new chunk will be formed.
         */
        cc->block_offset = block_offset;
        cc->offset = offset;

        ret = qemu_rdma_flush_unmergable(rdma, cc, NULL, f, size);

        if (ret) {
            ERROR(NULL, "remote flush unmergable");
            goto err;
        }

        if (cc->current_length >= RDMA_MERGE_MAX) {
            ret = qemu_rdma_write(f, rdma, cc, NULL);

            if (ret < 0) {
                ERROR(NULL, "remote write! %d", ret);
                goto err;
            }
        } else {
            ret = 0;
        }

        /*
         * We always return 1 bytes because the RDMA
         * protocol is completely asynchronous. We do not yet know
         * whether an  identified chunk is zero or not because we're
         * waiting for other pages to potentially be merged with
         * the current chunk. So, we have to call qemu_update_position()
         * later on when the actual write occurs.
         */
        if (bytes_sent) {
            *bytes_sent = 1;
        }
    } else {
        ret = qemu_rdma_instruct_unregister(rdma, f, block_offset, offset, size);

        if (ret) {
            goto err;
        }
    }

    ret = qemu_rdma_poll_until_empty(rdma, &rdma->lc_remote);

    if (ret) {
        goto err;
    }

    return RAM_SAVE_CONTROL_DELAYED;
err:
    SET_ERROR(rdma, ret);
    return ret;
}

static int qemu_rdma_accept_start(RDMAContext *rdma,
                                  RDMALocalContext *lc,
                                  struct rdma_cm_event **return_event)
{
    // struct rdma_cm_event *cm_event = NULL;
    int ret;

    // ret = rdma_get_cm_event(lc->channel, &cm_event);
    // if (ret) {
    //     ERROR(NULL, "failed to wait for initial connect request");
    //     goto err;
    // }

    // if (cm_event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
    //     ERROR(NULL, "initial connect request is invalid");
    //     ret = -EINVAL;
    //     rdma_ack_cm_event(cm_event);
    //     goto err;
    // }

    // if (lc->verbs && (lc->verbs != cm_event->id->verbs)) {
    //     ret = -EINVAL;
    //     ERROR(NULL, "ibv context %p != %p!", lc->verbs,
    //                                          cm_event->id->verbs);
    //     goto err;
    // }

    // lc->cm_id = cm_event->id;
    // lc->verbs = cm_event->id->verbs;

    // trace_qemu_rdma_accept_pin_verbsc(lc->verbs);
    // qemu_rdma_dump_id("rdma_accept_start", lc->verbs);

    // if (return_event) {
    //     *return_event = cm_event;
    // } else {
    //     rdma_ack_cm_event(cm_event);
    // }

    lc->sock = accept(lc->sock, NULL, 0);

    ret = resources_create(rdma, lc);

    // ret = qemu_rdma_alloc_pd_cq_qp(rdma, lc);
    // if (ret) {
    //     goto err;
    // }

    return 0;
// err:
//     SET_ERROR(rdma, ret);
//     return rdma->error_state;
}

static int qemu_rdma_accept_finish(RDMAContext *rdma,
                                   RDMALocalContext *lc)
{
    // struct rdma_cm_event *cm_event;
    // int ret;

    // ret = rdma_get_cm_event(lc->channel, &cm_event);
    // if (ret) {
    //     ERROR(NULL, "rdma_accept get_cm_event failed %d!", ret);
    //     goto err;
    // }

    // if (cm_event->event != RDMA_CM_EVENT_ESTABLISHED) {
    //     ERROR(NULL, "rdma_accept not event established!");
    //     rdma_ack_cm_event(cm_event);
    //     goto err;
    // }

    // rdma_ack_cm_event(cm_event);
    lc->connected = true;

    return 0;
// err:
//     SET_ERROR(rdma, ret);
//     return rdma->error_state;
}

static int qemu_rdma_accept(RDMAContext *rdma)
{
    // RDMACapabilities cap;
    // struct rdma_conn_param conn_param = {
    //                                         .responder_resources = 2,
    //                                         .private_data = &cap,
    //                                         .private_data_len = sizeof(cap),
    //                                      };
    // struct rdma_cm_event *cm_event;
    int ret = -EINVAL;
    int idx;

    // ret = qemu_rdma_accept_start(rdma, &rdma->lc_remote, &cm_event);

    // memcpy(&cap, cm_event->param.conn.private_data, sizeof(cap));

    // network_to_caps(&cap);

    // if (cap.version < 1 || cap.version > RDMA_CONTROL_VERSION_CURRENT) {
    //         error_report("Unknown source RDMA version: %d, bailing...",
    //                         cap.version);
    //         rdma_ack_cm_event(cm_event);
    //         goto err_rdma_dest_wait;
    // }

    // rdma->keepalive_rkey = cap.keepalive_rkey;
    // rdma->keepalive_addr = cap.keepalive_addr;

    //trace_qemu_rdma_accept_keepalive(cap.keepalive_rkey, cap.keepalive_addr, (uint64_t) &rdma->keepalive);

    /*
     * Respond with only the capabilities this version of QEMU knows about.
     */
    // cap.flags &= known_capabilities;

    /*
     * Enable the ones that we do know about.
     * Add other checks here as new ones are introduced.
     */
    // rdma->pin_all = cap.flags & RDMA_CAPABILITY_PIN_ALL;
    // rdma->do_keepalive = cap.flags & RDMA_CAPABILITY_KEEPALIVE;

    trace_qemu_rdma_accept_pin_state(rdma->pin_all ? "enabled" : "disabled");
    trace_qemu_rdma_accept_keepalive_state(rdma->do_keepalive ? "enabled" : "disabled");

    // rdma_ack_cm_event(cm_event);

    ret = qemu_rdma_reg_keepalive(rdma);

    if (ret) {
        ERROR(NULL, "allocating keepalive structures");
        goto err_rdma_dest_wait;
    }

    // cap.keepalive_rkey = rdma->keepalive_mr->rkey,
    // cap.keepalive_addr = (uint64_t) (uintptr_t) &rdma->keepalive;

    // trace_qemu_rdma_accept_keepalive_send(cap.keepalive_rkey, cap.keepalive_addr, rdma->keepalive_addr);

    // caps_to_network(&cap);

    // ret = rdma_accept(rdma->lc_remote.cm_id, &conn_param);
    // if (ret) {
    //     ERROR(NULL, "rdma_accept returns %d!", ret);
    //     goto err_rdma_dest_wait;
    // }

    ret = connect_qp(&rdma->lc_remote);
    if (ret) {
        /* code */
    }

    ret = qemu_rdma_accept_finish(rdma, &rdma->lc_remote);

    if (ret) {
        ERROR(NULL, "finishing connection with capabilities to source");
        goto err_rdma_dest_wait;
    }

    ret = qemu_rdma_init_ram_blocks(rdma);
    if (ret) {
        ERROR(NULL, "initializing ram blocks!");
        goto err_rdma_dest_wait;
    }

    for (idx = 0; idx < RDMA_WRID_MAX; idx++) {
        ret = qemu_rdma_reg_control(rdma, idx);
        if (ret) {
            ERROR(NULL, "registering %d control!", idx);
            goto err_rdma_dest_wait;
        }
    }

    // qemu_set_fd_handler(rdma->lc_remote.channel->fd, NULL, NULL, NULL);
    qemu_set_fd_handler(rdma->lc_remote.sock, NULL, NULL, NULL);

    ret = qemu_rdma_post_recv_control(rdma, RDMA_WRID_READY);
    if (ret) {
        ERROR(NULL, "posting second control recv!");
        goto err_rdma_dest_wait;
    }

    qemu_rdma_dump_gid("dest_connect", rdma->lc_remote.cm_id);

    return 0;

err_rdma_dest_wait:
    SET_ERROR(rdma, ret);
    qemu_rdma_cleanup(rdma, false);
    return ret;
}

/*
 * During each iteration of the migration, we listen for instructions
 * by the source VM to perform pinning operations before they
 * can perform RDMA operations.
 *
 * Keep doing this until the source tells us to stop.
 */
static int qemu_rdma_registration_handle(QEMUFile *f, void *opaque,
                                         uint64_t flags)
{
    RDMAControlHeader reg_resp = { .len = sizeof(RDMARegisterResult),
                               .type = RDMA_CONTROL_REGISTER_RESULT,
                               .repeat = 0,
                             };
    RDMAControlHeader unreg_resp = { .len = 0,
                               .type = RDMA_CONTROL_UNREGISTER_FINISHED,
                               .repeat = 0,
                             };
    RDMAControlHeader blocks = { .type = RDMA_CONTROL_RAM_BLOCKS_RESULT,
                                 .repeat = 1 };
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;
    RDMALocalBlocks *local = &rdma->local_ram_blocks;
    RDMAControlHeader head;
    RDMARegister *reg, *registers;
    RDMACompress *comp;
    RDMARegisterResult *reg_result;
    RDMALocalBlock *block;
    static RDMARegisterResult results[RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE];
    void *host_addr;
    int ret = 0;
    int idx = 0;
    int count = 0;
    int i = 0;

    CHECK_ERROR_STATE();

    do {
        trace_qemu_rdma_registration_handle_wait(flags);

        ret = qemu_rdma_exchange_recv(rdma, &head, RDMA_CONTROL_NONE);

        if (ret < 0) {
            break;
        }

        if (head.repeat > RDMA_CONTROL_MAX_COMMANDS_PER_MESSAGE) {
            error_report("rdma: Too many requests in this message (%d)."
                            "Bailing.", head.repeat);
            ret = -EIO;
            break;
        }

        switch (head.type) {
        case RDMA_CONTROL_COMPRESS:
            comp = (RDMACompress *) rdma->wr_data[idx].control_curr;
            network_to_compress(comp);

            trace_qemu_rdma_registration_handle_compress(comp->length,
                                                         comp->block_idx,
                                                         comp->offset);
            block = &(rdma->local_ram_blocks.block[comp->block_idx]);

            host_addr = block->local_host_addr +
                            (comp->offset - block->offset);

            ram_handle_compressed(host_addr, comp->value, comp->length);
            break;

        case RDMA_CONTROL_REGISTER_FINISHED:
            trace_qemu_rdma_registration_handle_finished();
            goto out;

        case RDMA_CONTROL_RAM_BLOCKS_REQUEST:
            trace_qemu_rdma_registration_handle_ram_blocks();

            if (rdma->pin_all) {
                ret = qemu_rdma_reg_whole_ram_blocks(rdma);
                if (ret) {
                    ERROR(NULL, "dest registering ram blocks!");
                    goto out;
                }
            }

            /*
             * Dest uses this to prepare to transmit the RAMBlock descriptions
             * to the source VM after connection setup.
             * Both sides use the "remote" structure to communicate and update
             * their "local" descriptions with what was sent.
             */
            for (i = 0; i < local->nb_blocks; i++) {
                rdma->dest_blocks[i].remote_host_addr =
                    (uintptr_t)(local->block[i].local_host_addr);

                if (rdma->pin_all) {
                    rdma->dest_blocks[i].remote_rkey = local->block[i].mr->rkey;
                }

                rdma->dest_blocks[i].offset = local->block[i].offset;
                rdma->dest_blocks[i].length = local->block[i].length;

                dest_block_to_network(&rdma->dest_blocks[i]);
            }

            blocks.len = rdma->local_ram_blocks.nb_blocks
                                                * sizeof(RDMADestBlock);


            ret = qemu_rdma_post_send_control(rdma,
                                        (uint8_t *) rdma->dest_blocks, &blocks);

            if (ret < 0) {
                ERROR(NULL, "sending remote info!");
                goto out;
            }

            break;
        case RDMA_CONTROL_REGISTER_REQUEST:
            trace_qemu_rdma_registration_handle_register(head.repeat);

            reg_resp.repeat = head.repeat;
            registers = (RDMARegister *) rdma->wr_data[idx].control_curr;

            for (count = 0; count < head.repeat; count++) {
                RDMACurrentChunk cc;

                reg = &registers[count];
                network_to_register(reg);

                reg_result = &results[count];

                trace_qemu_rdma_registration_handle_request(count, reg->current_block_idx, reg->key.current_addr, reg->chunks);

                cc.block = &(rdma->local_ram_blocks.block[reg->current_block_idx]);
                if (cc.block->is_ram_block) {
                    cc.addr = (cc.block->local_host_addr +
                                (reg->key.current_addr - cc.block->offset));
                    cc.chunk_idx = ram_chunk_index(cc.block->local_host_addr, cc.addr);
                } else {
                    cc.chunk_idx = reg->key.chunk;
                    cc.addr = cc.block->local_host_addr +
                        (reg->key.chunk * (1UL << RDMA_REG_CHUNK_SHIFT));
                }
                cc.chunk_start = ram_chunk_start(cc.block, cc.chunk_idx);
                cc.chunk_end = ram_chunk_end(cc.block, cc.chunk_idx + reg->chunks);
                if (qemu_rdma_register_and_get_keys(rdma, &cc, &rdma->lc_remote,
                                            false, NULL, &reg_result->rkey)) {
                    error_report("cannot get rkey!");
                    ret = -EINVAL;
                    goto out;
                }

                reg_result->host_addr = (uintptr_t) cc.block->local_host_addr;
                trace_qemu_rdma_registration_handle_register_rkey(
                                                           reg_result->rkey);

                result_to_network(reg_result);
            }

            ret = qemu_rdma_post_send_control(rdma,
                            (uint8_t *) results, &reg_resp);

            if (ret < 0) {
                error_report("Failed to send control buffer");
                goto out;
            }
            break;
        case RDMA_CONTROL_UNREGISTER_REQUEST:
            trace_qemu_rdma_registration_handle_unregister(head.repeat);
            unreg_resp.repeat = head.repeat;
            registers = (RDMARegister *) rdma->wr_data[idx].control_curr;

            for (count = 0; count < head.repeat; count++) {
                reg = &registers[count];
                network_to_register(reg);

                trace_qemu_rdma_registration_handle_unregister_loop(count,
                           reg->current_block_idx, reg->key.chunk);

                block = &(rdma->local_ram_blocks.block[reg->current_block_idx]);

                ret = ibv_dereg_mr(block->pmr[reg->key.chunk]);
                block->pmr[reg->key.chunk] = NULL;

                if (ret != 0) {
                    perror("rdma unregistration chunk failed");
                    ret = -ret;
                    goto out;
                }

                rdma->total_registrations--;

                trace_qemu_rdma_registration_handle_unregister_success(
                                                       reg->key.chunk);
            }

            ret = qemu_rdma_post_send_control(rdma, NULL, &unreg_resp);

            if (ret < 0) {
                error_report("Failed to send control buffer");
                goto out;
            }
            break;
        case RDMA_CONTROL_REGISTER_RESULT:
            error_report("Invalid RESULT message at dest.");
            ret = -EIO;
            goto out;
        default:
            error_report("Unknown control message %s", control_desc[head.type]);
            ret = -EIO;
            goto out;
        }
    } while (1);
out:
    if (ret < 0) {
        SET_ERROR(rdma, ret);
    }
    return ret;
}

static int qemu_rdma_registration_start(QEMUFile *f, void *opaque,
                                        uint64_t flags)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;

    CHECK_ERROR_STATE();

    trace_qemu_rdma_registration_start(flags);

    if (flags == RAM_CONTROL_FLUSH) {
        int ret;

        if (rdma->source) {
            ret = qemu_rdma_drain_cq(f, rdma, &rdma->chunk_local_src,
                                              &rdma->chunk_local_dest);

            if (ret < 0) {
                return ret;
            }
        }

    } else {
        qemu_put_be64(f, RAM_SAVE_FLAG_HOOK);
    }

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
    int ret = 0;

    CHECK_ERROR_STATE();

    qemu_fflush(f);
    ret = qemu_rdma_drain_cq(f, rdma, &rdma->chunk_remote, NULL);

    if (ret < 0) {
        goto err;
    }

    if (flags == RAM_CONTROL_SETUP) {
        RDMAControlHeader resp = {.type = RDMA_CONTROL_RAM_BLOCKS_RESULT };
        RDMALocalBlocks *local = &rdma->local_ram_blocks;
        int reg_result_idx, i, j, nb_dest_blocks;

        head.type = RDMA_CONTROL_RAM_BLOCKS_REQUEST;
        trace_qemu_rdma_registration_stop_ram();

        /*
         * Make sure that we parallelize the pinning on both sides.
         * For very large guests, doing this serially takes a really
         * long time, so we have to 'interleave' the pinning locally
         * with the control messages by performing the pinning on this
         * side before we receive the control response from the other
         * side that the pinning has completed.
         */
        ret = qemu_rdma_exchange_send(rdma, &head, NULL, &resp,
                    &reg_result_idx, rdma->pin_all ?
                    qemu_rdma_reg_whole_ram_blocks : NULL);
        if (ret < 0) {
            ERROR(errp, "receiving remote info!");
            return ret;
        }

        nb_dest_blocks = resp.len / sizeof(RDMADestBlock);

        /*
         * The protocol uses two different sets of rkeys (mutually exclusive):
         * 1. One key to represent the virtual address of the entire ram block.
         *    (pinning enabled - pin everything with one rkey.)
         * 2. One to represent individual chunks within a ram block.
         *    (pinning disabled - pin individual chunks.)
         *
         * Once the capability is successfully negotiated, the destination transmits
         * the keys to use (or sends them later) including the virtual addresses
         * and then propagates the remote ram block descriptions to their local copy.
         */

        if (local->nb_blocks != nb_dest_blocks) {
            ERROR(errp, "ram blocks mismatch #1! "
                        "Your QEMU command line parameters are probably "
                        "not identical on both the source and destination.");
            return -EINVAL;
        }

        qemu_rdma_move_header(rdma, reg_result_idx, &resp);
        memcpy(rdma->dest_blocks,
            rdma->wr_data[reg_result_idx].control_curr, resp.len);
        for (i = 0; i < nb_dest_blocks; i++) {
            network_to_dest_block(&rdma->dest_blocks[i]);

            /* search local ram blocks */
            for (j = 0; j < local->nb_blocks; j++) {
                if (rdma->dest_blocks[i].offset != local->block[j].offset) {
                    continue;
                }

                if (rdma->dest_blocks[i].length != local->block[j].length) {
                    ERROR(errp, "ram blocks mismatch #2! "
                        "Your QEMU command line parameters are probably "
                        "not identical on both the source and destination.");
                    return -EINVAL;
                }
                local->block[j].remote_host_addr =
                        rdma->dest_blocks[i].remote_host_addr;
                local->block[j].remote_rkey = rdma->dest_blocks[i].remote_rkey;
                break;
            }

            if (j >= local->nb_blocks) {
                ERROR(errp, "ram blocks mismatch #3! "
                        "Your QEMU command line parameters are probably "
                        "not identical on both the source and destination.");
                return -EINVAL;
            }
        }
    }

    trace_qemu_rdma_registration_stop(flags);

    head.type = RDMA_CONTROL_REGISTER_FINISHED;
    ret = qemu_rdma_exchange_send(rdma, &head, NULL, NULL, NULL, NULL);

    if (ret < 0) {
        goto err;
    }

    return 0;
err:
    SET_ERROR(rdma, ret);
    return ret;
}

static int qemu_rdma_get_fd(void *opaque)
{
    QEMUFileRDMA *rfile = opaque;
    RDMAContext *rdma = rfile->rdma;

    return rdma->lc_remote.comp_chan->fd;
}

static int qemu_rdma_delete_block(QEMUFile *f, void *opaque,
                                  ram_addr_t block_offset)
{
    QEMUFileRDMA *rfile = opaque;
    return delete_block(rfile->rdma, block_offset);
}


static int qemu_rdma_add_block(QEMUFile *f, void *opaque, void *host_addr,
                         ram_addr_t block_offset, uint64_t length)
{
    QEMUFileRDMA *rfile = opaque;
    return add_block(rfile->rdma, host_addr, block_offset, length);
}

static const QEMUFileOps rdma_read_ops = {
    .get_buffer    = qemu_rdma_get_buffer,
    .get_fd        = qemu_rdma_get_fd,
    .close         = qemu_rdma_close,
    .hook_ram_load = qemu_rdma_registration_handle,
    .copy_page     = qemu_rdma_copy_page,
    .add           = qemu_rdma_add_block,
    .remove        = qemu_rdma_delete_block,
};

static const QEMUFileOps rdma_write_ops = {
    .put_buffer         = qemu_rdma_put_buffer,
    .close              = qemu_rdma_close,
    .before_ram_iterate = qemu_rdma_registration_start,
    .after_ram_iterate  = qemu_rdma_registration_stop,
    .save_page          = qemu_rdma_save_page,
    .copy_page          = qemu_rdma_copy_page,
    .add                = qemu_rdma_add_block,
    .remove             = qemu_rdma_delete_block,
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

static int rdma_init_local(RDMAContext *rdma)
{
    int ret;
    struct rdma_conn_param cp_dest   = { .responder_resources = 2 },
                           cp_source = { .initiator_depth = 2,
                                         .retry_count = 5,
                                       };

    if (!migrate_use_mc_rdma_copy()) {
        printf("RDMA local copy is disabled.\n");
        return 0;
    }

    rdma->lc_dest.port = 0;
    rdma->lc_src.host = g_malloc(100);
    rdma->lc_dest.host = g_malloc(100);
    strcpy(rdma->lc_src.host, "127.0.0.1");
    strcpy(rdma->lc_dest.host, rdma->lc_src.host);
    rdma->lc_src.source = true;
    rdma->lc_src.dest = false;
    rdma->lc_dest.source = false;
    rdma->lc_dest.dest = true;

    /* bind & listen */
    ret = qemu_rdma_device_init(rdma, NULL, &rdma->lc_dest);
    if (ret) {
        ERROR(NULL, "initialize local device destination");
        goto err;
    }

    rdma->lc_src.port = ntohs(rdma_get_src_port(rdma->lc_dest.listen_id));

    trace_rdma_init_local(rdma->lc_src.port);

    /* resolve */
    ret = qemu_rdma_device_init(rdma, NULL, &rdma->lc_src);

    if (ret) {
        ERROR(NULL, "Failed to initialize local device source");
        goto err;
    }

    /* async connect */
    ret = rdma_connect(rdma->lc_src.cm_id, &cp_source);
    if (ret) {
        ERROR(NULL, "connect local device source");
        goto err;
    }

    /* async accept */
    ret = qemu_rdma_accept_start(rdma, &rdma->lc_dest, NULL);
    if (ret) {
        ERROR(NULL, "starting accept for local connection");
        goto err;
    }

    /* accept */
    ret = rdma_accept(rdma->lc_dest.cm_id, &cp_dest);
    if (ret) {
        ERROR(NULL, "rdma_accept returns %d (%s)!", ret, rdma->lc_dest.id_str);
        goto err;
    }

    /* ack accept */
    ret = qemu_rdma_connect_finish(rdma, &rdma->lc_src, NULL, NULL);
    if (ret) {
        ERROR(NULL, "finish local connection with source");
        goto err;
    }

    /* established */
    ret = qemu_rdma_accept_finish(rdma, &rdma->lc_dest);

    if (ret) {
        ERROR(NULL, "finish accept connection");
        goto err;
    }

    return 0;
err:
    perror("rdma_init_local");
    SET_ERROR(rdma, -ret);
    return rdma->error_state;
}

static void rdma_accept_incoming_migration(void *opaque)
{
    RDMAContext *rdma = opaque;
    int ret;
    QEMUFile *f;
    Error *local_err = NULL, **errp = &local_err;

    trace_qemu_rdma_accept_incoming_migration();
    ret = qemu_rdma_accept(rdma);

    if (ret) {
        ERROR(errp, "initialization failed!");
        return;
    }

    trace_qemu_rdma_accept_incoming_migration_accepted();

    f = qemu_fopen_rdma(rdma, "rb");
    if (f == NULL) {
        ERROR(errp, "could not qemu_fopen_rdma!");
        goto err;
    }

    if (rdma->do_keepalive) {
        qemu_rdma_keepalive_start();
    }

    rdma->migration_started = 1;
    process_incoming_migration(f);
    return;
err:
    qemu_rdma_cleanup(rdma, false);
}

static int sock_connect(RDMAContext *rdma, const char *servername, int port)
{
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;
    int listenfd = 0;
    int tmp;

    struct addrinfo hints =
    {
        .ai_flags = AI_PASSIVE,
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    if (sprintf(service, "%d", port) < 0)
    {
        goto sock_connect_exit;
    }

    /* Resolve DNS address, use sockfd as temp storage */
    
    sockfd = getaddrinfo(servername, service, &hints, &resolved_addr);

    if (sockfd < 0)
    {
        fprintf(stderr, "%s for %s:%d\n", gai_strerror(sockfd), servername, port);
        goto sock_connect_exit;
    }

    /* Search through results and find the one we want */

    for (iterator = resolved_addr; iterator ; iterator = iterator->ai_next)
    {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);

        if (sockfd >= 0)
        {
            if (servername)
                /* Client mode. Initiate connection to remote */
                if ((tmp=connect(sockfd, iterator->ai_addr, iterator->ai_addrlen)))
                {
                    fprintf(stdout, "failed connect \n");
                    close(sockfd);
                    sockfd = -1;
                }
            else
            {
                /* Server mode. Set up listening socket an accept a connection */
                listenfd = sockfd;
                if (bind(listenfd, iterator->ai_addr, iterator->ai_addrlen))
                {
                    goto sock_connect_exit;
                }
                listen(listenfd, 1);

                qemu_set_fd_handler(listenfd,
                                   rdma_accept_incoming_migration, NULL,
                                   (void *)(intptr_t) rdma);
            }
        }
    }

sock_connect_exit:
    if (listenfd)
    {
        close(listenfd);
    }

    if (resolved_addr)
    {
        freeaddrinfo(resolved_addr);
    }

    if (sockfd < 0)
    {
        if (servername)
        {
            fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
        }
        else
        {
            perror("server accept");
            fprintf(stderr, "accept() failed\n");
        }
    }

    return sockfd;
}

static int qemu_rdma_init_incoming(RDMAContext *rdma, Error **errp)
{
    int ret;
    Error *local_err = NULL;

    rdma->source = false;
    rdma->dest = true;
    rdma->lc_remote.source = false;
    rdma->lc_remote.dest = true;

    ret = qemu_rdma_device_init(rdma, &local_err, &rdma->lc_remote);

    if (ret) {
        goto err;
    }

    return 0;
err:
    if (rdma->lc_remote.listen_id) {
        rdma_destroy_id(rdma->lc_remote.listen_id);
        rdma->lc_remote.listen_id = NULL;
    }
    error_propagate(errp, local_err);

    return ret;
}

void rdma_start_incoming_migration(const char *host_port, Error **errp)
{
    int ret;
    RDMAContext *rdma;
    Error *local_err = NULL;

    trace_rdma_start_incoming_migration();
    rdma = qemu_rdma_data_init(host_port, &local_err);

    if (rdma == NULL) {
        goto err;
    }

    ret = qemu_rdma_init_incoming(rdma, &local_err);

    if (ret) {
        goto err;
    }

    // qemu_set_fd_handler(rdma->lc_remote.channel->fd,
    //                     rdma_accept_incoming_migration, NULL,
    //                     (void *)(intptr_t) rdma);
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
        ERROR(temp, "Failed to initialize RDMA data structures! %d", ret);
        goto err;
    }

    rdma->source = true;
    rdma->dest = false;

    if (rdma_init_local(rdma)) {
        ERROR(temp, "could not initialize local rdma queue pairs!");
        goto err;
    }

    ret = qemu_rdma_init_outgoing(rdma, &local_err, s);

    if (ret) {
        goto err;
    }

    trace_rdma_start_outgoing_migration_connect();
    ret = qemu_rdma_connect(rdma, &local_err);

    if (ret) {
        goto err;
    }

    trace_rdma_start_outgoing_migration_success();

    s->file = qemu_fopen_rdma(rdma, "wb");
    rdma->migration_started = 1;

    if (rdma->do_keepalive) {
        qemu_rdma_keepalive_start();
    }

    migrate_fd_connect(s);
    return;
err:
    error_propagate(errp, local_err);
    g_free(rdma);
    migrate_fd_error(s);
}
