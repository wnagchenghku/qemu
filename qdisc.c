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
#include "qemu-common.h"
#include "net/qdisc.h"
#include "hw/virtio.h"
#include "hw/virtio-net.h"
#include <libnl3/netlink/route/qdisc/plug.h>
#include <libnl3/netlink/route/class.h>
#include <libnl3/netlink/cli/utils.h>
#include <libnl3/netlink/cli/tc.h>
#include <libnl3/netlink/cli/qdisc.h>
#include <libnl3/netlink/cli/link.h>

//#define DEBUG_QDISC

#ifdef DEBUG_QDISC
#define DPRINTF(fmt, ...) \
    do { printf("qdisc: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

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

static int qdisc_deliver(int update)
{
    int err, flags = NLM_F_CREATE;

    if(!buffering_enabled)
	return -EINVAL;

    if (!update)
        flags |= NLM_F_EXCL;
  
    if ((err = rtnl_qdisc_add(sock, qdisc, flags)) < 0) {
	fprintf(stderr, "Unable control qdisc: %s!\n", nl_geterror(err));
	return -EINVAL;
    }

    return 0;
}

int qdisc_set_buffer_size(int size)
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

   printf("Set buffer size to %d bytes\n", size);

   return qdisc_deliver(1);
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
    device[end - 1] = '\0';

    first_nic_chosen = 1;
}

/*
 * Install a Qdisc plug for micro-checkpointing. 
 * If it exists already (say, from a previous dead VM or debugging
 * session) then just open all the netlink data structures pointing 
 * to the existing plug so that we can continue to manipulate it.
 */
int qdisc_enable_buffering(void)
{
    char dev[256];

    if(buffering_enabled)
	return -EINVAL;

    qemu_foreach_nic(init_mc_nic_buffering, dev);
    fprintf(stderr, "Initializing buffering for nic %s\n", dev);

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

    nl_cli_tc_parse_dev(tc, link_cache, (char *) dev);
    nl_cli_tc_parse_parent(tc, (char *) parent);

    if (!rtnl_tc_get_ifindex(tc)) {
        fprintf(stderr, "Qdisc device '%s' does not exist!\n", dev);
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
 
    if (qdisc_deliver(0) < 0) {
	fprintf(stderr, "First time qdisc create failed.\n");
	goto failed;
    }

    DPRINTF("Buffering enabled, size: %d MB.\n", buffer_size / 1024 / 1024);
   
    if(qdisc_set_buffer_size(buffer_size) < 0)
	goto failed;

    if(qdisc_suspend_buffering() < 0)
	goto failed;


    return 0;

failed:
    qdisc_disable_buffering();
    return -EINVAL;
}

int qdisc_suspend_buffering(void)
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

   return qdisc_deliver(1);
}

int qdisc_disable_buffering(void)
{
    int err;

    if(!buffering_enabled)
	goto out;

    qdisc_suspend_buffering();

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

int qdisc_start_buffer(void)
{
    int err;

    if(!buffering_enabled)
	return -EINVAL;

    if(new_buffer_size != buffer_size) {
	buffer_size = new_buffer_size;
        fprintf(stderr, "GDB setting new buffer size to %d\n", buffer_size);
	if (qdisc_set_buffer_size(buffer_size) < 0)
		return -EINVAL;
    }
 
    if ((err = rtnl_qdisc_plug_buffer((void *) qdisc)) < 0) {
        fprintf(stderr, "Unable to flush oldest checkpoint: %s\n", nl_geterror(err));
	return -EINVAL;
    }

    DPRINTF("Inserted checkpoint barrier\n");

    return qdisc_deliver(1);
}

int qdisc_flush_oldest_buffer(void)
{
    int err;

    if(!buffering_enabled)
	return -EINVAL;

    if ((err = rtnl_qdisc_plug_release_one((void *) qdisc)) < 0) {
        fprintf(stderr, "Unable to flush oldest checkpoint: %s\n", nl_geterror(err));
	return -EINVAL;
    }

    DPRINTF("Flushed oldest checkpoint barrier\n");

    return qdisc_deliver(1);
}
