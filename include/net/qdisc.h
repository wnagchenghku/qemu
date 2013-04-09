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

#ifndef QEMU_QDISC_H
#define QEMU_QDISC_H

int qdisc_enable_buffering(void);
int qdisc_disable_buffering(void);
int qdisc_suspend_buffering(void);
int qdisc_set_buffer_size(int size);
int qdisc_start_buffer(void);
int qdisc_flush_oldest_buffer(void);

#endif
