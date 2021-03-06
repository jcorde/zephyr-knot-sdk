//* proto.c - KNoT Application Client */

/*
 * Copyright (c) 2018, CESAR. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * The knot client application is acting as a client that is run in Zephyr OS,
 * The client sends sensor data encapsulated using KNoT protocol.
 */


#if (!defined(CONFIG_X86) && !defined(CONFIG_CPU_CORTEX_M4))
	#warning "Floating point services are currently available only for boards \
			based on the ARM Cortex-M4 or the Intel x86 architectures."
#endif

#include <zephyr.h>
#include <net/net_core.h>
#include <net/buf.h>
#include <logging/log.h>
#include <misc/reboot.h>

#include "knot.h"
#include "sm.h"
#include "proto.h"
#include "peripheral.h"
#include "clear.h"

LOG_MODULE_DECLARE(knot, CONFIG_KNOT_LOG_LEVEL);

static struct k_thread rx_thread_data;
static K_THREAD_STACK_DEFINE(rx_stack, 1024);
static struct k_pipe *proto2net;
static struct k_pipe *net2proto;

extern struct k_sem conn_sem;

/*
 * Handle connection and disconnection events. Return true if connected.
 */
static bool check_connection()
{
	static bool last_connected = false;
	bool connected;

	/* Semaphore available means connected */
	connected = (k_sem_count_get(&conn_sem) == 1);

	/* Finish if no state change */
	if (connected == last_connected)
		goto done;

	/* Control SM at transitions */
	if (connected)
		sm_start();
	else
		sm_stop();

	last_connected = connected;

done:
	return connected;
}

static void proto_thread(void)
{
	/* Considering KNOT Max MTU 128 */
	u8_t ipdu[128];
	u8_t opdu[128];
	size_t olen;
	size_t ilen;
	int ret;
	bool reset;

	/* Initializing KNoT peripherals control */
	peripheral_init();
	peripheral_set_status_period(STATUS_DISCONN_PERIOD);

	/* Initializing SM and abstract IO internals */
	sm_init();

	/* Calling KNoT app: setup() */
	setup();

	while (1) {
		/* Calling KNoT app: loop() */
		loop();

		/* Ignore net and SM if disconnected */
		if (check_connection() == false) {
			peripheral_set_status_period(STATUS_DISCONN_PERIOD);
			goto done;
		}

		ilen = 0;
		memset(&ipdu, 0, sizeof(ipdu));
		/* Reading data from NET thread */
		ret = k_pipe_get(net2proto, ipdu, sizeof(ipdu),
				 &ilen, 0U, K_NO_WAIT);

		olen = sm_run(ipdu, ilen, opdu, sizeof(opdu));

		/* Sending data to NET thread */
		if (olen != 0)
			k_pipe_put(proto2net, opdu, olen,
				   &olen, olen, K_NO_WAIT);

done:
		peripheral_flag_status();

		/* Handle reset flag */
		reset = peripheral_get_reset();
		if (reset) {
			/* TODO: Unregister before reseting */
			LOG_INF("Reseting system...");
			#if !CONFIG_BOARD_QEMU_X86
			clear_factory();
				sys_reboot(SYS_REBOOT_WARM);
			#endif
		}

		k_yield();
	}

	sm_stop();
}

int proto_start(struct k_pipe *p2n, struct k_pipe *n2p)
{
	LOG_DBG("PROTO: Start");

	proto2net = p2n;
	net2proto = n2p;
	k_thread_create(&rx_thread_data, rx_stack,
			K_THREAD_STACK_SIZEOF(rx_stack),
			(k_thread_entry_t) proto_thread,
			NULL, NULL, NULL, K_PRIO_PREEMPT(15),
			K_FP_REGS, K_NO_WAIT);

	return 0;
}

void proto_stop(void)
{
	LOG_DBG("PROTO: Stop");
}
