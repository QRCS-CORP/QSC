/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2020 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* Written by John G. Underhill
* Updated on November 11, 2020
* Contact: develop@vtdev.com */

#ifndef QSC_EVENT_H
#define QSC_EVENT_H

#include "common.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NAME_LENGTH 10

typedef enum qsc_event_list
{
	TEST1,
	TEST2,
	TEST3,
	MAX_EVENTS
} qsc_event_list;

typedef void (*qsc_event_callback)(void*);

QSC_EXPORT_API typedef struct qsc_event_handlers
{
	qsc_event_callback cb;
	struct EventHandlers *next;
} qsc_event_handlers;

qsc_event_handlers *listeners[MAX_EVENTS];

QSC_EXPORT_API int32_t qsc_event_register(qsc_event_list event, qsc_event_callback cb)
{
	qsc_event_handlers *handlers = listeners[event];

	if (handlers == NULL)
	{
		if (!(handlers = (qsc_event_handlers*)malloc(sizeof(qsc_event_handlers))))
		{
			return 0; // error returned from malloc
		}

		handlers->cb = cb;
		handlers->next = NULL;
		listeners[event] = handlers;
	}
	else
	{
		while (handlers->next != NULL) 
		{
			// handlers already registered for this event
			// check to see if it is a redundant handler for this event
			handlers = handlers->next;

			if (handlers->cb == cb)
			{
				return -1;
			}
		}

		qsc_event_handlers *nextHandler;

		if (!(nextHandler = (qsc_event_handlers*)malloc(sizeof(qsc_event_handlers))))
		{
			return 0; // error returned from malloc
		}

		nextHandler->cb = cb;
		nextHandler->next = NULL;
		handlers->next = nextHandler;
	}

	return 1;
}

QSC_EXPORT_API void qsc_event_init_listeners(qsc_event_handlers* handlers[], size_t size)
{
	size_t i;

	for (i = 0; i < MAX_EVENTS; i++)
	{
		handlers[i] = NULL;
	}
}

QSC_EXPORT_API void qsc_event_destroy_listeners(qsc_event_handlers* handlers[], int size)
{
	size_t i;
	qsc_event_handlers* deleteMe;
	qsc_event_handlers* next;

	for (i = 0; i < MAX_EVENTS; i++) 
	{
		deleteMe = handlers[i];

		while (deleteMe)
		{
			next = deleteMe->next;
			free(deleteMe);
			deleteMe = next;
		}
	}
}


/********************************************************************
	TEST EVENT HANDLERS FUNCTIONS
********************************************************************/

void Test1Handler1(void *data)
{
	printf("In Test1 Handler 1 %s\n", (char*)data);
}

void Test1Handler2(void *data)
{
	printf("In Test1 Handler 2 %s\n", (char*)data);
}

void Test1Handler3(void *data)
{
	printf("In Test1 Handler 3 %s\n", (char*)data);
}

void Test1Handler4(void *data)
{
	printf("In Test1 Handler 4 %s\n", (char*)data);
}

void Test2Handler1(void *data)
{
	printf("In Test2 Handler 1 %s\n", (char*)data);
}

void Test3Handler1(void *data)
{
	printf("In Test3 Handler 1 %s\n", (char*)data);
}

void Test3Handler2(void *data)
{
	printf("In Test3 Handler 2 %s\n", (char*)data);
}

/*********************************************************************
	MAIN ENTRY POINT
 ********************************************************************/

QSC_EXPORT_API int event_self_test()
{
	qsc_event_handlers *handlers = NULL;
	char data[] = "this is the data";

	qsc_event_init_listeners(listeners, MAX_EVENTS);

	if (qsc_event_register(TEST1, Test1Handler1) == -1)
		printf("duplicate test handler\n");
	if (qsc_event_register(TEST1, Test1Handler2) == -1)
		printf("duplicate test handler\n");
	if (qsc_event_register(TEST1, Test1Handler2) == -1)
		printf("duplicate test handler\n");
	if (qsc_event_register(TEST1, Test1Handler4) == -1)
		printf("duplicate test handler\n");
	if (qsc_event_register(TEST2, Test2Handler1) == -1)
		printf("duplicate test handler\n");
	if (qsc_event_register(TEST3, Test3Handler1) == -1)
		printf("duplicate test handler\n");
	if (qsc_event_register(TEST3, Test3Handler2) == -1)
		printf("duplicate test handler\n");

	handlers = listeners[TEST1];
	for (; handlers != NULL; handlers = handlers->next)
	{
		handlers->cb(data);
	}

	handlers = listeners[TEST2];
	for (; handlers != NULL; handlers = handlers->next)
	{
		handlers->cb(data);
	}

	handlers = listeners[TEST3];
	for (; handlers != NULL; handlers = handlers->next)
	{
		handlers->cb(data);
	}

	qsc_event_destroy_listeners(listeners, MAX_EVENTS);

	return 0;
}



//#if defined(QSC_SYSTEM_OS_WINDOWS)
//#	include <WinSock2.h>
//#	include <WS2tcpip.h>
//#	include <ws2def.h>
//#	include <objbase.h>
//#	include <inaddr.h>
//#	include <iphlpapi.h>
//#	pragma comment(lib, "ws2_32.lib")
//#elif defined(QSC_SYSTEM_OS_POSIX)
//#	include <ifaddrs.h>
//#	include <netinet/in.h> 
//#	include <arpa/inet.h>
//#	include <sys/socket.h>
//#	include <sys/types.h>
//#	include <unistd.h>
//#else
//#	error the operating system is unsupported! 
//#endif
//
//
//#ifndef EVENT__HAVE_FD_MASK
///* This type is mandatory, but Android doesn't define it. */
//typedef unsigned long fd_mask;
//#endif
//
//#ifndef NFDBITS
//#define NFDBITS (sizeof(fd_mask)*8)
//#endif
//
///* Divide positive x by y, rounding up. */
//#define DIV_ROUNDUP(x, y)   (((x)+((y)-1))/(y))
//
///* How many bytes to allocate for N fds? */
//#define SELECT_ALLOC_SIZE(n) \
//	(DIV_ROUNDUP(n, NFDBITS) * sizeof(fd_mask))
//
//struct selectop {
//	int event_fds;		/* Highest fd in fd set */
//	int event_fdsz;
//	int resize_out_sets;
//	fd_set *event_readset_in;
//	fd_set *event_writeset_in;
//	fd_set *event_readset_out;
//	fd_set *event_writeset_out;
//};
//
//const struct eventop selectops = {
//	"select",
//	select_init,
//	select_add,
//	select_del,
//	select_dispatch,
//	select_dealloc,
//	1, /* need_reinit. */
//	EV_FEATURE_FDS,
//	0,
//};
//
//static void
//check_selectop(struct selectop *sop)
//{
//	/* nothing to be done here */
//}
//#else
//#define check_selectop(sop) do { (void) sop; } while (0)
//#endif
//
//static int
//select_dispatch(struct event_base *base, struct timeval *tv)
//{
//	int res = 0, i, j, nfds;
//	struct selectop *sop = base->evbase;
//
//	check_selectop(sop);
//	if (sop->resize_out_sets) {
//		fd_set *readset_out = NULL, *writeset_out = NULL;
//		size_t sz = sop->event_fdsz;
//		if (!(readset_out = mm_realloc(sop->event_readset_out, sz)))
//			return (-1);
//		sop->event_readset_out = readset_out;
//		if (!(writeset_out = mm_realloc(sop->event_writeset_out, sz))) {
//			/* We don't free readset_out here, since it was
//			 * already successfully reallocated. The next time
//			 * we call select_dispatch, the realloc will be a
//			 * no-op. */
//			return (-1);
//		}
//		sop->event_writeset_out = writeset_out;
//		sop->resize_out_sets = 0;
//	}
//
//	memcpy(sop->event_readset_out, sop->event_readset_in,
//		sop->event_fdsz);
//	memcpy(sop->event_writeset_out, sop->event_writeset_in,
//		sop->event_fdsz);
//
//	nfds = sop->event_fds + 1;
//
//	EVBASE_RELEASE_LOCK(base, th_base_lock);
//
//	res = select(nfds, sop->event_readset_out,
//		sop->event_writeset_out, NULL, tv);
//
//	EVBASE_ACQUIRE_LOCK(base, th_base_lock);
//
//	check_selectop(sop);
//
//	if (res == -1) {
//		if (errno != EINTR) {
//			event_warn("select");
//			return (-1);
//		}
//
//		return (0);
//	}
//
//	event_debug(("%s: select reports %d", __func__, res));
//
//	check_selectop(sop);
//	i = evutil_weakrand_range_(&base->weakrand_seed, nfds);
//	for (j = 0; j < nfds; ++j) {
//		if (++i >= nfds)
//			i = 0;
//		res = 0;
//		if (FD_ISSET(i, sop->event_readset_out))
//			res |= EV_READ;
//		if (FD_ISSET(i, sop->event_writeset_out))
//			res |= EV_WRITE;
//
//		if (res == 0)
//			continue;
//
//		evmap_io_active_(base, i, res);
//	}
//	check_selectop(sop);
//
//	return (0);
//}
//
//static int
//select_resize(struct selectop *sop, int fdsz)
//{
//	fd_set *readset_in = NULL;
//	fd_set *writeset_in = NULL;
//
//	if (sop->event_readset_in)
//		check_selectop(sop);
//
//	if ((readset_in = mm_realloc(sop->event_readset_in, fdsz)) == NULL)
//		goto error;
//	sop->event_readset_in = readset_in;
//	if ((writeset_in = mm_realloc(sop->event_writeset_in, fdsz)) == NULL) {
//		/* Note that this will leave event_readset_in expanded.
//		 * That's okay; we wouldn't want to free it, since that would
//		 * change the semantics of select_resize from "expand the
//		 * readset_in and writeset_in, or return -1" to "expand the
//		 * *set_in members, or trash them and return -1."
//		 */
//		goto error;
//	}
//	sop->event_writeset_in = writeset_in;
//	sop->resize_out_sets = 1;
//
//	memset((char *)sop->event_readset_in + sop->event_fdsz, 0,
//		fdsz - sop->event_fdsz);
//	memset((char *)sop->event_writeset_in + sop->event_fdsz, 0,
//		fdsz - sop->event_fdsz);
//
//	sop->event_fdsz = fdsz;
//	check_selectop(sop);
//
//	return (0);
//
//error:
//	event_warn("malloc");
//	return (-1);
//}
//
//
//static int
//select_add(struct event_base *base, int fd, short old, short events, void *p)
//{
//	struct selectop *sop = base->evbase;
//	(void)p;
//
//	EVUTIL_ASSERT((events & EV_SIGNAL) == 0);
//	check_selectop(sop);
//	/*
//	 * Keep track of the highest fd, so that we can calculate the size
//	 * of the fd_sets for select(2)
//	 */
//	if (sop->event_fds < fd) {
//		int fdsz = sop->event_fdsz;
//
//		if (fdsz < (int)sizeof(fd_mask))
//			fdsz = (int)sizeof(fd_mask);
//
//		/* In theory we should worry about overflow here.  In
//		 * reality, though, the highest fd on a unixy system will
//		 * not overflow here. XXXX */
//		while (fdsz < (int)SELECT_ALLOC_SIZE(fd + 1))
//			fdsz *= 2;
//
//		if (fdsz != sop->event_fdsz) {
//			if (select_resize(sop, fdsz)) {
//				check_selectop(sop);
//				return (-1);
//			}
//		}
//
//		sop->event_fds = fd;
//	}
//
//	if (events & EV_READ)
//		FD_SET(fd, sop->event_readset_in);
//	if (events & EV_WRITE)
//		FD_SET(fd, sop->event_writeset_in);
//	check_selectop(sop);
//
//	return (0);
//}
//
///*
// * Nothing to be done here.
// */
//
//static int
//select_del(struct event_base *base, int fd, short old, short events, void *p)
//{
//	struct selectop *sop = base->evbase;
//	(void)p;
//
//	EVUTIL_ASSERT((events & EV_SIGNAL) == 0);
//	check_selectop(sop);
//
//	if (sop->event_fds < fd) {
//		check_selectop(sop);
//		return (0);
//	}
//
//	if (events & EV_READ)
//		FD_CLR(fd, sop->event_readset_in);
//
//	if (events & EV_WRITE)
//		FD_CLR(fd, sop->event_writeset_in);
//
//	check_selectop(sop);
//	return (0);
//}
//
//static void
//select_free_selectop(struct selectop *sop)
//{
//	if (sop->event_readset_in)
//		mm_free(sop->event_readset_in);
//	if (sop->event_writeset_in)
//		mm_free(sop->event_writeset_in);
//	if (sop->event_readset_out)
//		mm_free(sop->event_readset_out);
//	if (sop->event_writeset_out)
//		mm_free(sop->event_writeset_out);
//
//	memset(sop, 0, sizeof(struct selectop));
//	mm_free(sop);
//}
//
//static void
//select_dealloc(struct event_base *base)
//{
//	evsig_dealloc_(base);
//
//	select_free_selectop(base->evbase);
//}


#endif