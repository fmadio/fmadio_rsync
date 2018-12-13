#ifndef __LINUX_AIO_H__
#define __LINUX_AIO_H__

// linux AIO helpers

#include <sys/syscall.h>
#include <poll.h>
#include <string.h>
#include <malloc.h>
#include <fcntl.h>

#define IOCB_FLAG_RESFD		(1 << 0)

enum
{
	IOCB_CMD_PREAD = 0,
	IOCB_CMD_PWRITE = 1,
	IOCB_CMD_FSYNC = 2,
	IOCB_CMD_FDSYNC = 3,
	// These two are experimental.
	// IOCB_CMD_PREADX = 4,
	// IOCB_CMD_POLL = 5,
	IOCB_CMD_NOOP = 6,
	IOCB_CMD_PREADV = 7,
	IOCB_CMD_PWRITEV = 8,
};

typedef unsigned long aio_context_t;

typedef struct iocb
{
	// these are internal to the kernel/libc. 

	u64	aio_data;	// data to be returned in event's data 
	u32	aio_key;
	u32	aio_reserved1;

	// the kernel sets aio_key to the req # 

	// common fields

	u16	aio_lio_opcode;	// see IOCB_CMD_ above 
	s16	aio_reqprio;
	u32	aio_fildes;

	u64	aio_buf;
	u64	aio_nbytes;
	s64	aio_offset;

	// extra parameters

	u64	aio_reserved2;	// TODO: use this for a (struct sigevent *)
	u32	aio_flags;

	// If different from 0, this is an eventfd to deliver AIO results to

	u32	aio_resfd;

} iocb_t;

typedef struct io_event
{
	u64		data;           /* the data field from the iocb */
	u64		obj;            /* what iocb this event came from */
	s64		res;            /* result code for this event */
	s64		res2;           /* secondary result */

} io_event_t;

#define AIO_OP_STATE_FREE			1
#define AIO_OP_STATE_PENDING		2
#define AIO_OP_STATE_COMPLETE		3

typedef struct fAIOOp_t
{
	iocb_t				iocb;
	struct fAIOOp_t*	NextFree;	
	u64					KickTS;
	u8					State;			
	u8					FileOp;

	u64					Offset;
	u64					Length;
	u8*					Buffer;

} fAIOOp_t;

typedef struct fAIO_t 
{
	int				afd;
	aio_context_t 	ctx;

	u32 			IOEventMax;
	io_event_t*		IOEvent;

	u32				AIOOpMax;
	fAIOOp_t* 		AIOOpList;

	fAIOOp_t* 		AIOOpFree;

	u32				IOCount;
	u32 			IOListMax;
	iocb_t**		IOList;

	u32				IOPending;

	u64				HistoBin;
	u32				HistoMax;
	u32*			HistoRd;
	u32*			HistoWr;


	// serialized write interface 
	int 			WriteFD;	
	u64				WriteOffset;

	// IO Write queue
	u32 			WriteQueuePut;
	u32 			WriteQueueGet;
	u32 			WriteQueueMsk;
	u32 			WriteQueueMax;
	fAIOOp_t* 		WriteQueue[128];
	u8*				WriteQueueBuffer[128];

	u32				WritePos;
	u32				WriteMax;
	u8*				WriteUnaligned;
	u8*				Write;

} fAIO_t;

static long io_setup(unsigned nr_reqs, aio_context_t *ctx) {
	return syscall(__NR_io_setup, nr_reqs, ctx);
}

static long io_destroy(aio_context_t ctx) {
	return syscall(__NR_io_destroy, ctx);
}

static long io_submit(aio_context_t ctx, long n, struct iocb **paiocb) {
	return syscall(__NR_io_submit, ctx, n, paiocb);
}

static long io_cancel(aio_context_t ctx, struct iocb *aiocb,
		      struct io_event *res) {
	return syscall(__NR_io_cancel, ctx, aiocb, res);
}

static long io_getevents(aio_context_t ctx, long min_nr, long nr,
			 struct io_event *events, struct timespec *tmo) {
	return syscall(__NR_io_getevents, ctx, min_nr, nr, events, tmo);
}

static int eventfd(int count) {
	return syscall(__NR_eventfd, count);
}

static void asyio_prep_preadv(struct iocb *iocb, int fd, struct iovec *iov,
			      int nr_segs, int64_t offset, int afd)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IOCB_CMD_PREADV;
	iocb->aio_reqprio = 0;
	iocb->aio_buf = (u_int64_t) iov;
	iocb->aio_nbytes = nr_segs;
	iocb->aio_offset = offset;
	iocb->aio_flags = IOCB_FLAG_RESFD;
	iocb->aio_resfd = afd;
}

static void asyio_prep_pwritev(struct iocb *iocb, int fd, struct iovec *iov,
			       int nr_segs, int64_t offset, int afd)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IOCB_CMD_PWRITEV;
	iocb->aio_reqprio = 0;
	iocb->aio_buf = (u_int64_t) iov;
	iocb->aio_nbytes = nr_segs;
	iocb->aio_offset = offset;
	iocb->aio_flags = IOCB_FLAG_RESFD;
	iocb->aio_resfd = afd;
}

static void asyio_prep_pread(struct iocb *iocb, int fd, void *buf,
			     int nr_segs, int64_t offset, int afd)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IOCB_CMD_PREAD;
	iocb->aio_reqprio = 0;
	iocb->aio_buf = (u_int64_t) buf;
	iocb->aio_nbytes = nr_segs;
	iocb->aio_offset = offset;
	iocb->aio_flags = IOCB_FLAG_RESFD;
	iocb->aio_resfd = afd;
}

static void asyio_prep_pwrite(struct iocb *iocb, int fd, void const *buf,
			      int nr_segs, int64_t offset, int afd)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->aio_fildes = fd;
	iocb->aio_lio_opcode = IOCB_CMD_PWRITE;
	iocb->aio_reqprio = 0;
	iocb->aio_buf = (u_int64_t) buf;
	iocb->aio_nbytes = nr_segs;
	iocb->aio_offset = offset;
	iocb->aio_flags = IOCB_FLAG_RESFD;
	iocb->aio_resfd = afd;
}

static long waitasync(int afd, int timeo)
{
	struct pollfd pfd;

	pfd.fd = afd;
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (poll(&pfd, 1, timeo) < 0) {
		perror("poll");
		return -1;
	}
	if ((pfd.revents & POLLIN) == 0) {
		fprintf(stderr, "no results completed\n");
		return 0;
	}

	return 1;
}

//-------------------------------------------------------------------------------

fAIO_t* 	fAIO_Open(int fd);
fAIOOp_t*	fAIO_Queue(fAIO_t* A, int fd, u32 FileOp, void* Buffer, u64 Offset, u64 SectorSize);
int  		fAIO_Kick(fAIO_t* A);
int 		fAIO_Update(fAIO_t* A);
int 		fAIO_Flush(fAIO_t*);
int 		fAIO_IsIdle(fAIO_t*A);
int 		fAIO_NumPending(fAIO_t*A);
void 		fAIO_DumpHisto(fAIO_t*A);
u64 		fAIO_LatencyMax(fAIO_t*A);
u64 		fAIO_LatencyMid(fAIO_t*A);
void 		fAIO_HistoReset(fAIO_t*A);

s32 		fAIO_Write(fAIO_t* A, u8* Buffer, u32 Length);
void 		fAIO_WriteUpdate(fAIO_t* a);
void 		fAIO_WriteFlush(fAIO_t* A);

void 		fAIO_OpClose(fAIO_t* A, fAIOOp_t* Op);
bool 		fAIO_IsOpComplete(fAIO_t* A, fAIOOp_t* Op);

#endif
