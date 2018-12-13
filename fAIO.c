//-----------------------------------------------------------------------------------------------
//
// fmadio asyncronous file io (AIO) helpers 
// 
// Copyright fmad enginering inc 2018 all rights reserved 
//
// BSD License 
//
//-------------------------------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <linux/sched.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

#include "fTypes.h"
#include "fAIO.h"

//-----------------------------------------------------------------------------------------------

fAIO_t* fAIO_Open(int fd)
{
	fAIO_t* A = (fAIO_t*)malloc(sizeof(fAIO_t));
	assert(A != NULL);
	memset(A, 0, sizeof(fAIO_t));

	A->afd = eventfd(0);
	//printf("AFD: %08x\n", A->afd);

	// non blocking

	fcntl(A->afd, F_SETFL, fcntl(A->afd, F_GETFL, 0) | O_NONBLOCK);

	if (io_setup(4*1024, &A->ctx))
	{
		printf("io_setup failed");
		return NULL;
	}
	
	A->IOEventMax	= 128*1024;
	A->IOEvent		= malloc(A->IOEventMax * sizeof(io_event_t));
	assert(A->IOEvent != NULL);
	memset(A->IOEvent, 0, A->IOEventMax * sizeof(io_event_t));

	A->AIOOpMax		= 256;
	A->AIOOpList	= malloc(A->AIOOpMax * sizeof(fAIOOp_t));
	assert(A->AIOOpList != NULL);
	memset(A->AIOOpList, 0, A->AIOOpMax * sizeof(fAIOOp_t));

	A->AIOOpFree	= NULL; 
	for (int i=0; i < A->AIOOpMax; i++)
	{
		fAIOOp_t* O	= &A->AIOOpList[i];
		O->NextFree	= A->AIOOpFree;
		O->iocb.aio_data = (u64)O;

		A->AIOOpFree	= O;
	}

	A->IOCount		= 0;
	A->IOListMax	= 1024*1024;
	A->IOList		= (iocb_t**)malloc(sizeof(iocb_t*)*A->IOListMax);
	assert(A->IOList != NULL);
	memset(A->IOList, 0, sizeof(iocb_t*)*A->IOListMax);

	A->HistoBin		= 1e6;
	A->HistoMax		= 1e6;
	A->HistoRd		= (u32*)(malloc(A->HistoMax * sizeof(u32)));
	assert(A->HistoRd != NULL);
	memset(A->HistoRd, 0, A->HistoMax * sizeof(u32));

	A->HistoWr		= (u32*)(malloc(A->HistoMax * sizeof(u32)));
	assert(A->HistoWr != NULL);
	memset(A->HistoWr, 0, A->HistoMax * sizeof(u32));

	A->WriteFD			= fd;

	// allocate write buffer
	A->WritePos			= 0; 
	A->WriteMax			= kKB(256);
	A->WriteUnaligned	 	= malloc( A->WriteMax * 3);
	A->Write				= (u8*) ( ((u64)A->WriteUnaligned + 4095) & (~4095ULL) ); 

	// write queue
	A->WriteQueuePut	= 0;
	A->WriteQueueGet	= 0;
	A->WriteQueueMax	= 16;
	A->WriteQueueMsk	= A->WriteQueueMax - 1;
	for (int i=0; i < A->WriteQueueMax; i++)
	{
		A->WriteQueueBuffer[i] = memalign(4096, kKB(256));
		assert(A->WriteQueueBuffer[i] != NULL); 
	}

	return A;
}

//-----------------------------------------------------------------------------------------------

fAIOOp_t* fAIO_Queue(fAIO_t* A, int fd, u32 FileOp, void* Buffer, u64 Offset, u64 SectorSize)
{
	fAIOOp_t* Op			= A->AIOOpFree;
	assert(Op != NULL);

	A->AIOOpFree		= A->AIOOpFree->NextFree;
	assert(A->AIOOpFree != NULL);

	iocb_t* iocb		= &Op->iocb;
	memset(iocb, 0, sizeof(iocb_t));

	iocb->aio_fildes	= fd;
	iocb->aio_lio_opcode= FileOp; //IOCB_CMD_PWRITE;
	iocb->aio_reqprio	= 0;
	iocb->aio_buf		= (u_int64_t)Buffer;
	iocb->aio_nbytes	= SectorSize; 
	iocb->aio_offset	= Offset;
	iocb->aio_flags		= IOCB_FLAG_RESFD;
	iocb->aio_resfd		= A->afd;
	iocb->aio_data		= (u64)Op;

	A->IOList[A->IOCount++]	= iocb;
	A->IOPending++;

	Op->KickTS			= rdtsc();
	Op->Offset			= Offset;
	Op->Length			= SectorSize;

	Op->State			= AIO_OP_STATE_PENDING;
	Op->Buffer			= Buffer;
	Op->FileOp			= FileOp;

	return Op;
}

//-----------------------------------------------------------------------------------------------

int  fAIO_Kick(fAIO_t* A)
{
	int ret = io_submit(A->ctx, A->IOCount, A->IOList);
	A->IOCount = 0;

	if (ret < 0)
	{
		printf("io submit failed %i Pending:%i Errno:%i (%s)\n", ret, A->IOPending, errno, strerror(errno));
		return false;
	}
	return true;
}

//-----------------------------------------------------------------------------------------------

int fAIO_Flush(fAIO_t* A)
{
	// kick disk write 
	bool Done = false;
	for (int i=0; i < 1000; i++)
	{
		if (fAIO_Kick(A))
		{
			Done = true;
			break;
		}
		for (int j=0; j < 100; j++)
		{
			fAIO_Update(A);
			usleep(10);
		}
		printf("kick resend\n");
	}
	assert(Done == true);
}

//-----------------------------------------------------------------------------------------------
// checks system for async io`s that have completed
int fAIO_Update(fAIO_t* A)
{
	if (!A) return 0;

	u64 eval = 0;
	read(A->afd, &eval, sizeof(eval));

	if (eval > 0)
	{
		u64 TSC = rdtsc();
		struct timespec tmo;
		tmo.tv_sec = 0;
		tmo.tv_nsec = 0;

		int r = io_getevents(A->ctx, 0, 128, A->IOEvent, &tmo);
		for (int i=0; i < r; i++)
		{
			io_event_t* e = &A->IOEvent[i];

			// recycle
			fAIOOp_t* O	 = (fAIOOp_t*)e->data;

			iocb_t* iocb = (iocb_t*)e->obj;
			//printf("Complete %p, %016llx %08x %i %016llx : %i\n", O, O->Offset, O->State, O->FileOp, iocb->aio_offset, e->res);

			// mark as complete

			O->State		= AIO_OP_STATE_COMPLETE;

			// update histogram

			u64 dTS			= tsc2ns(TSC - O->KickTS);
			u32 Index		= dTS / A->HistoBin;
			Index			= (Index >= A->HistoMax) ? A->HistoMax - 1 : Index;
			switch (O->FileOp)
			{
			case IOCB_CMD_PWRITE: A->HistoWr[Index]++; break;
			case IOCB_CMD_PREAD : A->HistoRd[Index]++; break;
			}

			if (e->res != O->Length)
			{
				printf("error: %i %i : %i %i : %p : %016llx FileOp:%x fd:%i (%s)\n", e->res, O->Length, i, r, O, O->Offset, O->FileOp, iocb->aio_fildes, strerror(-e->res) );
				/*
				printf("%lli %lli %lli %lli\n", e->data, e->obj, e->res, e->res2);

				printf("Buffer: %p\n", O->Buffer);
				assert(false);
				*/
			}

			if (e->res < 0)
			{
				printf("aio %i event %016llx %016llx %016lli %016lli\n", i, e->data, e->obj, e->res, e->res2);
				printf("Offset: %016llx Lenght:%016llx\n", O->Offset, O->Length);
				//assert(false);
			}
			A->IOPending--;
		}
	}
	return 0;
}

//-----------------------------------------------------------------------------------------------
// checks if operation has finished yet
bool fAIO_IsOpComplete(fAIO_t* A, fAIOOp_t* Op)
{
	return Op->State == AIO_OP_STATE_COMPLETE;
}

//-----------------------------------------------------------------------------------------------

void fAIO_OpClose(fAIO_t* A, fAIOOp_t* Op)
{
	Op->NextFree	= A->AIOOpFree;
	A->AIOOpFree	= Op;

	Op->State		= AIO_OP_STATE_FREE;
}

//-----------------------------------------------------------------------------------------------

int fAIO_IsIdle(fAIO_t*A)
{
	return A->IOPending == 0;
}

//-----------------------------------------------------------------------------------------------

int fAIO_IsReady(fAIO_t*A)
{
	return A->AIOOpFree != NULL;
}

//-----------------------------------------------------------------------------------------------

int fAIO_NumPending(fAIO_t*A)
{
	if (!A) return 0;

	return A->IOPending;
}

//-----------------------------------------------------------------------------------------------
// write a blob of data
s32 fAIO_Write(fAIO_t* A, u8* Buffer, u32 Length)
{
	// theres space in the output queue
	// NOTE: need +2 as Write output gets written using the +1 WriteBuffer 
	if (((A->WriteQueuePut + 2) & A->WriteQueueMsk) == (A->WriteQueueGet & A->WriteQueueMsk))
	{
		return -1;	
	}

	// copy write buffer
	memcpy(A->Write + A->WritePos, Buffer, Length);
	A->WritePos += Length;

	// flush ?
	if (A->WritePos >= A->WriteMax)
	{
		u32 QueueIndex = A->WriteQueuePut & A->WriteQueueMsk;

		u8* WriteBuffer = A->WriteQueueBuffer[ QueueIndex ];
		assert(WriteBuffer != NULL);

		fAIOOp_t* Op = fAIO_Queue(A, A->WriteFD, IOCB_CMD_PWRITE, WriteBuffer, A->WriteOffset, kKB(256));	
		fAIO_Kick(A);

		A->WriteQueue[ QueueIndex ] = Op;
		A->WriteQueuePut++; 

		A->WriteOffset += kKB(256);

		s32 Remain = A->WritePos - kKB(256);
		if (Remain > 0)
		{
			assert(false);
		}

		// set next write buffer
		A->Write  	= A->WriteQueueBuffer[ A->WriteQueuePut & A->WriteQueueMsk ];
		A->WritePos = 0;			
	}
	return Length;
}

//-----------------------------------------------------------------------------------------------
void fAIO_WriteUpdate(fAIO_t* A)
{
	// nothing to do 
	if (A->WriteQueuePut == A->WriteQueueGet) return;

	fAIOOp_t* Op = A->WriteQueue[ A->WriteQueueGet & A->WriteQueueMsk ];

	// not completed
	if (Op->State != AIO_OP_STATE_COMPLETE) return;

	// release
	fAIO_OpClose(A, Op);

	// update queue
	A->WriteQueueGet++;
}

//-----------------------------------------------------------------------------------------------

void fAIO_WriteFlush(fAIO_t* A)
{
	// wait for all ops to complete 
	while (A->WriteQueueGet != A->WriteQueuePut)
	{
		fAIO_Update(A);

		// retire the next 
		if (A->WriteQueue[ A->WriteQueueGet & A->WriteQueueMsk ] != NULL)
		{
			fAIOOp_t* Op = A->WriteQueue[ A->WriteQueueGet & A->WriteQueueMsk ];
			if (fAIO_IsOpComplete(A, Op))
			{
				// free requestor
				fAIO_OpClose(A, Op);

				// advnace queue
				A->WriteQueue[ A->WriteQueueGet & A->WriteQueueMsk ] = NULL;
				A->WriteQueueGet++;
			}
		}
	}
}

//-----------------------------------------------------------------------------------------------

u64 fAIO_LatencyMax(fAIO_t*A)
{
	u32 LatencyMax = 0;
	for (int i=0; i < A->HistoMax; i++)
	{
		if (A->HistoWr[i] != 0)
		{
			LatencyMax = i * A->HistoBin;
		}
		if (A->HistoRd[i] != 0)
		{
			LatencyMax = i * A->HistoBin;
		}
	}
	return LatencyMax;
}

//-----------------------------------------------------------------------------------------------

u64 fAIO_LatencyMid(fAIO_t*A)
{
	u64 Total = 0;
	u32 SampleMax = 0;
	for (int i=0; i < A->HistoMax; i++)
	{
		Total += A->HistoWr[i];
		SampleMax = (SampleMax < A->HistoWr[i]) ? A->HistoWr[i] : SampleMax;
	}
	u64 Sum = 0;
	for (int i=0; i < A->HistoMax; i++)
	{
		if (A->HistoWr[i] == 0) continue;

		double Pct = A->HistoWr[i] / (double)SampleMax;
		if (Pct >= 0.50) return i * A->HistoBin;
	}
	return 0;
}

//-----------------------------------------------------------------------------------------------

void fAIO_DumpHisto(fAIO_t*A)
{
	u64 Total = 0;
	u32 SampleMax = 0;
	for (int i=0; i < A->HistoMax; i++)
	{
		Total += A->HistoWr[i];
		Total += A->HistoRd[i];
		SampleMax = (SampleMax < A->HistoWr[i]) ? A->HistoWr[i] : SampleMax;
		SampleMax = (SampleMax < A->HistoRd[i]) ? A->HistoRd[i] : SampleMax;
	}
	u64 Sum = 0;
	for (int i=0; i < A->HistoMax; i++)
	{
		if ((A->HistoWr[i] == 0) && (A->HistoRd[i] == 0)) continue;

		double PctWr = A->HistoWr[i] / (double)SampleMax;
		double PctRd = A->HistoRd[i] / (double)SampleMax;

		Sum += A->HistoWr[i];
		Sum += A->HistoRd[i];

		char Buffer[1024];
		sprintf(Buffer, "%12.6fms : %.6f %.6f : Wr:%8i :: ", i*A->HistoBin / 1e6, PctWr, Sum / (double)Total, A->HistoWr[i]);

		char Stars[1024];
		Stars[0] = 0;	
		for (int s =0; s < 100 * PctWr; s++) strcat(Stars, "w");
		printf("%s : %s\n", Buffer, Stars);

		sprintf(Buffer, "%12.6fms : %.6f %.6f : Rd:%8i :: ", i*A->HistoBin / 1e6, PctRd, Sum / (double)Total, A->HistoRd[i]);

		Stars[0] = 0;	
		for (int s =0; s < 100 * PctRd; s++) strcat(Stars, "r");
		printf("%s : %s\n", Buffer, Stars);
		//printf("\n");
	}
}

//-----------------------------------------------------------------------------------------------

void fAIO_HistoReset(fAIO_t*A)
{
	memset(A->HistoWr, 0, A->HistoMax * sizeof(u32) );
	memset(A->HistoRd, 0, A->HistoMax * sizeof(u32) );
}
