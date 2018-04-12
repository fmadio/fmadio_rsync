//*****************************************************************************************
//**
//** fmadio high speed rsync 
//**
//** Copyright fmad enginering inc 2018 all rights reserved 
//**
//** BSD License 
//**
//*****************************************************************************************

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "fTypes.h"

#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>


//-------------------------------------------------------------------------------------------

typedef struct
{
	u32                 SeqNo;              // chunk seq no
	u32                 XferLength;         // byte length of transfer size
	u32                 DataLength;         // raw unpacked data length
	u32                 CRC32;              // chunks crc32

} __attribute__((packed)) PacketHeader_t;

// standard PCAP header 

#define PCAPHEADER_MAGIC_NANO       0xa1b23c4d
#define PCAPHEADER_MAGIC_USEC       0xa1b2c3d4
#define PCAPHEADER_MAJOR            2
#define PCAPHEADER_MINOR            4
#define PCAPHEADER_LINK_ETHERNET    1

typedef struct
{

	u32             Magic;
	u16             Major;
	u16             Minor;
	u32             TimeZone;
	u32             SigFlag;
	u32             SnapLen;
	u32             Link;

} __attribute__((packed)) PCAPHeader_t;


typedef struct Chunk_t
{

	u32					SeqNo;
	u32					Bytes;						// number of bytes in this chunk

	u32					SliceTotal;					// total number of slices
	u32					SliceCnt;					// total number of recevied slices
	u8					SliceList[64];				// list of recv slice ids 

	PacketHeader_t		Header;						// header info from sender
	u8					Data[256*1024];				// up to 256KB for full chunk

	struct Chunk_t*		NextFree;					// next free chunk 
	struct Chunk_t*		NextAck;					// chunk has been complete send ack 

} Chunk_t;

typedef struct Queue_t
{
	volatile u64		Put;
	u8					pad0[4096 - 8];

	volatile u64		Get;
	u8					pad1[4096 - 8];

	u32					Mask;
	Chunk_t*			Entry[4*1024];

} Queue_t;

typedef struct
{
	u32					CPUID;						// CPU which this is binded to 

	int					Sock;					// socket for acks
	struct sockaddr_in	BindAddr;					// bind address for acks

	u8*					Buffer;						// receive buffer	
	u32					BufferMax;					// max size of buffer

	u64					TotalByte;					// total number of bytes recveid
	u64					TotalChunk;					// total number of chunks

	u32					LastSeqNo;					// last recevied seqno 

	Queue_t				Queue;						// per worker queue 

} Network_t;

//-------------------------------------------------------------------------------------------

double TSC2Nano;
volatile u32 g_Exit = false;

static volatile u32			s_ChunkFreeLock[128/4];		// use a full 128B cache line to avoid contention
static volatile Chunk_t*	s_ChunkFree	= NULL;			// free chunk list

//-------------------------------------------------------------------------------------------
// light weight mutexs
static inline void Lock(u32* Lock)
{
	while (__sync_bool_compare_and_swap(Lock, 0, 1) == false)
	{
		// put cpu into low prioity for 100nsec
		ndelay(100);
	}
}
static inline void Unlock(u32* Lock)
{
	if (__sync_bool_compare_and_swap(Lock, 1, 0) == false)
	{
		fprintf(stderr, "Unlock failed\n");
	}
}

Chunk_t* ChunkAlloc(void)
{
	// get lock
	Lock(&s_ChunkFreeLock[0]);

	Chunk_t* C = (volatile Chunk_t*)s_ChunkFree;
	if (C != NULL)
	{
		s_ChunkFree = C->NextFree;

		// reset
		C->SeqNo = 0;	
	}

	// release lock
	Unlock(&s_ChunkFreeLock[0]);

	return C;
}

void ChunkFree(Chunk_t* C)
{
	// get lock
	Lock(&s_ChunkFreeLock[0]);

	C->NextFree = (Chunk_t*)s_ChunkFree;
	s_ChunkFree = C;

	// release lock
	Unlock(&s_ChunkFreeLock[0]);
}

//-------------------------------------------------------------------------------------------

static Network_t* NetworkOpen(u32 CPUID, u32 PortBase)
{
	Network_t* N = memalign2(4*1024,  sizeof(Network_t)); 
	memset(N, 0, sizeof(Network_t));

	N->CPUID		= CPUID;

	N->Sock = socket(AF_INET, SOCK_STREAM, 0);
	assert(N->Sock > 0);
	
	// listen address 
	memset((char *) &N->BindAddr, 0, sizeof(N->BindAddr));

	N->BindAddr.sin_family 		= AF_INET;
	N->BindAddr.sin_port 		= htons(PortBase + CPUID);
	N->BindAddr.sin_addr.s_addr = inet_addr("192.168.15.40");

	//bind socket to port
	int ret = connect(N->Sock, (struct sockaddr*)&N->BindAddr, sizeof(N->BindAddr));
	if (ret < 0)
	{
		fprintf(stderr, "connect failed: %i %i : %s\n", ret, errno, strerror(errno)); 
		return 0;
	}

	// set massive recvie buffer to minimize packet drops
	int size = kMB(256);
	ret = setsockopt(N->Sock, SOL_SOCKET, SO_RCVBUF, (char *)&size, sizeof(size));  
	if (ret < 0)
	{
		fprintf(stderr, "failed to set recv buffer size: %i %s\n", ret, strerror(errno));
	}

	// packet recv buffer
	N->Buffer 		= memalign2(128, 256*1024);
	N->BufferMax 	= 256*1024;


	// reset queue
	N->Queue.Put	= 0;
	N->Queue.Get	= 0;
	N->Queue.Mask	= 1024 - 1;

	return N;
}

//-------------------------------------------------------------------------------------------

void* RxThread(void* _User)
{
	Network_t* N = (Network_t*)_User;
	printf("[%i] RxThread starting\n", N->CPUID);

	// receive at maximum rate per thread 
	bool Exit = false;
	while (!Exit)
	{
		// dont have too many outstanding entries
		// Put/Get are 64b and reset for each download
		// its impossible to for this to wrap around 
		if (N->Queue.Put  - N->Queue.Get >= 192) 
		{
			usleep(0);
			continue;
		}

		Chunk_t* C = ChunkAlloc();
		if (C == NULL)
		{
			// no chunks free
			usleep(0);
			continue;
		}

		// get the packet header first
		s32 HeaderLength 	= sizeof(PacketHeader_t);
		u8* Header8			= (u8*)&C->Header;
		while (HeaderLength > 0)
		{
			int rlen = recv(N->Sock, Header8, HeaderLength, 0);
			if (rlen > 0)
			{
				HeaderLength 	-= rlen;
				Header8 		+= rlen;
			}
			if ((rlen < 0) && (errno != EAGAIN))
			{
				fprintf(stderr, "recv failed %s\n", strerror(errno));
				Exit = true;
				break;
			}
		}

		//printf("[%i] SeqNo: %i XferLen:%i %08x\n", PortNo, Header.SeqNo, Header.XferLength, Header.CRC32);
		assert(C->Header.SeqNo != 0);
		C->SeqNo = C->Header.SeqNo;

		s32 BufferLength= C->Header.XferLength;
		u8* Buffer8		= (u8*)C->Data;
		while (BufferLength > 0)
		{
			int rlen = recv(N->Sock, Buffer8, BufferLength, 0);
			if (rlen <= 0)
			{
				if (errno != EAGAIN)
				{
					fprintf(stderr, "Worker: %i  Error %i %i %s\n", N->CPUID, rlen, errno, strerror(errno));
					Exit = true;
					break;
				}
			}
			else
			{
				// iterate thought the raw buffer 
				N->TotalByte 	+= rlen;

				BufferLength	-= rlen;
				Buffer8			+= rlen;	
			}
		}

		N->TotalChunk++;
		N->LastSeqNo	= C->Header.SeqNo;

		// push onto serialization queue
		u32 Index = (N->Queue.Put & N->Queue.Mask); 

		N->Queue.Entry[Index] = C;

		// kick it
		sfence();
		N->Queue.Put++;
	}

	g_Exit = true;

	return NULL;
}

//-------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	fprintf(stderr, "fmadio rsync: %s\n", __DATE__);

	u8* CaptureName = NULL;	
	for (int i=0; i < argc; i++)
	{
		// set the download capture name
		if (argv[i][0] != '-')
		{
			CaptureName = argv[i];
		}
	}

	CycleCalibration();

	// init network connections	
	Network_t* N[4];
	N[0] = NetworkOpen(0, 10000);
	N[1] = NetworkOpen(1, 10000);
	N[2] = NetworkOpen(2, 10000);
	N[3] = NetworkOpen(3, 10000);

	// init the locks
	s_ChunkFreeLock[0] = 1;
	Unlock(&s_ChunkFreeLock[0]);


	// write pcap header
	PCAPHeader_t	PCAPHeader;
	PCAPHeader.Magic	= PCAPHEADER_MAGIC_NANO;
	PCAPHeader.Major	= PCAPHEADER_MAJOR;
	PCAPHeader.Minor	= PCAPHEADER_MINOR;
	PCAPHeader.TimeZone	= 0; 
	PCAPHeader.SigFlag	= 0; 
	PCAPHeader.SnapLen	= 0; 
	PCAPHeader.Link		= PCAPHEADER_LINK_ETHERNET;
	fwrite(&PCAPHeader, 1, sizeof(PCAPHeader), stdout);

	// allocate chunks
	for (int i=0; i < 1024; i++)
	{
		Chunk_t* C = (Chunk_t*)memalign2(128, sizeof(Chunk_t));
		ChunkFree(C);
	}

	// spin up the worker threads 
	pthread_t   RxThread0;
	pthread_t   RxThread1;
	pthread_t   RxThread2;
	pthread_t   RxThread3;
	pthread_t   RxThread4;
	pthread_t   RxThread5;

	pthread_create(&RxThread0, NULL, RxThread, (void*)N[0]);
	pthread_create(&RxThread1, NULL, RxThread, (void*)N[1]);
	pthread_create(&RxThread2, NULL, RxThread, (void*)N[2]);
	pthread_create(&RxThread3, NULL, RxThread, (void*)N[3]);

	cpu_set_t RxThread0CPU;
	CPU_ZERO(&RxThread0CPU);
	CPU_SET (20, &RxThread0CPU);
	pthread_setaffinity_np(RxThread0, sizeof(cpu_set_t), &RxThread0CPU);

	cpu_set_t RxThread1CPU;
	CPU_ZERO(&RxThread1CPU);
	CPU_SET (21, &RxThread1CPU);
	pthread_setaffinity_np(RxThread1, sizeof(cpu_set_t), &RxThread1CPU);

	cpu_set_t RxThread2CPU;
	CPU_ZERO(&RxThread2CPU);
	CPU_SET (22, &RxThread2CPU);
	pthread_setaffinity_np(RxThread2, sizeof(cpu_set_t), &RxThread2CPU);

	cpu_set_t RxThread3CPU;
	CPU_ZERO(&RxThread3CPU);
	CPU_SET (23, &RxThread3CPU);
	pthread_setaffinity_np(RxThread3, sizeof(cpu_set_t), &RxThread3CPU);

	u64 NextPrintTSC = 0;

	u32 SeqNo 		= 1;			// SeqNo 0 is reserved
	u64 TotalByte 	= 0;

	u64 LastByte 	= 0;
	u64 LastTSC  	= 0;

	while (!g_Exit)
	{
		// find next seq no 
		for (int c=0; c < 4; c++)
		{
			Queue_t* Q = &N[c]->Queue;

			// nothing to process 
			if (Q->Put == Q->Get) continue;

			// check each queue for the next seq no
			u32 Index 	= Q->Get & Q->Mask;
			Chunk_t* C 	= Q->Entry[Index];
			if (C->SeqNo == SeqNo)
			{
				TotalByte += C->Header.DataLength;

				// next seq no to expect
				SeqNo 		= C->SeqNo + 1;

				// write sequential data to disk 
				fwrite(C->Data, 1, C->Header.DataLength, stdout);

				// recycle the chunk
				ChunkFree(C);
				Q->Get++;
			}
		}

		// print some stats
		u64 TSC = rdtsc();
		if (TSC > NextPrintTSC)
		{
			NextPrintTSC = TSC + ns2tsc(1e9);	

			double dByte = TotalByte - LastByte;
			double dT = tsc2ns(TSC - LastTSC) / 1e9;
			double bps = dByte * 8.0 / dT;

			fprintf(stderr, "Recved %8.3f GB %8.3f Gbps Queue (%3i) (%3i) (%3i) (%3i)\n", 
					TotalByte / 1e9, 
					bps / 1e9,

					(u32)(N[0]->Queue.Put - N[0]->Queue.Get),
					(u32)(N[1]->Queue.Put - N[1]->Queue.Get),
					(u32)(N[2]->Queue.Put - N[2]->Queue.Get),
					(u32)(N[3]->Queue.Put - N[3]->Queue.Get)
			); 

			LastByte 	= TotalByte;
			LastTSC		= TSC;
		}
	}

	pthread_join(RxThread0, NULL);
	pthread_join(RxThread1, NULL);
	pthread_join(RxThread2, NULL);
	pthread_join(RxThread3, NULL);
}
