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
#include <sys/mman.h>
#include <linux/sched.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "fAIO.h"

//-------------------------------------------------------------------------------------------

// packet header from the capture system
#define PACKETHEADER_FLAG_EOF			(1<<0)	// end of capture
typedef struct
{
	u32                 SeqNo;              // chunk seq no
	u32                 XferLength;         // byte length of transfer size
	u32                 DataLength;         // raw unpacked data length
	u8                 	Flag;           	// flags for the chunk 
	u8					pad[3];

} __attribute__((packed)) PktHeader_t;

// commands to/from the capture system
#define CMDHEADER_CMD_LIST          1       // list all the captures
#define CMDHEADER_CMD_GET           2       // get a capture
#define CMDHEADER_CMD_END          100 		// end of communications 
#define CMDHEADER_CMD_OK           101 		// sucess 
#define CMDHEADER_CMD_NG           102 		// failed 

#define CMDHEADER_VERSION_1_0		0x10	// first release

typedef struct
{
	u8					Version;			// cmd header version
	u32                 Cmd;                // command to issue
	u8                  StreamName[1024];	// stream info 
	u64					StreamSize;

	u32					Arg[1024];			// various arguments

	u8                  FilterBPF[1024];    // run BPF filter
	u8                  FilterRE[1024];     // run RegEx filter

} __attribute__((packed)) CmdHeader_t;


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

typedef struct PCAPPacket_t
{
	u32             Sec;                    // time stamp sec since epoch
	u32             NSec;                   // nsec fraction since epoch

	u32             LengthCapture;			// captured length
	u32             LengthWire;				// Length on the wire 

} __attribute__((packed)) PCAPPacket_t;


// internal format thats on the tcp connection
// contains some extra metadata
typedef struct FMADPacket_t
{
	u64             TS;                     // 64bit nanosecond epoch 

	u32             LengthCapture	: 16;	// length captured 
	u32             LengthWire		: 16;   // Length on the wire 

	u32             PortNo			:  8;   // Port number 
	u32             pad1			:  8;   // flags 
	u32             pad0			: 16; 

} __attribute__((packed)) FMADPacket_t;


typedef struct Chunk_t
{

	u32					SeqNo;
	u32					Bytes;						// number of bytes in this chunk
	u64					PktCnt;						// number of packets in this chunk	

	u32					SliceTotal;					// total number of slices
	u32					SliceCnt;					// total number of recevied slices
	u8					SliceList[64];				// list of recv slice ids 

	PktHeader_t			Header;						// header info from sender
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

static volatile u32			s_EOFSeqNo = 0;				// indicates SeqNo for EOF

u32							g_Quiet = false;			// quiet mode 

static bool					s_OutputAIO		= false;	// output via AIO
static bool					s_OutputStdout 	= true;		// output on stdout
static u8					s_OutputFileName[256];		// where to write the file
static int					s_OutputFD;					// output file descriptor
static fAIO_t*				s_OutputAIOFD	= NULL;		// output AIO instance	

static u8					s_OutputFileName[256];		// output file name 
static u32					s_OutputBufferMax = 0;		// max bytes in output buffer 
static u32					s_OutputBufferPos = 0;		// current bytes in output buffer 
static u8*					s_OutputBuffer 		= NULL;	// 1MB output buffer

static u64					s_WorkerCPUTop[16];			// total cycles in worker threads
static u64					s_WorkerCPUIO[16];			// total cycles in recv() tcp  
static u64					s_WorkerCPUParse[16];		// total cycles in parsing the data 
static u64					s_WorkerCPUStall[16];		// total cycles worker is stalled 

//-------------------------------------------------------------------------------------------
// light weight mutexs
static inline void Lock(volatile u32* Lock)
{
	while (__sync_bool_compare_and_swap(Lock, 0, 1) == false)
	{
		// put cpu into low prioity for 100nsec
		ndelay(100);
	}
}
static inline void Unlock(volatile u32* Lock)
{
	// required to ensure correct memory ordering 
	// of lock/unlock. a normal write should be sufficent 
	// however the ordering of that write seems very relaxed..
	if (__sync_bool_compare_and_swap(Lock, 1, 0) == false)
	{
		fprintf(stderr, "Unlock failed\n");
	}
}

Chunk_t* ChunkAlloc(void)
{
	// get lock
	Lock(&s_ChunkFreeLock[0]);

	volatile Chunk_t* C = (volatile Chunk_t*)s_ChunkFree;
	if (C != NULL)
	{
		s_ChunkFree = C->NextFree;

		// reset
		C->SeqNo = 0;	
	}

	// release lock
	Unlock(&s_ChunkFreeLock[0]);

	return (Chunk_t*)C;
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

static Network_t* NetworkOpen(u32 CPUID, u32 PortBase, u8* IPAddress)
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
	N->BindAddr.sin_addr.s_addr = inet_addr(IPAddress);

	// retry connection a few times 
	int ret = -1;
	for (int r=0; r < 10; r++)
	{
		//bind socket to port
		ret = connect(N->Sock, (struct sockaddr*)&N->BindAddr, sizeof(N->BindAddr));
		if (ret >= 0) break;

		// connection timed out
		usleep(100e3);
	}
	if (ret < 0)
	{
		fprintf(stderr, "connect failed: %i %i : %s : %s:%i\n", ret, errno, strerror(errno), IPAddress, PortBase + CPUID); 
		return NULL;
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

static bool RecvSock(int Sock, u8* Buffer8, s32 BufferLength)
{
	while (BufferLength > 0)
	{
		int rlen = recv(Sock, Buffer8, BufferLength, 0);
		if (rlen <= 0)
		{
			if (errno != EAGAIN)
			{
				fprintf(stderr, "RecvSock Error %i %i %s\n", rlen, errno, strerror(errno));
				return false;	
			}
		}
		else
		{
			// iterate thought the raw buffer 
			BufferLength	-= rlen;
			Buffer8			+= rlen;	
		}
	}
	return true;
}

//-------------------------------------------------------------------------------------------
// process a single TCP condition and push the result on the output queu
void* RxThread(void* _User)
{
	Network_t* N = (Network_t*)_User;
	if (!g_Quiet) fprintf(stderr, "[%i] RxThread starting\n", N->CPUID);

	// receive at maximum rate per thread 
	bool Exit = false;
	while (!Exit)
	{
		// global exit
		if (g_Exit) break;

		u64 TSC0 = rdtsc();

		// dont have too many outstanding entries
		// Put/Get are 64b and reset for each download
		// its impossible to for this to wrap around 
		if (N->Queue.Put  - N->Queue.Get >= 192) 
		{
			usleep(0);

			s_WorkerCPUStall[N->CPUID] 	+= rdtsc() - TSC0;
			s_WorkerCPUTop[N->CPUID] 	+= rdtsc() - TSC0;
			continue;
		}

		Chunk_t* C = ChunkAlloc();
		if (C == NULL)
		{
			// no chunks free
			usleep(0);
			s_WorkerCPUStall[N->CPUID] 	+= rdtsc() - TSC0;
			s_WorkerCPUTop[N->CPUID] 	+= rdtsc() - TSC0;
			continue;
		}

		// get the packet header first
		s32 HeaderLength 	= sizeof(PktHeader_t);
		u8* Header8			= (u8*)&C->Header;
		if(!RecvSock(N->Sock, Header8, HeaderLength))
		{
			Exit = true;
			fprintf(stderr, "recv failed %s\n", strerror(errno));
			break;
		}

		// check for End of File marker
		if (C->Header.Flag & PACKETHEADER_FLAG_EOF)
		{
			if (!g_Quiet) fprintf(stderr, "EOF Reached SeqNo: %i\n", C->Header.SeqNo);
			if (C->Header.SeqNo != 0)
			{
				s_EOFSeqNo		= C->Header.SeqNo;
			}
			break;
		}

		//printf("[%i] SeqNo: %i XferLen:%i %08x\n", PortNo, Header.SeqNo, Header.XferLength, Header.CRC32);
		assert(C->Header.SeqNo != 0);
		C->SeqNo = C->Header.SeqNo;

		// get the data payload
		s32 BufferLength= C->Header.XferLength;
		u8* Buffer8		= (u8*)C->Data;
		if(!RecvSock(N->Sock, Buffer8, BufferLength))
		{
			Exit = true;
			fprintf(stderr, "recv data failed %s\n", strerror(errno));
			break;
		}
		u64 TSC1 = rdtsc();
		s_WorkerCPUIO[N->CPUID] += TSC1 - TSC0;

		// stats 
		N->TotalByte 	+= BufferLength;

		// packet count
		u64 PktCnt 		= 0; 

		// filter out and translate to PCAP format 
		u8* Data8 = (u8*)C->Data;	
		u8* Data8End = Data8 + C->Header.DataLength; 
		while (Data8 < Data8End)
		{
			FMADPacket_t* FPkt 	= (FMADPacket_t*)Data8;
			PCAPPacket_t* PPkt 	= (PCAPPacket_t*)FPkt;

			// convert from fmad packet to pcap packet
			u64 TS				= FPkt->TS;
			u32 LengthCapture 	= FPkt->LengthCapture;
			u32 LengthWire 		= FPkt->LengthWire;

			u32 PortNo			= FPkt->PortNo;

			//
			// *** here is where any custom filter logic goes ***
			//

			// overwrite
			PPkt->Sec			= TS / 1e9;
			PPkt->NSec			= TS - (u64)PPkt->Sec * 1000000000ULL;		// carefull keep full 64bit precision..
			PPkt->LengthCapture	= LengthCapture;
			PPkt->LengthWire	= LengthWire;

			Data8 += sizeof(PCAPPacket_t) + PPkt->LengthCapture;
			PktCnt += 1;
		}

		N->TotalChunk++;
		N->LastSeqNo	= C->Header.SeqNo;

		// update packet count
		C->PktCnt = PktCnt;

		// push onto serialization queue
		u32 Index = (N->Queue.Put & N->Queue.Mask); 

		N->Queue.Entry[Index] = C;

		// kick it
		sfence();
		N->Queue.Put++;

		s_WorkerCPUParse[N->CPUID] += rdtsc() - TSC1;
		s_WorkerCPUTop	[N->CPUID] += rdtsc() - TSC0;
	}

	if (!g_Quiet) fprintf(stderr, "[%i] RxThread exit\n", N->CPUID);

	return NULL;
}

//-------------------------------------------------------------------------------------------
// open file for output 
static void DataOpen(u8* FileName) 
{
	strncpy(s_OutputFileName, FileName, sizeof(s_OutputFileName));	

	s_OutputAIO 	= true;
	s_OutputStdout 	= false;

	s_OutputFD = open(s_OutputFileName, O_WRONLY| O_DIRECT | O_CREAT | O_TRUNC, S_IWUSR | S_IRUSR); 
	if (s_OutputFD < 0)
	{
		fprintf(stderr, "failed to create file [%s] %i %s\n", FileName, errno, strerror(errno));
		exit(-1);	
	}

	s_OutputAIOFD = fAIO_Open(s_OutputFD);
	assert(s_OutputAIOFD != NULL);

	// allocate output buffer
	s_OutputBufferPos	= 0;
	s_OutputBufferMax	= kMB(1);
	s_OutputBuffer		= memalign(4096, s_OutputBufferMax);
	assert(s_OutputBuffer != NULL);
}

//-------------------------------------------------------------------------------------------
// write data out
static void DataWrite(u8* Data, u32 Length)
{
	if (s_OutputStdout)
	{
		int wlen = fwrite(Data, 1, Length, stdout);
		if (wlen != Length)
		{
			fprintf(stderr, "ERROR: write to output failed wlen:%i errno:%i (%s)\n", wlen, errno, strerror(errno) );
			g_Exit = true;
		}
	}

	if (s_OutputAIO)
	{
		// update internal AIO state	
		fAIO_Update(s_OutputAIOFD);
		fAIO_WriteUpdate(s_OutputAIOFD);

		// buffer full
		if (s_OutputBufferPos + Length > s_OutputBufferMax)
		{
			u32 BLength 	= s_OutputBufferMax- s_OutputBufferPos;
			memcpy(s_OutputBuffer + s_OutputBufferPos, Data, BLength);

			//int rlen = write(s_OutputFD, Out->Buffer, Out->BufferMax);

			// write block
			fAIO_Write(s_OutputAIOFD, s_OutputBuffer + 0 * kKB(256), kKB(256) );
			fAIO_Write(s_OutputAIOFD, s_OutputBuffer + 1 * kKB(256), kKB(256) );
			fAIO_Write(s_OutputAIOFD, s_OutputBuffer + 2 * kKB(256), kKB(256) );
			fAIO_Write(s_OutputAIOFD, s_OutputBuffer + 3 * kKB(256), kKB(256) );

			s_OutputBufferPos 	= 0;

			// write remaining into next block
			memcpy(s_OutputBuffer + s_OutputBufferPos, Data + BLength, Length - BLength);

			s_OutputBufferPos += Length - BLength;
		}
		// append to current buffer
		else
		{
			memcpy(s_OutputBuffer + s_OutputBufferPos, Data, Length);
			s_OutputBufferPos += Length;
		}

		/*
		// write block fd only
		int rlen = write(s_OutputFD, Data, Length);
		if (rlen != Length)
		{
			fprintf(stderr, "failed to write data: %i %s : length %i\n", errno, strerror(errno), Length);
		}
		*/
	}
}

//-------------------------------------------------------------------------------------------
// flush any remaining data 
static void DataClose(void)
{
	if (s_OutputStdout)
	{
		fflush(stdout);
	}
	if (s_OutputAIO)
	{
		// wait for all writes to complete 
		fAIO_WriteFlush(s_OutputAIOFD);

		// shutdown AIO and file handle
		close(s_OutputFD);

		// need re-open for non POW2 aligned writes
		s_OutputFD = open(s_OutputFileName, O_WRONLY | O_APPEND, S_IWUSR | S_IRUSR); 

		// write remainder using normal IO
		int wlen = write(s_OutputFD, s_OutputBuffer, s_OutputBufferPos);
		if (wlen <= 0)
		{
			fprintf(stderr, "trailing write error %i %s\n", errno, strerror(errno));
		}
		close(s_OutputFD);
	}
}

//-------------------------------------------------------------------------------------------
// master control thread that takes blocks recevied by each thread and
// re-assemables them in order 
static void GetStreamData(u8* IPAddress)
{
	u64 TSStart = clock_ns();

	// init network connections	
	Network_t* N[4];
	N[0] = NetworkOpen(0, 10010, IPAddress);
	N[1] = NetworkOpen(1, 10010, IPAddress);
	N[2] = NetworkOpen(2, 10010, IPAddress);
	N[3] = NetworkOpen(3, 10010, IPAddress);

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
	PCAPHeader.SnapLen	= 65535; 
	PCAPHeader.Link		= PCAPHEADER_LINK_ETHERNET;
	DataWrite((u8*)&PCAPHeader, sizeof(PCAPHeader));

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
	u64 TotalPkt	= 0;

	u64 LastByte 	= 0;
	u64 LastTSC  	= 0;

	u64 LastDataTSC = rdtsc();			// last time data was processed

	u64 CycleTotalTop 	= 0;
	u64 CycleTotalIO  	= 0;

	while (!g_Exit)
	{
		// print some stats
		u64 TSC0 = rdtsc();
		if (TSC0 > NextPrintTSC)
		{
			NextPrintTSC = TSC0 + ns2tsc(1e9);	

			double dByte = TotalByte - LastByte;
			double dT = tsc2ns(TSC0 - LastTSC) / 1e9;
			double bps = dByte * 8.0 / dT;

			// core cpu io write stalls
			float CPUIO = CycleTotalIO * inverse(CycleTotalTop);

			// worker cpu occupancy stats
			u64 WorkerCPUTop = 0;
			u64 WorkerCPUIO = 0;
			u64 WorkerCPUParse = 0;
			u64 WorkerCPUStall = 0;
			for (int i=0; i < 4; i++)
			{
				WorkerCPUTop 	+= s_WorkerCPUTop[i]; 
				WorkerCPUIO 	+= s_WorkerCPUIO[i]; 
				WorkerCPUParse 	+= s_WorkerCPUParse[i]; 
				WorkerCPUStall 	+= s_WorkerCPUStall[i]; 
			}

			float CPUWorkerIO	 = WorkerCPUIO * inverse(WorkerCPUTop);
			float CPUWorkerParse = WorkerCPUParse * inverse(WorkerCPUTop);
			float CPUWorkerStall = WorkerCPUStall * inverse(WorkerCPUTop);

			if (!g_Quiet) 
			{
				fprintf(stderr, "Recved %8.3f GB %8.3f Gbps Queue (%3i) (%3i) (%3i) (%3i)  | SeqNo: %i %i | CPU Core IO %.3f | CPU Worker IO:%.3f Parse:%.3f Stall:%.3f\n", 
					TotalByte / 1e9, 
					bps / 1e9,

					(u32)(N[0]->Queue.Put - N[0]->Queue.Get),
					(u32)(N[1]->Queue.Put - N[1]->Queue.Get),
					(u32)(N[2]->Queue.Put - N[2]->Queue.Get),
					(u32)(N[3]->Queue.Put - N[3]->Queue.Get),

					SeqNo, s_EOFSeqNo,

					CPUIO, CPUWorkerIO, CPUWorkerParse, CPUWorkerStall
				); 
			}

			LastByte 	= TotalByte;
			LastTSC		= TSC0;
		}

		// EOF ? 
		// NOTE: SeqNo is the NEXT expected SeqNo not
		//       last processed so it will match s_EOFSeqNo
		if ((s_EOFSeqNo != 0) && (SeqNo == s_EOFSeqNo))
		{
			if (!g_Quiet) fprintf(stderr, "Last Chunk Written\n");
			g_Exit = true;
			break;
		}

		// find next seq no 
		for (int c=0; c < 4; c++)
		{
			Queue_t* Q = &N[c]->Queue;

			// nothing to process 
			if (Q->Put == Q->Get)
			{
				ndelay(1000);
				continue;
			}

			// check each queue for the next seq no
			u32 Index 	= Q->Get & Q->Mask;
			Chunk_t* C 	= Q->Entry[Index];
			if (C->SeqNo == SeqNo)
			{
				u64 TSC2 = rdtsc();

				TotalByte += C->Header.DataLength;
				TotalPkt += C->PktCnt;
				//fprintf(stderr, "%lli %i\n", TotalByte, C->Header.DataLength);

				// next seq no to expect
				SeqNo 		= C->SeqNo + 1;

				// write sequential block to output 
				DataWrite(C->Data, C->Header.DataLength);

				// recycle the chunk
				ChunkFree(C);
				Q->Get++;

				// save last time somthing was processed
				u64 TSC3 		= rdtsc();
				LastDataTSC  	= TSC3;
				CycleTotalIO 	+= TSC3 - TSC2;	
			}
		}

		// check for timeout on no data recevied
		if (tsc2ns(rdtsc() - LastDataTSC) > 10e9)
		{
			fprintf(stderr, "ERROR: no data receveid in 10sec, exiting\n");
			g_Exit = true;
			break;
		}

		u64 TSC1 = rdtsc();
		CycleTotalTop += TSC1 - TSC0;
	}

	DataClose();

	pthread_join(RxThread0, NULL);
	pthread_join(RxThread1, NULL);
	pthread_join(RxThread2, NULL);
	pthread_join(RxThread3, NULL);

	u64 TSStop = clock_ns();

	// print transfer stats
	float dTS = (TSStop - TSStart) / 1e9;
	float Bps = (TotalByte * 8.0) / dTS;
	fprintf(stderr, "Took %.2f Sec  %.3f Gbps\n", dTS, Bps / 1e9); 
}

//-------------------------------------------------------------------------------------------
// test the local disk sequential write performance 
static void TestStream(u64 FileLength, u8* FilePath)
{
	CycleCalibration();

	printf("CreateTest File [%s]\n", FilePath);

	int fd  = open(FilePath, O_WRONLY| O_DIRECT | O_CREAT, S_IWUSR | S_IRUSR); 
	assert(fd > 0);

	fAIO_t* AIO = fAIO_Open(fd);
	assert(AIO != NULL);

	// truncate 
	int ret = ftruncate64(fd, FileLength);
	//int ret = ftruncate64(fd, 0);
	if (ret < 0)
	{
		printf("failed to truncate file %i %i\n", ret, errno);
	}

	// write pcap header
	PCAPHeader_t	PCAPHeader;
	PCAPHeader.Magic	= PCAPHEADER_MAGIC_NANO;
	PCAPHeader.Major	= PCAPHEADER_MAJOR;
	PCAPHeader.Minor	= PCAPHEADER_MINOR;
	PCAPHeader.TimeZone	= 0; 
	PCAPHeader.SigFlag	= 0; 
	PCAPHeader.SnapLen	= 65535; 
	PCAPHeader.Link		= PCAPHEADER_LINK_ETHERNET;
	//fwrite(&PCAPHeader, 1, sizeof(PCAPHeader), Output);
	//write(fd, &PCAPHeader, sizeof(PCAPHeader));

	u64 NextPrintTSC = 0;

	u32 SeqNo 		= 1;			// SeqNo 0 is reserved
	u64 TotalByte 	= 0;
	u64 TotalPkt	= 0;

	u64 LastByte 	= 0;
	u64 LastTSC  	= 0;

	// fill with random data, ensure 
	// write compression is negated
	u8* WriteDataUnalign	= malloc(kKB(256)*2);
	u8* WriteData			= (u8*)( ((u64) WriteDataUnalign + 4095) & (~4095ULL) );	
	u32 rnd = 0x12345678;
	for (int i=0; i < kKB(256); i++)
	{
		WriteData[i] = (rnd >> 16)&0xFF;
		rnd = rnd * 214013 + 2531011; 
	}

	u64 StartTSC = rdtsc();
	while (!g_Exit)
	{
		// print some stats
		u64 TSC0 = rdtsc();
		if (TSC0 > NextPrintTSC)
		{
			NextPrintTSC = TSC0 + ns2tsc(1e9);	

			double dByte = TotalByte - LastByte;
			double dT = tsc2ns(TSC0 - LastTSC) / 1e9;
			double bps = dByte * 8.0 / dT;

			if (!g_Quiet) 
			{
				fprintf(stderr, "Recved %8.3f GB %8.3f Gbps\n",
					TotalByte / 1e9, 
					bps / 1e9
				); 
			}

			LastByte 	= TotalByte;
			LastTSC		= TSC0;
		}
		fAIO_Update(AIO);
		fAIO_WriteUpdate(AIO);

		/*
		int wlen = write(fd, WriteData, kKB(256));
		assert(wlen == kKB(256));
		TotalByte += wlen;
		*/
		if (fAIO_Write(AIO, WriteData, kKB(256) ) > 0)
		{
			TotalByte 	+= kKB(256); 
			TotalPkt 	+= 1; 
		}

		// exit condition
		if (TotalByte >= FileLength) break;
		//if (TotalByte > kGB(1024) ) break;
	}

	// wait for all writes to complete 
	fAIO_WriteFlush(AIO);

	// total average write speed
	if (!g_Quiet) 
	{
		double dByte = TotalByte;
		double dT = tsc2ns(rdtsc() - StartTSC) / 1e9;
		double bps = dByte * 8.0 / dT;

		fprintf(stderr, "Total  %8.3f GB %8.3f Gbps\n", TotalByte / 1e9, bps / 1e9); 
	}
	//munmap(Map, MapLength);
	//fAIO_DumpHisto(AIO);

	//fclose(Output);
	close(fd);
}

//-------------------------------------------------------------------------------------------
// list all streams on the device
static void ListStreams(u8* IPAddress)
{
	CycleCalibration();

	Network_t* CnC = NetworkOpen(0, 10000, IPAddress);
	assert(CnC != NULL);

	CmdHeader_t Cmd;
	memset(&Cmd, 0, sizeof(Cmd));
	Cmd.Version = CMDHEADER_VERSION_1_0;
	Cmd.Cmd		= CMDHEADER_CMD_LIST;         

	// send request
	send(CnC->Sock, &Cmd, sizeof(Cmd), 0);

	// header
	printf("%-60s | Capture Size\n", "Stream Name");
	printf("-------------------------------------------------------------+------------------\n");

	// wait for reposonse
	while (true)
	{
		// get each stream 
		if (!RecvSock(CnC->Sock, (u8*)&Cmd, sizeof(Cmd))) break;

		// list finished
		if (Cmd.Cmd == CMDHEADER_CMD_END) break;

		printf("%-60s | %10.3f GB\n", Cmd.StreamName, Cmd.StreamSize / 1e9);
	}
	printf("-------------------------------------------------------------+------------------\n");
	printf("\n");
}

//-------------------------------------------------------------------------------------------
// get a specific stream 
static void GetStream(u8* IPAddress, u8* StreamName)
{
	CycleCalibration();

	if (!g_Quiet) fprintf(stderr, "GetStream IP[%s] [%s]\n", IPAddress, StreamName);

	Network_t* CnC = NetworkOpen(0, 10000, IPAddress);
	assert(CnC != NULL);

	CmdHeader_t Cmd;
	memset(&Cmd, 0, sizeof(Cmd));
	Cmd.Version = CMDHEADER_VERSION_1_0;
	Cmd.Cmd		= CMDHEADER_CMD_GET;         
	strncpy(Cmd.StreamName, StreamName, sizeof(Cmd.StreamName));

	// send request
	send(CnC->Sock, &Cmd, sizeof(Cmd), 0);

	// wait for reposonse
	if (!RecvSock(CnC->Sock, (u8*)&Cmd, sizeof(Cmd)))
	{
		fprintf(stderr, "Failed to connect [%s]\n", StreamName);
		return;
	}

	// check resposne
	if (Cmd.Cmd != CMDHEADER_CMD_OK)
	{
		fprintf(stderr, "Failed to find stream [%s]\n", StreamName);
		return;
	}

	// download it
	GetStreamData(IPAddress);

	// close CnC
	shutdown(CnC->Sock, 0);
}

//-------------------------------------------------------------------------------------------
static void help(void)
{
	fprintf(stderr, "fmadio_rsync: high speed download interface\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "PCAP Output is written to stdout.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "  -q                                        : Quiet mode\n");
	fprintf(stderr, "  --output-stdout                           : write output to stdout\n");
	fprintf(stderr, "  --output-disk <filename>                  : write output to disk specified at <filename>\n");

	fprintf(stderr, "  --list <fmadio device ip>                 : List all the captures on the device\n");
	fprintf(stderr, "  --get  <fmadio device ip> <capture name>  : download the specified capture\n");
	fprintf(stderr, "  --test <output size byte>                 : null disk write test, writes <bytes> output as fast as possible\n");
}

//-------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	fprintf(stderr, "fmadio rsync: %s\n", __DATE__);
	for (int i=1; i < argc; i++)
	{
		if (strcmp(argv[i], "--help") == 0)
		{
			help();
			return 0;
		}
		// quiet mode 
		else if (strcmp(argv[i], "-q") == 0)
		{
			g_Quiet = true;	
		}
		// output stdout 
		else if (strcmp(argv[i], "--output-stout") == 0)
		{
			s_OutputStdout = true;
			fprintf(stderr, "OutputMode stdout\n");
		}
		// output stdout 
		else if (strcmp(argv[i], "--output-file") == 0)
		{
			strncpy(s_OutputFileName, argv[i+1], sizeof(s_OutputFileName) );
			fprintf(stderr, "OutputMode File [%s]\n", s_OutputFileName);
			i += 1;

			// open a file for output via AIO
			DataOpen(s_OutputFileName);
		}
		// list all the captures 
		else if (strcmp(argv[i], "--list") == 0)
		{
			ListStreams(argv[i+1]);
			i += 1;
		}
		// featch a file and output to stdout 
		else if (strcmp(argv[i], "--get") == 0)
		{
			GetStream(argv[i + 1], argv[i+2]);
			i += 2;
		}
		// local disk io perf testing 
		else if (strcmp(argv[i], "--test") == 0)
		{
			u64 GBWrite = atof(argv[i+1]);
			fprintf(stderr, "Stream Null size %.f GB\n", GBWrite/1e9);
			TestStream(GBWrite, s_OutputFileName);
			i += 1;
		}
		else
		{
			fprintf(stderr, "unknown command [%s]\n", argv[i]);
		}
	}
}
