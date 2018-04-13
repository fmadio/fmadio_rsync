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

#define PACKETHEADER_FLAG_EOF			(1<<0)	// end of capture

typedef struct
{
	u32                 SeqNo;              // chunk seq no
	u32                 XferLength;         // byte length of transfer size
	u32                 DataLength;         // raw unpacked data length
	u8                 	Flag;           	// flags for the chunk 
	u8					pad[3];

} __attribute__((packed)) PacketHeader_t;


#define CMDHEADER_CMD_LIST          1       // list all the captures
#define CMDHEADER_CMD_GET           2       // get a capture
#define CMDHEADER_CMD_END          100 		// end of communications 
#define CMDHEADER_CMD_OK           101 		// sucess 
#define CMDHEADER_CMD_NG           102 		// failed 

typedef struct
{
	u32                 Cmd;                // command to issue
	u8                  StreamName[1024];	// stream info 
	u64					StreamSize;

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

static volatile u32			s_EOFSeqNo = 0;				// indicates SeqNo for EOF

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
	fprintf(stderr, "[%i] RxThread starting\n", N->CPUID);

	// receive at maximum rate per thread 
	bool Exit = false;
	while (!Exit)
	{
		// global exit
		if (g_Exit) break;

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
		if(!RecvSock(N->Sock, Header8, HeaderLength))
		{
			Exit = true;
			fprintf(stderr, "recv failed %s\n", strerror(errno));
			break;
		}
		/*
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
				Exit = true;
				break;
			}
		}
		*/

		// check for End of File marker
		if (C->Header.Flag & PACKETHEADER_FLAG_EOF)
		{
			fprintf(stderr, "EOF Reached SeqNo: %i\n", C->Header.SeqNo);
			if (C->Header.SeqNo != 0)
			{
				s_EOFSeqNo		= C->Header.SeqNo;
			}
			break;
		}

		//printf("[%i] SeqNo: %i XferLen:%i %08x\n", PortNo, Header.SeqNo, Header.XferLength, Header.CRC32);
		assert(C->Header.SeqNo != 0);
		C->SeqNo = C->Header.SeqNo;

		s32 BufferLength= C->Header.XferLength;
		u8* Buffer8		= (u8*)C->Data;
		if(!RecvSock(N->Sock, Buffer8, BufferLength))
		{
			Exit = true;
			fprintf(stderr, "recv data failed %s\n", strerror(errno));
			break;
		}

		// stats 
		N->TotalByte 	+= BufferLength;

		/*
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
		*/

		// mask out any meta data to make a pure PCAP 
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

	fprintf(stderr, "[%i] RxThread exit\n", N->CPUID);

	return NULL;
}

//-------------------------------------------------------------------------------------------
// master control thread that takes blocks recevied by each thread and
// re-assemables them in order 
static void GetStreamData(void)
{
	CycleCalibration();

	// init network connections	
	Network_t* N[4];
	N[0] = NetworkOpen(0, 10010);
	N[1] = NetworkOpen(1, 10010);
	N[2] = NetworkOpen(2, 10010);
	N[3] = NetworkOpen(3, 10010);

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
		// print some stats
		u64 TSC = rdtsc();
		if (TSC > NextPrintTSC)
		{
			NextPrintTSC = TSC + ns2tsc(1e9);	

			double dByte = TotalByte - LastByte;
			double dT = tsc2ns(TSC - LastTSC) / 1e9;
			double bps = dByte * 8.0 / dT;

			fprintf(stderr, "Recved %8.3f GB %8.3f Gbps Queue (%3i) (%3i) (%3i) (%3i)  : SeqNo: %i %i\n", 
					TotalByte / 1e9, 
					bps / 1e9,

					(u32)(N[0]->Queue.Put - N[0]->Queue.Get),
					(u32)(N[1]->Queue.Put - N[1]->Queue.Get),
					(u32)(N[2]->Queue.Put - N[2]->Queue.Get),
					(u32)(N[3]->Queue.Put - N[3]->Queue.Get),

					SeqNo, s_EOFSeqNo
			); 

			LastByte 	= TotalByte;
			LastTSC		= TSC;
		}

		// EOF ? 
		// NOTE: SeqNo is the NEXT expected SeqNo not
		//       last processed so it will match s_EOFSeqNo
		if ((s_EOFSeqNo != 0) && (SeqNo == s_EOFSeqNo))
		{
			fprintf(stderr, "Last Chunk Written\n");
			g_Exit = true;
			break;
		}

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
				int wlen = fwrite(C->Data, 1, C->Header.DataLength, stdout);
				assert(wlen == C->Header.DataLength);

				// recycle the chunk
				ChunkFree(C);
				Q->Get++;
			}
		}
	}

	pthread_join(RxThread0, NULL);
	pthread_join(RxThread1, NULL);
	pthread_join(RxThread2, NULL);
	pthread_join(RxThread3, NULL);
}

//-------------------------------------------------------------------------------------------
// list all streams on the device
static void ListStreams(void)
{
	CycleCalibration();

	Network_t* CnC = NetworkOpen(0, 10000);
	assert(CnC != NULL);


	CmdHeader_t Cmd;
	memset(&Cmd, 0, sizeof(Cmd));
	Cmd.Cmd	= CMDHEADER_CMD_LIST;         

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
static void GetStream(u8* StreamName)
{
	CycleCalibration();

	Network_t* CnC = NetworkOpen(0, 10000);
	assert(CnC != NULL);

	CmdHeader_t Cmd;
	memset(&Cmd, 0, sizeof(Cmd));
	Cmd.Cmd	= CMDHEADER_CMD_GET;         
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
	GetStreamData();

	// close CnC
	shutdown(CnC->Sock, 0);
}

//-------------------------------------------------------------------------------------------

int main(int argc, char* argv[])
{
	fprintf(stderr, "fmadio rsync: %s\n", __DATE__);

	for (int i=1; i < argc; i++)
	{
		// set the download capture name
		if (strcmp(argv[i], "--list") == 0)
		{
			ListStreams();
		}
		// featch a file and output to stdout 
		else if (strcmp(argv[i], "--get") == 0)
		{
			GetStream(argv[i + 1]);
			i++;
		}
		else
		{
			fprintf(stderr, "unknown command [%s]\n", argv[i]);
		}
	}
}
