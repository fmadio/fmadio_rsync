#ifndef __F_TYPES_H__
#define __F_TYPES_H__

#include <math.h>
#include <limits.h>
#include <assert.h>
#include <string.h>

typedef unsigned char		u8;
typedef char				s8;

typedef unsigned short		u16;
typedef short				s16;

typedef unsigned int 		u32;
typedef int					s32;

typedef unsigned long long	u64;
typedef long long			s64;

/*
typedef struct
{
	unsigned long long	hi;
	unsigned long long	lo;
} u128;
*/
typedef unsigned __int128	u128;

typedef union
{
	u8	_u8;
	u16	_u16;
	s16	_s16;
	s32	_s32;
	u32	_u32;
	u64	_u64;
	s64	_s64;

	float	f;
	double	d;

} MultiType_u;

#define DSCALE 				(1.0 / 10000.0)
#define D4SCALE 			(1.0 / 10000.0)
#define k1E9 				1000000000ULL

#define kKB(a) 				(((u64)a)*1024ULL)
#define kMB(a) 				(((u64)a)*1024ULL*1024ULL)
#define kGB(a)				(((u64)a)*1024ULL*1024ULL*1024ULL)
#define kTB(a)				(((u64)a)*1024ULL*1024ULL*1024ULL*1024ULL)
#define kGiB(a)				(((u64)a)*1024ULL*1024ULL*1024ULL)
#define kTiB(a)				(((u64)a)*1024ULL*1024ULL*1024ULL*1024ULL)

#define kYearNS(a) 			((u64)a  * 365ULL * 24ULL * 60ULL * 60ULL *  1000000000ULL) 
#define kYearNSEpoch(a) 	((u64)(a - 1970)  * 365ULL * 24ULL * 60ULL * 60ULL *  1000000000ULL) 

#define LIMIT_U64_MIN		0	
#define LIMIT_U64_MAX		(0xffffffffffffffffLL)

#define true		1
#define false		0

#ifndef NULL
	#define NULL	0
#endif

#define INLINE		inline

// linux defines
#define __USE_FILE_OFFSET64 1

#ifndef __cplusplus
	typedef unsigned int bool;
#endif

#include <time.h>
#include <sys/time.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>

#define PACKED		__attribute__((packed))	
#define FileOpen	fopen64
#define FileClose	fclose	
#define FileRead	fread	
#define FilePrintf	fprintf	
#define FileWrite	fwrite	
#define FileSeek	fseeko64	
#define FileTell	ftello64	
#define FileFlush	fflush	

typedef struct
{
	int		year;
	int		month;
	int		day;
	int		hour;
	int		sec;
	int		min;
} clock_date_t;

static clock_date_t  clock_date(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	struct tm t;
	localtime_r(&tv.tv_sec, &t);

	clock_date_t c; 
	c.year		= 1900 + t.tm_year;
	c.month		= 1 + t.tm_mon;
	c.day		= t.tm_mday;
	c.hour		= t.tm_hour;
	c.min		= t.tm_min;
	c.sec		= t.tm_sec;

	return c;
}

// 0 - Sunday
// 1 - Monday 
// ...
// http://en.wikipedia.org/wiki/Determination_of_the_day_of_the_week#Implementation-dependent_methods_of_Sakamoto.2C_Lachman.2C_Keith_and_Craver 
static inline int dayofweek(int d, int m, int y)
{
    static int t[] = { 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    y -= m < 3;
    return ( y + y/4 - y/100 + y/400 + t[m-1] + d) % 7;
}

// generates date in web format RFC1123
static inline void  clock_rfc1123(u8* Str, clock_date_t c)
{
	const char *DayStr[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	const char *MonthStr[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	struct tm t;
	t.tm_year		= c.year - 1900;
	t.tm_mon		= c.month - 1;
	t.tm_mday		= c.day;
	t.tm_hour		= c.hour;
	t.tm_min		= c.min;
	t.tm_sec		= c.sec;

	int wday		= dayofweek(c.day, c.month, c.year);

    const int RFC1123_TIME_LEN = 29;
	strftime(Str, RFC1123_TIME_LEN+1, "---, %d --- %Y %H:%M:%S GMT", &t);
	memcpy(Str, 	DayStr	[wday], 3);
    memcpy(Str+8, 	MonthStr[c.month - 1], 3);
}

static inline void  clock_str(u8* Str, clock_date_t c)
{
	sprintf(Str, "%04i%02i%02i_%02i%02i%02i", c.year, c.month, c.day, c.hour, c.min, c.sec);
}
static inline void  ns_str(u8* Str, u64 NS) 
{
	u64 sec = NS % k1E9;	
	int msec = sec / 1000000ULL; 
	int usec = (sec - msec*1000000ULL)/ 1000ULL; 
	int nsec = (sec - msec*1000000ULL- usec*1000ULL);

	sprintf(Str, "%03i.%03i.%03i", msec, usec, nsec);
}


// GMT epoch nanos -> year, mont, day, ..
static clock_date_t  ns2clock(u64 ts)
{
	time_t t0 = ts / 1e9;

	struct tm* t = localtime(&t0);
	clock_date_t c; 

	c.year		= 1900 + t->tm_year;
	c.month		= 1 + t->tm_mon;
	c.day		= t->tm_mday;
	c.hour		= t->tm_hour;
	c.min		= t->tm_min;
	c.sec		= t->tm_sec;

	return c;
}

// verbose -> nanos since epoch
static u64 clock2ns(int year, int month, int day, int hour, int min, int sec)
{
	struct tm t;

	t.tm_year 	= year - 1900;
	t.tm_mon	= month-1;
	t.tm_mday	= day;
	t.tm_hour	= hour;
	t.tm_min	= min;
	t.tm_sec	= sec;

	time_t epoch = mktime(&t);
	return (u64)epoch * (u64)1e9; 
}

static u64 clock_date2ns(clock_date_t d)
{
	struct tm t;

	t.tm_year 	= d.year - 1900;
	t.tm_mon	= d.month-1;
	t.tm_mday	= d.day;
	t.tm_hour	= d.hour;
	t.tm_min	= d.min;
	t.tm_sec	= d.sec;

	time_t epoch = mktime(&t);
	return (u64)epoch * (u64)1e9; 
}

// returns the first day of the week
static clock_date_t clock_startofweek(clock_date_t d)
{
	struct tm t;

	int wday		= dayofweek(d.day, d.month, d.year);

	t.tm_year 	= d.year - 1900;
	t.tm_mon	= d.month-1;
	t.tm_mday	= d.day - wday;
	t.tm_hour	= d.hour;
	t.tm_min	= d.min;
	t.tm_sec	= d.sec;

	mktime(&t);

	clock_date_t r;
	r.year		= 1900 + t.tm_year;
	r.month		= 1 + t.tm_mon;
	r.day		= t.tm_mday;
	r.hour		= t.tm_hour;
	r.min		= t.tm_min;
	r.sec		= t.tm_sec;

	return r;
}


// epoch in nanos in GMT timezone 
static u64 clock_ns(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);

	return (u64)tv.tv_sec *(u64)1e9 +(u64)tv.tv_usec * (u64)1e3;
}

static INLINE volatile u64 rdtsc(void)
{
	u32 hi, lo;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi) );
	return (((u64)hi)<<32ULL) | (u64)lo;
}
static INLINE volatile u64 rdtsc2(void)
{
	u32 hi, lo;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi) );
	return (((u64)hi)<<32ULL) | (u64)lo;
}


extern double TSC2Nano;
static INLINE volatile u64 rdtsc_ns(void)
{
	u32 hi, lo;
	__asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi) );

	u64 ts = (((u64)hi)<<32ULL) | (u64)lo;
	return ts * TSC2Nano; 
}

static INLINE volatile u64 rdtsc2ns(u64 ts)
{
	return ts * TSC2Nano; 
}

static INLINE volatile u64 tsc2ns(u64 ts)
{
	return ts * TSC2Nano; 
}

static INLINE u64 ns2tsc(u64 ns)
{
	return (u64)( (double)ns / TSC2Nano);
}

static void ndelay(u64 ns)
{
	u64 NextTS = rdtsc() + ns2tsc(ns);
	while (rdtsc() < NextTS)
	{
		__asm__ volatile("pause");
		__asm__ volatile("pause");
		__asm__ volatile("pause");
		__asm__ volatile("pause");
	}
}

static INLINE void prefetchnta(void* ptr)
{
	__asm__ volatile("prefetchnta (%0)" :  : "r"(ptr));
}
static INLINE void prefetcht0(void* ptr)
{
	__asm__ volatile("prefetcht0  (%0)" :  : "r"(ptr));
}
static INLINE void prefetcht1(void* ptr)
{
	__asm__ volatile("prefetcht1  (%0)" :  : "r"(ptr));
}
static INLINE void prefetcht2(void* ptr)
{
	__asm__ volatile("prefetcht2  (%0)" :  : "r"(ptr));
}

static INLINE void clflush(void* ptr)
{
	__asm__ volatile("clflush  (%0)" :  : "r"(ptr));
}
static INLINE void clflushopt(void* ptr)
{
	__asm__ volatile("clflushopt  (%0)" :  : "r"(ptr));
}

static INLINE void clwb(void* ptr)
{
	__asm__ volatile("clwb  (%0)" :  : "r"(ptr));
}

static INLINE void sfence(void)
{
	__asm__ volatile("sfence");
}

static INLINE void mfence(void)
{
	__asm__ volatile("mfence");
}

static INLINE u32 swap32(const u32 a)
{
	return (((a>>24)&0xFF)<<0) | (((a>>16)&0xFF)<<8) | (((a>>8)&0xFF)<<16) | (((a>>0)&0xFF)<<24);
}

static INLINE u16 swap16(const u16 a)
{
	return (((a>>8)&0xFF)<<0) | (((a>>0)&0xFF)<<8);
}

static INLINE u64 swap64(const u64 a)
{
	return swap32(a>>32ULL) | ( (u64)swap32(a) << 32ULL); 
}

static INLINE u128 swap128(const u128 a)
{
	u64* p = (u64*)&a;
	return (u128)swap64(p[1]) | ((u128)swap64(p[0]));
}

static INLINE u32 min32(const u32 a, const u32 b)
{
	return (a < b) ? a : b;
}

static INLINE s32 min32s(const s32 a, const s32 b)
{
	return (a < b) ? a : b;
}

static INLINE u32 max32(const u32 a, const u32 b)
{
	return (a > b) ? a : b;
}
static INLINE s32 max32s(const s32 a, const s32 b)
{
	return (a > b) ? a : b;
}


static INLINE s32 sign32(const s32 a)
{
	if (a == 0) return 0;
	return (a > 0) ? 1 : -1;
}

static INLINE u64 min64(const u64 a, const u64 b)
{
	return (a < b) ? a : b;
}

static INLINE u64 max64(const u64 a, const u64 b)
{
	return (a > b) ? a : b;
}

static INLINE double maxf(const double a, const double b)
{
	return (a > b) ? a : b;
}

static INLINE double minf(const double a, const double b)
{
	return (a < b) ? a : b;
}
static INLINE double clampf(const double min, const double v, const double max)
{
	return maxf(min, minf(v,  max)); 
}

static INLINE double inverse(const double a)
{
	if (a == 0) return 0;
	return 1.0 / a;
}

static INLINE double fSqrt(const double a)
{
	if (a <= 0) return 0;
	return sqrtf(a);
}

static INLINE double signf(const double a)
{
	if (a > 0) return  1.0;
	if (a < 0) return -1.0;

	// keep it simple..
	return 1;
}
static INLINE double alog(const double a)
{
	if (a == 0) return 0;
	if (a < 0) return -logf(-a);
	return -logf(a);
}

static INLINE char* FormatTS(u64 ts)
{
	u64 usec = ts / 1000ULL;
	u64 msec = usec / 1000ULL;
	u64 sec = msec / 1000ULL;
	u64 min = sec / 60ULL;
	u64 hour = min / 60ULL;

	u64 nsec = ts - usec*1000ULL;
	usec = usec - msec*1000ULL;
	msec = msec - sec*1000ULL;
	sec = sec - min*60ULL;
	min = min - hour*60ULL;

	static char List[16][128];
	static int Pos = 0;

	char* S = List[Pos];
	Pos = (Pos + 1) & 0xf;

	sprintf(S, "%02lli:%02lli:%02lli.%03lli.%03lli.%03lli", hour % 24, min, sec, msec,usec, nsec);
	return S;
}
static inline void  ns2str(u8* Str, u64 TS) 
{
	clock_date_t c = ns2clock(TS);

	u64 sec = TS % k1E9;	
	int msec = sec / 1000000ULL; 
	int usec = (sec - msec*1000000ULL)/ 1000ULL; 
	int nsec = (sec - msec*1000000ULL- usec*1000ULL);

	sprintf(Str, "%04i%02i%02i_%02i%02i%02i.%03i.%03i.%03i", c.year, c.month, c.day, c.hour, c.min, c.sec, msec, usec, nsec);
}


static INLINE void CycleCalibration(void)
{
    //fprintf(stderr, "calibrating...\n");
    u64 StartTS[16];
    u64 EndTS[16];

	// parse /proc/cpuinfo to get the target rdtsc freq
	// lazymans cpuid

	/*

	FILE * F = fopen("/proc/cpuinfo", "r");	
	static char Buffer[1024];
	fread(Buffer, 1024, 1, F);
	fclose(F);

	u64 TargetFreq = 0;
	if (strstr(Buffer, "E5-1620 v3") != NULL) TargetFreq = 3.5e9;
	if (strstr(Buffer, "E5-1630 v3") != NULL) TargetFreq = 3.7e9;
	if (strstr(Buffer, "E5-1650 v3") != NULL) TargetFreq = 3.5e9;
	if (strstr(Buffer, "E5-2620 v3") != NULL) TargetFreq = 2.4e9;
	if (strstr(Buffer, "E5-2620 v4") != NULL) TargetFreq = 2.1e9;
	if (strstr(Buffer, "N3050")      != NULL) TargetFreq = 1.6e9;		// fmad1g 
	*/

	// calibrate exactly
    u64 CyclesSum   = 0;
    u64 CyclesSum2  = 0;
    u64 CyclesCnt   = 0;
	double CalibPeriodNS = 1e6;
	int i;
    for (i=0; i < 1; i++)
 	{
        u64 NextTS = clock_ns() + CalibPeriodNS;
        u64 StartTSC = rdtsc();
        while (clock_ns() < NextTS)
        {
			/*
        	if ((rdtsc() - StartTSC) > 5 * TargetFreq)
			{
        		fprintf(stderr, "%i : Calibration overflow: %lli : %lli\n", i, clock_ns(), NextTS);  
				break;
			}
			*/
        }
        u64 EndTSC  = rdtsc();

        u64 Cycles = EndTSC - StartTSC;
        CyclesSum += Cycles;
        CyclesSum2 += Cycles*Cycles;
        CyclesCnt++;

        //fprintf(stderr, "%i : %lli %16.4f cycles/nsec\n", i, Cycles, Cycles / 1e9);
    }

    double CyclesSec = CyclesSum / CyclesCnt;
    double CyclesStd = sqrt(CyclesCnt *CyclesSum2 - CyclesSum *CyclesSum) / CyclesCnt;
    //fprintf(stderr, "Cycles/Sec %12.4f %.2f Ghz\n", CyclesSec, CyclesSec / CalibPeriodNS); 

	// set global
	TSC2Nano = CalibPeriodNS / CyclesSec;
}

// convert pcap style sec : nsec format into pure nano
static inline u64 nsec2ts(u32 sec, u32 nsec)
{
	return (u64)sec * 1000000000ULL + (u64)(nsec & 0x7fffffff);
}

static void * memalign2(int align, size_t size)
{
	void* a;
	posix_memalign(&a, align, size);
	return a;
}

#endif
