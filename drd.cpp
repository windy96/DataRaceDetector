/*
 *	Data race detector
 *
 *	Description
 *		This program detects data races, which are potential concurrency bugs.
 *
 *	Programming
 *		spawned from coach and tracker May 5, 2013
 *		last updated on May 17, 2013
 *		written by Kim, Wooil
 *		kim844@illinois.edu
 *
 */


#include "pin.H"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <string>
#include <map>
#include <vector>
#include <list>
#include <bitset>
#include <set>
#include <bits/wordsize.h>


//-------------------------------------------------------------------
//	Configurable Parameters
//-------------------------------------------------------------------

#define __64BIT__
//	Maximum worker threads are set to 32.
#define MAX_WORKER	8
//	Maximum threads are maximum work threads + 1 to support master-workers execution model.
#define MAX_THREADS MAX_WORKER+1
#define STATE_BITS	3
#define MAX_STATES  (MAX_THREADS)*(STATE_BITS)

#define WORD_BITWIDTH	32
#define WORD_BYTES		4

const char *configFileName = "drd.cfg";




//	Currently all operations are verified with 64-bit only.
//	[TODO] make this work with 32-bit binaries
#if __WORDSIZE == 64
	#define INT_SIZE	8
	#define WORD_SIZE	4
	#define ADDR_MASK	0xFFFFFFFFFFFFFFFC
#else
	// 32-bit execution is not verified yet.
	#define INT_SIZE	4
	#define WORD_SIZE	4
	#define ADDR_MASK	0xFFFFFFFC
#endif

//	[TODO] this will be deleted.
#define LINE_SIZE	64
#define PAD_SIZE 	(LINE_SIZE - INT_SIZE)


using namespace std;



//-------------------------------------------------------------------
//	Logger
//-------------------------------------------------------------------

//	WindyLogger is used for displaying all logging/debugging/error messages.
//	It has five display levels, and can have output file other than stdout.
class WindyLogger
{
private:
	int		displayLevel;
	int		fileoutLevel;
	FILE*	outputFile;

public:
	enum DisplayLevelEnum {
		DISPLAY_TEMP_DEBUG,		// Debugging information which will be used temporarily.
		DISPLAY_DEBUG,
		DISPLAY_LOG,
		DISPLAY_WARNING,
		DISPLAY_ERROR,
		DISPLAY_NONE			// At this level, any message is not displayed.
	};

	enum FileoutLevelEnum {
		FILEOUT_TEMP_DEBUG,		// Debugging information which will be used temporarily.
		FILEOUT_DEBUG,
		FILEOUT_LOG,
		FILEOUT_WARNING,
		FILEOUT_ERROR,
		FILEOUT_NONE			// At this level, any message is not displayed.
	};

	WindyLogger() 
	{ 
		displayLevel = DISPLAY_ERROR;
		fileoutLevel = FILEOUT_LOG;
		outputFile = stdout;
	}

	int		getDisplayLevel()		{ return displayLevel; }
	void	setDisplayLevel(int d)	{ displayLevel = d; }

	int		getFileoutLevel()		{ return fileoutLevel; }
	void	setFileoutLevel(int d)	{ fileoutLevel = d; }

	FILE*	getOutputFile()			{ return outputFile; }
	void	setOutputFile(FILE* fp)	{ outputFile = fp; }
	void	close()					{ fprintf(outputFile, "#eof\n"); fclose(outputFile); }


	void temp(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_TEMP_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[TEMP]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_TEMP_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[TEMP]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

	void debug(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[DEBUG]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_DEBUG) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[DEBUG]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

	void log(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_LOG) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[LOG]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_LOG) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[LOG]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

	void warn(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_WARNING) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[WARN]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_WARNING) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[WARN]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

	void error(const char* format, ...)
	{
		if (displayLevel <= DISPLAY_ERROR) {
			if (!strcmp(format, "")) {
				fprintf(stdout, "\n");
				return;
			}

			va_list args;
			fprintf(stdout, "[ERROR]  ");
			va_start(args, format);
			vfprintf(stdout, format, args);
			va_end(args);
			fprintf(stdout, "\n");
		}

		if (fileoutLevel <= FILEOUT_ERROR) {
			if (!strcmp(format, "")) {
				fprintf(outputFile, "\n");
				return;
			}

			va_list args;
			fprintf(outputFile, "[ERROR]  ");
			va_start(args, format);
			vfprintf(outputFile, format, args);
			va_end(args);
			fprintf(outputFile, "\n");
		}
	}

};	// class WindyLogger

WindyLogger		Logger;



//-------------------------------------------------------------------
//	Data Structure
//-------------------------------------------------------------------
INT			BarrierCount;				// How many barrier epochs appeared

//	sourceLocation structure is used in MallocTracker.
//	This structure is used for storing source code location.
struct sourceLocation
{
	int		col;
	int		line;
	string	filename;

	sourceLocation() {}
	sourceLocation(int c, int l, string fname)
		: col(c), line(l), filename(fname)
	{ }
};


struct WordStatus
{
	int				state;
	unsigned int	proc;
	int				epoch;
	int				segment;
	void*			lock;

	struct sourceLocation	src;
};



//	Memory Allocation Tracker
class MallocTracker 
{
private:
	// Address and size pair is maintained in STL map.
	map<ADDRINT, int>					addrMap;
	map<ADDRINT, int>::iterator			it;

	map<ADDRINT, struct sourceLocation>				sourceMap;
	map<ADDRINT, struct sourceLocation>::iterator	sourceIt;

	map<ADDRINT, string>				variableNameMap;
	map<ADDRINT, string>::iterator		variableNameIt;

	map<ADDRINT, struct WordStatus* >			stateMap;
	map<ADDRINT, struct WordStatus* >::iterator	stateIt;

public:
	//	Previous information about allocation is open for WritesMemBefore.
	ADDRINT		prevAddr[MAX_THREADS];
	int			prevSize[MAX_THREADS];

	MallocTracker() 
	{ 
		addrMap.clear(); 
		sourceMap.clear();
		variableNameMap.clear();
		stateMap.clear();
		for (int i = 0; i < MAX_THREADS; i++) {
			prevAddr[i] = 0;
			prevSize[i] = 0;
		}
	}

	bool hasEntry(ADDRINT addr) { return (addrMap.find(addr) != addrMap.end()); }

	void add(ADDRINT addr, int size, THREADID tid) 
	{
		// if we already have the same address as a start address, this is problematic.
		// sometimes the program exectues malloc twice for some reason, this should not be treated as errors.
		if (hasEntry(addr)) {
			if (addrMap[addr] != size) {
				Logger.error("Memory allocation occurs for the already allocated address: 0x%lx.", addr);
				return;
			}

			// if (addrMap[addr] == size) 
			// [NOTE]
			// memory allocation for the same address and size is called.
			// For now, just ignore it.
			// calloc after malloc initializes the value. Thus, if we consider the value, we should check it.
			return;
		}

		addrMap[addr] = size;

		// [TODO] consider word-alignment
		// Currently, only word-aligned memory allocation is considered.
		struct WordStatus	*pState;
		int wordSize = (size + (WORD_SIZE - 1)) / WORD_SIZE;
		pState = new struct WordStatus [wordSize];
		for (int i = 0; i < wordSize; i++)
		{
			pState[i].state = 0;
			pState[i].proc = 9999;	// proc is unsigned.
			pState[i].epoch = 0;
			pState[i].segment = 0;
			pState[i].lock = 0;

			pState[i].src.col = 0;
			pState[i].src.line = 0;
			pState[i].src.filename = "";
		}
		stateMap[addr] = pState;

		// prev information is maintained for malloc.
		prevAddr[tid] = addr;
		prevSize[tid] = size;

		Logger.log("MAlloc tracker adds addr 0x%lx with size 0x%x. %d entries are added.", addr, size, wordSize);
		int sum = 0;
		int i;
		for (i = 0; i < wordSize / WORD_SIZE; i++)
			sum += (stateMap[addr]) [i].state;
		Logger.log("verify: sum=%d i=%d", sum, i);
			
	}

	void remove(ADDRINT addr) 
	{
		// free(ptr) removes the entry.

		// If address is 0, this may be free(ptr) call from the system.
		// We ignore this.
		if (addr == 0)
			return;

		// If the address is not in addrMap, this might be a problem.
		// For now, however, this is not our concern.
		if (!hasEntry(addr))
			return;

		Logger.log("MAlloc tracker removes addr 0x%lx with size 0x%x.", addr, addrMap[addr]);

		delete[] (stateMap[addr]);
		stateMap.erase(addr);
		addrMap.erase(addr);
	}

	// to check if addr is within currently allocated memory area
	bool contain(ADDRINT addr)
	{
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT	startAddr, endAddr;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					return true;
			}
			else
				return false;
		}
		return false;
	}

	// to provide an offset inside the variable for the given address
	// It is recommended to call getOffset with true return value of contain.
	ADDRINT getBase(ADDRINT addr)
	{
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT	startAddr, endAddr;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					return startAddr;
			}
			else
				return -1;
		}
		return -1;
	}

	// to provide an offset inside the variable for the given address
	// It is recommended to call getOffset with true return value of contain.
	ADDRINT getOffset(ADDRINT addr)
	{
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT	startAddr, endAddr;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					return addr - startAddr;
			}
			else
				return -1;
		}
		return -1;
	}

	struct WordStatus * wordStatus(ADDRINT addr)
	{
		ADDRINT	startAddr, endAddr;

		startAddr = 0;	// this is for turning off warning message.
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			//Logger.log("wordStatus: 0x%lx - 0x%lx", (*it).first, (*it).first + (*it).second);
			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					break;
			}
			else {
				Logger.error("No match in wordStatus for address 0x%lx (overrun): saddr 0x%lx, eaddr 0x%lx.", addr, startAddr, endAddr);
				return NULL;
			}
		}
		if (it == addrMap.end()) {
			Logger.error("No match in wordStatus for address 0x%lx (end).", addr);
			return NULL;
		}

		//Logger.log("wordStatus: match found for 0x%lx: 0x%lx - 0x%lx: %d th entry", addr, startAddr, endAddr, (addr-startAddr)/WORD_SIZE);
		return &( ( (stateMap[startAddr]) )[(addr - startAddr) / WORD_SIZE] );
	}

	void clear()
	{
		ADDRINT	startAddr, endAddr;

		startAddr = 0;	// this is for turning off warning message.
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			ADDRINT startWordAddress, endWordAddress;

			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			startWordAddress = startAddr & ADDR_MASK;
			endWordAddress = endAddr & ADDR_MASK;

			for (ADDRINT a = startWordAddress; a < endWordAddress; a += WORD_SIZE)
			{				
				struct WordStatus *pStatus;
				pStatus = wordStatus(a);

				pStatus->state = 0;
				pStatus->proc = 9999;
				pStatus->epoch = 0;
				pStatus->segment = 0;
				pStatus->lock = 0;

				pStatus->src.col = 0;
				pStatus->src.line = 0;
				pStatus->src.filename = "";
			}
			//Logger.log("%s is cleared for size %d.", getVariableName(startAddr).c_str(), endWordAddress-startWordAddress);
		}
	}

	// Source functions are doing the same thing as above functions, 
	// but this is for maintaining source code location.
	void addSource(int column, int line, string filename, THREADID tid)
	{
		sourceMap[prevAddr[tid]] = sourceLocation(column, line, filename);
	}

	void removeSource(ADDRINT addr)
	{
		sourceMap.erase(addr);
	} 

	struct sourceLocation* getSource(ADDRINT addr)
	{
		ADDRINT	startAddr, endAddr;

		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					break;
			}
			else {
				Logger.error("No match in getSource for address 0x%lx (overrun): saddr 0x%lx, eaddr 0x%lx.", addr, startAddr, endAddr);
				return NULL;
			}
		}
		if (it == addrMap.end()) {
			Logger.error("No match in getSource for address 0x%lx (end).", addr);
			return NULL;
		}
		
		return &(sourceMap[startAddr]);
	}


	// Variable name functions are doing the same thing as above functions, 
	// but this is for maintaining variable names for memory allocation.
	void addVariableName(string s, int offset, THREADID tid)
	{
		if (offset != 0) {
			char	t[20];
			sprintf(t, "[0x%x]", offset);
			s.append(t);
		}

		Logger.temp("addVariableName: %s is added as addr 0x%lx.", s.c_str(), prevAddr[tid]);
		variableNameMap[prevAddr[tid]] = s;
	}

	void removeVariableName(ADDRINT addr)
	{
		variableNameMap.erase(addr);
	}

	string getVariableName(ADDRINT addr)
	{
		ADDRINT	startAddr, endAddr;

		startAddr = 0;
		for (it = addrMap.begin(); it != addrMap.end(); it++)
		{
			startAddr = (*it).first;
			endAddr = startAddr + (*it).second;

			if (startAddr <= addr) {
				if (endAddr > addr)
					break;
			}
			else {
				Logger.error("No match in getVariableName for address 0x%lx (overrun): saddr 0x%lx, eaddr 0x%lx.", addr, startAddr, endAddr);
				return NULL;
			}
		}
		if (it == addrMap.end()) {
			Logger.error("No match in getVariableName for address 0x%lx (end).", addr);
			return NULL;
		}
		
		return variableNameMap[startAddr];		
	}
};	// class MallocTracker



class OrderingTracker
{
private:
	vector< THREADID > signalTidVec;
	vector< int > signalSegNumVec;
	vector< void * > signalCondVec;

	vector <int> orderPrev[MAX_THREADS];
	vector <int> orderNext[MAX_THREADS];

public:
	OrderingTracker()
	{
	}

	void whenSignal(THREADID tid, int segmentNum, void *cond)
	{
		signalTidVec.push_back(tid);
		signalSegNumVec.push_back(segmentNum);
		signalCondVec.push_back(cond);
	}

	void whenWaitIsDone(THREADID tid, int segmentNum, void *cond)
	{
		int i, j;
		for (i = signalTidVec.size() - 1; i >= 0; i--)
		{
			if (signalCondVec[i] == cond) {	// match is found
				for (j = 0; j < MAX_THREADS; j++)
				{
					orderPrev[j].push_back(-1);
					orderNext[j].push_back(-1);
				}
				orderPrev[signalTidVec[i]].back() = signalSegNumVec[i];
				orderNext[tid].back() = segmentNum;
				Logger.log("ordering established from %d %d to %d %d at epoch %d", 
					signalTidVec[i], signalSegNumVec[i],
					tid, segmentNum, BarrierCount);
				break;
			}
		}
		// no error handling is added.
	}

	int established(int prev, int next)
	{
		int i;
		Logger.log("established prev:%d next:%d", prev, next);
		for (i = orderNext[next].size() - 1; i >= 0; i--)
		{
			if (orderNext[next][i] != -1) {
				if (orderPrev[prev][i] != -1) {
					return orderPrev[prev][i];
				}
			}
		}
		return -1;
	}	
	
	void clear()
	{
		signalTidVec.clear();
		signalSegNumVec.clear();
		signalCondVec.clear();
		
		for (int i = 0; i < MAX_THREADS; i++) {
			orderPrev[i].clear();
			orderNext[i].clear();
		}
	}


};

//	This structure is used for thread-specific read/write counts.
//	pad is used to avoid per-thread cache invalidation.  Line size is assumed as 64-Bytes.
struct thread_data_t
{
	UINT64	count;
	UINT8	pad[PAD_SIZE];
};



//	Global variable information is stored in this structure.
struct GlobalVariableStruct {
	string	name;
	ADDRINT	addr;
	int		size;
	ADDRINT	allocAddr;		// if this variable is used for memory allocation, allocated address in heap is registered here.
	int		allocSize;
	struct WordStatus *pState;

	GlobalVariableStruct() { }
	GlobalVariableStruct(string s, ADDRINT a, int sz, int aa, int as)
		: name(s), addr(a), size(sz), allocAddr(aa), allocSize(as)
	{
		int wordSize = (sz + (WORD_BYTES - 1)) / WORD_BYTES;
		pState = new struct WordStatus [wordSize];
		for (int i = 0; i < wordSize; i++)
		{
			pState[i].state = 0;
			pState[i].proc = 9999;
			pState[i].epoch = 0;
			pState[i].segment = 0;
			pState[i].lock = 0;

			pState[i].src.col = 0;
			pState[i].src.line = 0;
			pState[i].src.filename = "";
		}
	}

	void attachState()
	{
		int wordSize = (allocSize + WORD_BYTES - 1) / WORD_BYTES;
		pState = new struct WordStatus [wordSize];
		for (int i = 0; i < wordSize; i++)
		{
			pState[i].state = 0;
			pState[i].proc = 9999;
			pState[i].epoch = 0;
			pState[i].segment = 0;
			pState[i].lock = 0;

			pState[i].src.col = 0;
			pState[i].src.line = 0;
			pState[i].src.filename = "";
		}
	}
};


//	Code for PMC instructions
enum PMCInst {
	invalidation,
	writeback,
	writebackInvalidation,
	loadBypass,
	storeBypass,
	writebackMerge,
	writebackReserve,
	writeFirst
};

enum ProgramCategory {
	UNKNOWN,
	PTHREAD,
	GTHREAD,
	OPENMP
};



enum LockedState {
	Unlocked,
	Locked,
	DuringLockFunc
};

//-------------------------------------------------------------------
//	Global Variables
//-------------------------------------------------------------------

//	Category configuration
int				Category;

//	Display configuration
BOOL			Suggestion;
char			OutputFileName[100];
FILE			*OutputFile;

// Machine configuration
int				MaxWorkerThreads;
int				CacheLineSize;

// variable configuration
char			VariableFileName[100];
BOOL			ExcludePotentialSystemVariables;	// if true, global variable which name starts with '.' or '_' is ignored.

//	tracking configuration
BOOL			AfterMainTracking;			// if true, address tracking is enabled after main function is started
BOOL			MainRunning;				// after main function is started, this is set as true.
BOOL			MasterThreadOnlyAllocFree;	// if true, memory allocation/free from child threads is not tracked



PIN_LOCK		Lock;

INT			NumThreads;					// Current number of threads
INT			MaxThreads;					// Maximum number of threads appeared during execution
//INT			BarrierCount;				// How many barrier region appeared
INT			BarrierNumber;				// How many participants for this barrier
INT			CurrentBarrierArrival;		// For tracking currently arrived participants for the barrier
INT			SegmentCount[MAX_THREADS];
OrderingTracker		Ordering;

MallocTracker		MATracker;

std::map<ADDRINT, std::string>	DisAssemblyMap;
struct thread_data_t	NumReads[MAX_THREADS];
struct thread_data_t	NumWrites[MAX_THREADS];

BOOL			AfterAlloc[MAX_THREADS];	// if true, it is just after memory allocation function.

vector< set<ADDRINT> >	ReadWordsInAnEpoch[MAX_THREADS];
vector< set<ADDRINT> >::iterator	ReadWordsVectorIterator[MAX_THREADS];
set<ADDRINT>		ReadWordsInThisEpoch[MAX_THREADS];
set<ADDRINT>::iterator	ReadWordsIterator[MAX_THREADS];

vector< set<ADDRINT> >	WrittenWordsInAnEpoch[MAX_THREADS];
vector< set<ADDRINT> >::iterator	WrittenWordsVectorIterator[MAX_THREADS];
set<ADDRINT>		WrittenWordsInThisEpoch[MAX_THREADS];
set<ADDRINT>::iterator	WrittenWordsIterator[MAX_THREADS];

map<ADDRINT, int> WrittenBackInThisEpoch[MAX_THREADS];
map<ADDRINT, int>::iterator WrittenBackIterator[MAX_THREADS];


//	Global Variable Vector
//	State definition
//	00 means unloaded state
//	01 means valid state
//	10 means stale state
vector<struct GlobalVariableStruct>	GlobalVariableVec;
vector<struct GlobalVariableStruct>::iterator	GlobalVariableVecIterator;

//	This is not enough for tracking many lock variables.
//	For only checking single lock variable, MutexLocked is used.
int			MutexLocked[MAX_THREADS];
void*			MutexLock[MAX_THREADS];
BOOL			DuringBarrierFunc[MAX_THREADS];
BOOL			DuringCondFunc[MAX_THREADS];

//list<ADDRINT>	WrittenWordsInThisLock[MAX_THREADS];
set<ADDRINT>	WrittenWordsInThisLock[MAX_THREADS];
map<ADDRINT, int> WrittenBackInThisLock[MAX_THREADS];




//-------------------------------------------------------------------
//	Global Functions
//-------------------------------------------------------------------

void AnalyzeWritebacksAcrossThreads();
void AnalyzeBarrierRegion(int tid);
void CheckBarrierResultBefore(THREADID tid);
void CheckBarrierResultBeforeGOMPImplicit();


//	Check if given address is for global variable
BOOL isGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return true;
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return true;
	}
	return false;
}

BOOL isAllocatedGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			if ((*it).allocSize != 0)
				return true;
	}
	return false;
}


//	Calculate the base within global variable
//	The address should be for global variable. If not, -1 will be returned.
ADDRINT baseOfGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return (*it).addr;
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return (*it).addr;
	}
	// This must not happen.
	return -1;
}


//	Calculate the offset within global variable
//	The address should be for global variable. If not, -1 will be returned.
ADDRINT offsetInGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return 0;
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return (addr - (*it).addr);
	}
	// This must not happen.
	return -1;
}


//bitset<MAX_STATES>* bitVectorForGlobalVariable(ADDRINT addr)
struct WordStatus* wordStatusForGlobalVariable(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return &((*it).pState[0]);
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return &((*it).pState[(addr-(*it).addr) / WORD_BYTES]);
	}

	Logger.error("No match in wordStatusForGlobalVariable (end or overrun) addr = 0x%lx", addr);
	Logger.error("List of global variables");
	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		Logger.error("addr=0x%lx, size=%d", (*it).addr, (*it).size);
	}

	return NULL;
}


const char* getGlobalVariableName(ADDRINT addr)
{
	vector<struct GlobalVariableStruct>::iterator	it;

	for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
	{
		if ((*it).addr == addr)
			return (*it).name.c_str();
		if ( (addr >= (*it).addr) && (addr < (*it).addr + (*it).size) )
			return (*it).name.c_str();
	}

	Logger.error("No match in getGlobalVariableName (end or overrun) addr = 0x%lx", addr);
	return NULL;
}


//-------------------------------------------------------------------
//	Functions for Instruction Instrumentation
//-------------------------------------------------------------------

//	Generic Function Call Tracker
VOID FuncBefore(THREADID tid, CHAR *name, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s is called. (%s in %s)\n", tid, name, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncArg1IntBefore(THREADID tid, CHAR *name, INT arg1, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s with arg %d is called. (%s in %s)\n", tid, name, arg1, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncArg1AddrBefore(THREADID tid, CHAR *name, ADDRINT arg1, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s with arg 0x%lx is called. (%s in %s)\n", tid, name, arg1, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncArg2IntIntBefore(THREADID tid, CHAR *name, INT arg1, INT arg2, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s with arg %d, %d is called. (%s in %s)\n", tid, name, arg1, arg2, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncArg2AddrIntBefore(THREADID tid, CHAR *name, ADDRINT arg1, INT arg2, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] func %s with arg 0x%lx, %d is called. (%s in %s)\n", tid, name, arg1, arg2, rtnName, secName);
	ReleaseLock(&Lock);
}


VOID FuncAfter(THREADID tid, CHAR *name)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d]   func %s is returned.\n", tid, name);
	ReleaseLock(&Lock);
}


VOID FuncRetIntAfter(THREADID tid, CHAR *name, INT ret)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d]   func %s with return value %d is returned.\n", tid, name, ret);
	ReleaseLock(&Lock);
}


VOID FuncRetAddrAfter(THREADID tid, CHAR *name, ADDRINT ret)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d]   func %s with return value 0x%lx is returned.\n", tid, name, ret);
	ReleaseLock(&Lock);
}


//	Special Function Call Tracker
//	This is used for main function.
VOID SpecialBefore(THREADID tid, CHAR *name, CHAR *rtnName, CHAR *secName)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] *** %s is called. (%s in %s)\n", tid, name, rtnName, secName);
	MainRunning = true;
	ReleaseLock(&Lock);
}


VOID SpecialAfter(THREADID tid, CHAR *name, INT ret)
{
	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] *** %s with return value %d is returned.\n", tid, name, ret);
	MainRunning = false;
	ReleaseLock(&Lock);
}


//	Wrappers for Memory Allocation
VOID* vallocWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int size)
{
	VOID *ret;
	CONTEXT writableContext, * context = ctxt;

	/*
	if (TimeForRegChange()) {
		PIN_SaveContext(ctxt, &writableContext); // need to copy the ctxt into a writable context
		context = & writableContext;
		PIN_SetContextReg(context , REG_GAX, 1);
	}
	*/

	PIN_CallApplicationFunction(context, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		//	PIN_PARG(VOID *), v,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] valloc with size 0x%x returns 0x%lx.\n", tid, size, (ADDRINT) ret);

	// if return value is NULL, valloc failed. address is not tracked, then.
	if (ret != NULL)
		MATracker.add((ADDRINT) ret, size, tid);
	else
		Logger.warn("[tid: %d] valloc failed.", tid);
	AfterAlloc[tid] = true;
	
	ReleaseLock(&Lock);
	return ret;
}


VOID* mallocWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int size)
{
	VOID *ret;

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		//	PIN_PARG(VOID *), v,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] malloc with size 0x%x returns 0x%lx.", tid, size, (ADDRINT) ret);

	// if return value is NULL, malloc failed. address is not tracked, then.
	if (ret != NULL)
		MATracker.add((ADDRINT) ret, size, tid);
	else
		Logger.warn("[tid: %d] malloc failed.", tid);
	AfterAlloc[tid] = true;
	
	ReleaseLock(&Lock);
	return ret;
}


VOID* callocWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int nmeb, int size)
{
	VOID *ret;

	Logger.warn("[tid: %d] calloc is called with nmeb %d and size %d, but wrapper function for calloc is not verified yet.", tid, nmeb, size);
	// calloc writes values, so write to this memory area should be added.

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		//	PIN_PARG(VOID *), v,
		PIN_PARG(int), nmeb,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] calloc with nmeb %d, size %d returns 0x%lx\n", tid, nmeb, size, (ADDRINT) ret);

	// [TODO] This is not verified.
	// calloc allocates the memory as nmeb*size, however memory alignment should be considered.
	// if return value is NULL, valloc failed. address is not tracked, then.
	if (ret != NULL)
		MATracker.add((ADDRINT) ret, nmeb*size, tid);
	else
		Logger.warn("[tid: %d] calloc failed.", tid);
	AfterAlloc[tid] = true;

	ReleaseLock(&Lock);
	return ret;
}


VOID* reallocWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID *ptr, int size)
{
	VOID *ret;

	Logger.warn("[tid: %d] realloc is called for 0x%p, but not supported completely for now.", tid, ptr);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), ptr,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] realloc with ptr 0x%p, size %d returns 0x%lx\n", tid, ptr, size, (ADDRINT) ret);

	// if return value is NULL, realloc failed. address is not tracked, then.
	if (ret != NULL) {

		// if ptr is null, realloc is the same as malloc.
		// even if ptr is null, we have safety in AddrMap, so remove is called.
		MATracker.remove((ADDRINT) ptr);
		// if the size is 0, it is equal to free(ptr).
		if (size > 0)
			MATracker.add((ADDRINT) ret, size, tid);
	}
	else
		Logger.warn("[tid: %d] realloc failed.", tid);
	AfterAlloc[tid] = true;

	ReleaseLock(&Lock);
	return ret;
}



VOID* posix_memalignWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int size)
{
	VOID *ret;

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		//	PIN_PARG(VOID *), v,
		PIN_PARG(int), size,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] posix_memalign with size 0x%x returns 0x%lx\n", tid, size, (ADDRINT) ret);

	// if return value is NULL, posix_memalign failed. address is not tracked, then.
	if (ret != NULL)
		MATracker.add((ADDRINT) ret, size, tid);
	else
		Logger.warn("[tid: %d] posix_memalign failed.", tid);
	AfterAlloc[tid] = true;
	
	ReleaseLock(&Lock);
	return ret;
}


VOID* freeWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID *ptr)
{
	VOID *ret;

	/* 
	// for debug
	GetLock(&Lock, tid+1);
	fprintf(Trace, "[tid: %d] before free with ptr %p.\n", tid, ptr);
	fflush(Trace);
	ReleaseLock(&Lock);
	*/
	//Logger.log("[tid: %d] free is called for %p, but not removed from allocation tracker for now.", tid, ptr);
	
	// eagerly removed allocated objects before free call.
	// because it is observed that during free time, some wierd writes appeared to the freeing memory region.
	/*
	// removing from MATracker is not executed for now. 
	// When memory is freed, written result loses where to find its source.
	// for FFT, this happens with -p4 options, resuling in overrun of MATracker with pthread related area.
	if (MainRunning) {
		if ((MasterThreadOnlyAllocFree && (tid == 0)) || !MasterThreadOnlyAllocFree) {
			GetLock(&Lock, tid+1);
			MATracker.remove((ADDRINT) ptr);
			ReleaseLock(&Lock);
		}
	}
	*/

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), ptr,
		PIN_PARG_END());

	// If main function is not started, ignore allocation in MATracker for simplicity.
	if (!MainRunning)
		return ret;

	// If we assume only main thread can create globally shared variables,
	// we can ignore child threads behavior.
	// Child threads can appear after main function, so this order is correct.
	if (MasterThreadOnlyAllocFree)
		if (tid > 0)
			return ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] free with ptr 0x%p returns.\n", tid, ptr);

	// remove call is moved forward to prevent some wierd writes during free() call.
	MATracker.remove((ADDRINT) ptr);
	ReleaseLock(&Lock);

	return ret;
}




VOID* barrierInitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar, VOID* some, int num)
{
	VOID *ret;

	BarrierNumber = num;
	DuringBarrierFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,
		PIN_PARG(VOID *), bar,
		PIN_PARG(VOID *), some,
		PIN_PARG(int), num,
		PIN_PARG_END());
	DuringBarrierFunc[tid] = false;

	return ret;
}


VOID* barrierWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Executing barrier wrapper", tid);

	CheckBarrierResultBefore(tid);
	DuringBarrierFunc[tid] = true;
	ReleaseLock(&Lock);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), bar, 
		PIN_PARG_END());

	DuringBarrierFunc[tid] = false;
	return ret;
}


VOID* threadCreateWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4)
{
	VOID *ret;


	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Creating thread wrapper", tid);
	ReleaseLock(&Lock);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,
		PIN_PARG(VOID *), arg1,
		PIN_PARG(VOID *), arg2,
		PIN_PARG(VOID *), arg3,
		PIN_PARG(VOID *), arg4,
		PIN_PARG_END());

	return ret;
}


VOID* threadJoinWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* arg1, VOID* arg2)
{
	VOID *ret;


	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Joining thread wrapper", tid);
	ReleaseLock(&Lock);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,
		PIN_PARG(VOID *), arg1,
		PIN_PARG(VOID *), arg2,
		PIN_PARG_END());

	return ret;
}


VOID* gompBarrierWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar)
{
	VOID *ret;


	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Executing GOMP barrier wrapper", tid);
	CheckBarrierResultBefore(tid);
	ReleaseLock(&Lock);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), bar, 
		PIN_PARG_END());

	return ret;
}


VOID* omp_set_num_threads_Wrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, int num)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] OpenMP number of threads is set to %d.\n", tid, num);
	BarrierNumber = num;
	ReleaseLock(&Lock);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret,		// void
		PIN_PARG(int), num,
		PIN_PARG_END());

	return ret;
}


VOID* gomp_fini_work_share_Wrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* bar)
{
	VOID *ret;


	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] Executing gomp_fini_work_share wrapper", tid);
	CheckBarrierResultBeforeGOMPImplicit();
	ReleaseLock(&Lock);
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 	// void
		PIN_PARG(VOID *), bar, 		// struct gomp_work_share *
		PIN_PARG_END());

	return ret;
}


VOID* lockInitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* mutex, VOID* attr)
{
	VOID *ret;

	MutexLocked[tid] = DuringLockFunc;
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG(VOID *), attr, 
		PIN_PARG_END());

	MutexLocked[tid] = Unlocked;
	return ret;
}


VOID* lockWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* mutex)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	if (MutexLocked[tid] == Locked) {
		Logger.error("[tid: %d] nested lock is detected", tid);
	}
	MutexLocked[tid] = DuringLockFunc;
	ReleaseLock(&Lock);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	MutexLocked[tid] = Locked;
	MutexLock[tid] = mutex;
	Logger.log("[tid: %d] Lock 0x%x", tid, mutex);
	ReleaseLock(&Lock);

	return ret;
}



void AnalyzeCriticalSection(int tid) 
{
	// Report if allocated memory is written but not written back.

	// source code reference for memory allocation is removed.
	//struct sourceLocation* sl;
	string s2;
	vector<struct GlobalVariableStruct>::iterator	it;
	//list<ADDRINT>::iterator	wit;
	set<ADDRINT>::iterator	wit;

	Logger.log("[tid: %d] *** Analyzing unwritten-back writes in the critical section", tid);
	for (wit = WrittenWordsInThisLock[tid].begin(); wit != WrittenWordsInThisLock[tid].end(); wit++)
	{
		// check global variable
		BOOL done = false;
		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
		{
			if ( (*wit >= (*it).addr) &&
				 (*wit < (*it).addr + (*it).size) ) {
				Logger.warn("0x%lx for %s (offset 0x%lx) is not written back.", *wit, (*it).name.c_str(), (int) (*wit - (*it).addr));
				done = true;
				break;
			}
		}
		if (done)
			continue;

		// check allocated memory
		s2 = MATracker.getVariableName(*wit);
		ADDRINT	allocAddr;
		int	allocSize;

		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++) 
		{
			if (s2 == (*it).name) {
				allocAddr = (*it).allocAddr;
				allocSize = (*it).allocSize;
				Logger.warn("0x%lx, allocated in %s (0x%lx, offset 0x%lx, size 0x%lx), is not written back.", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), allocSize);
				break;
			}
		}

			
		/*
		sl = MATracker.getSource(*WrittenWordsIterator[i]);
		if (sl != NULL) {
			printf("variable is allocated in col: %d line: %d, filename: %s\n", sl->col, sl->line, sl->filename.c_str());
		}
		else
			Logger.warn("variable source is null\n");
			//printf("sl is null\n");
		*/
	}
	Logger.log("[tid: %d] *** Analysis for writeback is done.", tid);
}




VOID* unlockWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* mutex)
{
	VOID *ret;

	// Another checking routine is required.
	//LockBarrierResultBefore(tid);
	GetLock(&Lock, tid+1);
	MutexLocked[tid] = DuringLockFunc;
	ReleaseLock(&Lock);

	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	//AnalyzeCriticalSection(tid);
	WrittenWordsInThisLock[tid].clear();
	MutexLocked[tid] = Unlocked;
	MutexLock[tid] = 0;
	Logger.log("[tid: %d] Unlock 0x%x, segment: %d", tid, mutex, SegmentCount[tid]);
	//SegmentCount[tid]++;
	ReleaseLock(&Lock);
	return ret;
}



VOID* condInitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond, VOID* attr)
{
	VOID *ret;

	DuringCondFunc[tid] = true;
	
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG(VOID *), attr, 
		PIN_PARG_END());

	DuringCondFunc[tid] = false;
	return ret;
}


VOID* condWaitWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond, VOID* mutex)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] before cond_wait 0x%x", tid, cond);
	ReleaseLock(&Lock);

	DuringCondFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	Logger.log("[tid: %d] cond_wait 0x%x, segment %d", tid, cond, SegmentCount[tid]);
	SegmentCount[tid]++;
	Ordering.whenWaitIsDone(tid, SegmentCount[tid], cond);
	ReleaseLock(&Lock);

	return ret;
}


VOID* condWaitNullWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond, VOID* mutex)
{
	VOID *ret;

	GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] before cond_wait_null 0x%x", tid, cond);
	ReleaseLock(&Lock);
	DuringCondFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG(VOID *), mutex, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	Logger.log("[tid: %d] cond_wait_null 0x%x, segment %d", tid, cond, SegmentCount[tid]);
	SegmentCount[tid]++;
	Ordering.whenWaitIsDone(tid, SegmentCount[tid], cond);
	ReleaseLock(&Lock);

	return ret;
}



VOID* condSignalWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond)
{
	VOID *ret;

	DuringCondFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG_END());

	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	Logger.log("[tid: %d] cond_signal 0x%x, segment %d", tid, cond, SegmentCount[tid]);
	Ordering.whenSignal(tid, SegmentCount[tid], cond);
	SegmentCount[tid]++;
	ReleaseLock(&Lock);

	return ret;
}


VOID* condBroadcastWrapper(CONTEXT *ctxt, AFUNPTR orig_function, THREADID tid, VOID* cond)
{
	VOID *ret;

	DuringCondFunc[tid] = true;
	PIN_CallApplicationFunction(ctxt, PIN_ThreadId(),
		CALLINGSTD_DEFAULT, orig_function,
		PIN_PARG(VOID *), &ret, 
		PIN_PARG(VOID *), cond, 
		PIN_PARG_END());

	
	GetLock(&Lock, tid+1);
	DuringCondFunc[tid] = false;
	Logger.log("[tid: %d] cond_broadcast 0x%x, segment %d", tid, cond, SegmentCount[tid]);
	Ordering.whenSignal(tid, SegmentCount[tid], cond);
	SegmentCount[tid]++;
	ReleaseLock(&Lock);

	return ret;
}



//-------------------------------------------------------------------
//	Image Instrumentation
//-------------------------------------------------------------------

VOID ImageLoad(IMG img, VOID *v)
{
	RTN rtn;

	// tracking main function
	// when main function is started, MainRunning is set true.
	rtn = RTN_FindByName(img, "main");
	if (RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)SpecialBefore,
			IARG_THREAD_ID,
			IARG_ADDRINT, "main",
			IARG_ADDRINT, RTN_Name(rtn).c_str(),
			IARG_ADDRINT, SEC_Name(RTN_Sec(rtn)).c_str(),
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)SpecialAfter, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "main",
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
		RTN_Close(rtn);
	}

/*
	// This function call tracker works at entry point, but may not work at exit point.
	// Since Pin does not guarantee function exit point tracing,
	// if this is used, some valloc return value is missing.
	//
	// Current solution is to make function wrapper for valloc.

	// The same can be applied to malloc, calloc, realloc, and free.
	// malloc has the same interface.
	// calloc gets two arguments, so IARG_FUNCARG_ENTRYPOINT_VALUE, 1 is required.
	// FuncArg2IntIntBefore is used at IPOINT_BEFORE.
	// realloc gets two arguments with address and size. FuncArg2AddrIntBefore is required.
	// free gets address as an argument. FuncArg1AddrBefore is used.

	rtn = RTN_FindByName(img, "valloc");
	if (RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FuncArg1IntBefore, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "valloc", 
			// The following two work as an alternative to entry point value.
			//IARG_G_ARG0_CALLEE,
			//IARG_FUNCARG_CALLSITE_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_ADDRINT, RTN_Name(rtn).c_str(),
			IARG_ADDRINT, SEC_Name(RTN_Sec(rtn)).c_str(),
			// At this moment, we do not care about image name.
			// IARG_ADDRINT, IMG_Name(SEC_Img(RTN_Sec(mallocRtn))).c_str(),
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FuncRetAddrAfter, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "valloc",
			// The following works instead of exit point.
			// But, IARG_G_RESULT0 is deprecated.
			// IARG_G_RESULT0,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
		RTN_Close(rtn);
	}
*/

/*
	// To find caller function at callee site, this is written for test.
	rtn = RTN_FindByName(img, "malloc");
	if (RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FuncArg1IntBefore, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "malloc", 
			// The following two work as an alternative to entry point value.
			//IARG_G_ARG0_CALLEE,
			//IARG_FUNCARG_CALLSITE_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_ADDRINT, RTN_Name(rtn).c_str(),
			IARG_ADDRINT, SEC_Name(RTN_Sec(rtn)).c_str(),
			// At this moment, we do not care about image name.
			//IARG_ADDRINT, IMG_Name(SEC_Img(RTN_Sec(mallocRtn))).c_str(),
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)FuncRetAddrAfter, 
			IARG_THREAD_ID,
			IARG_ADDRINT, "malloc",
			// The following works instead of exit point.
			// But, IARG_G_RESULT0 is deprecated.
			// IARG_G_RESULT0,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
		RTN_Close(rtn);
	}
*/

	// wrappers for memory allocation/deallocation functions
	// valloc in pthread, malloc, calloc, realloc, free
	rtn = RTN_FindByName(img, "valloc_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"valloc", PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(vallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	// malloc is used for many libraries which are executed by default.
	// To track our interested variables only, malloc_pmc is used in the application code.
	rtn = RTN_FindByName(img, "malloc_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"malloc", PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(mallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z10malloc_pmcm");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"malloc", PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(mallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_END);
	}


	rtn = RTN_FindByName(img, "calloc_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"calloc", PIN_PARG(int), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(callocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z10calloc_pmcmm");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"calloc", PIN_PARG(int), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(callocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}


	rtn = RTN_FindByName(img, "realloc_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"realloc", PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(reallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z11realloc_pmcPvm");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"realloc", PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(reallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_END);
	}


	rtn = RTN_FindByName(img, "posix_memalign_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"posix_memalign", PIN_PARG(VOID **), PIN_PARG(int), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(reallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z18posix_memalign_pmcPPVmm");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"posix_memalign", PIN_PARG(VOID **), PIN_PARG(int), PIN_PARG(int), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(reallocWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
			IARG_END);
	}

	// more candidates: alloca, _alloca

	rtn = RTN_FindByName(img, "free_pmc");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"free", PIN_PARG(VOID *), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(freeWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
	}

	rtn = RTN_FindByName(img, "_Z8free_pmcPv");
	if (RTN_Valid(rtn)) {
		PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
						"free", PIN_PARG(VOID *), PIN_PARG_END() );
		RTN_ReplaceSignature(rtn, AFUNPTR(freeWrapper), 
			IARG_PROTOTYPE, proto,
			IARG_CONST_CONTEXT,
			IARG_ORIG_FUNCPTR,
			IARG_THREAD_ID,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_END);
	}


	if (Category == PTHREAD) {
		// pthread_barrier_init
		rtn = RTN_FindByName(img, "pthread_barrier_init");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_barrier_init", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(barrierInitWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

		// pthread_barrier_wait
		rtn = RTN_FindByName(img, "pthread_barrier_wait");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_barrier_wait", PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(barrierWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		}

		/*
		// pthread_create
		rtn = RTN_FindByName(img, "pthread_create");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_create", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(threadCreateWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
				IARG_END);
		}

		// pthread_join
		rtn = RTN_FindByName(img, "pthread_join");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_join", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(threadJoinWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				IARG_END);
		}
		*/

		
		// pthread_mutex_init		
		rtn = RTN_FindByName(img, "pthread_mutex_init");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_mutex_init", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(lockInitWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
		
		// pthread_mutex_lock		
		rtn = RTN_FindByName(img, "pthread_mutex_lock");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_mutex_lock", PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(lockWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
		
		// pthread_mutex_unlock
		rtn = RTN_FindByName(img, "pthread_mutex_unlock");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_mutex_unlock", PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(unlockWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

		// pthread_cond_init
		rtn = RTN_FindByName(img, "pthread_cond_init");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_init", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condInitWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
			
		// pthread_cond_wait
		rtn = RTN_FindByName(img, "pthread_cond_wait");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_wait", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condWaitWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

		// pthread_cond_wait_null
		rtn = RTN_FindByName(img, "pthread_cond_wait_null");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_wait_null", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condWaitNullWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}

		rtn = RTN_FindByName(img, "_Z22pthread_cond_wait_nullPvS_");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_wait_null", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condWaitNullWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
		// pthread_cond_signal
		rtn = RTN_FindByName(img, "pthread_cond_signal");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_signal", PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condSignalWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
			
		// pthread_cond_broadcat
		rtn = RTN_FindByName(img, "pthread_cond_broadcast");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"pthread_cond_broadcast", PIN_PARG(VOID *), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(condBroadcastWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				//IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
				IARG_END);
		}
			
			
		
		
	}
	else if (Category == OPENMP) {

		// omp_set_num_threads
		rtn = RTN_FindByName(img, "omp_set_num_threads");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"omp_set_num_threads", PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(omp_set_num_threads_Wrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		}


		// GOMP_barrier for OpenMP
		rtn = RTN_FindByName(img, "GOMP_barrier");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"GOMP_barrier", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(gompBarrierWrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		}

		// gomp_fini_work_share for OpenMP
		rtn = RTN_FindByName(img, "gomp_fini_work_share");
		if (RTN_Valid(rtn)) {
			PROTO proto = PROTO_Allocate( PIN_PARG(VOID *), CALLINGSTD_DEFAULT,
							"gomp_fini_work_share", PIN_PARG(VOID *), PIN_PARG(VOID *), PIN_PARG(int), PIN_PARG_END() );
			RTN_ReplaceSignature(rtn, AFUNPTR(gomp_fini_work_share_Wrapper),
				IARG_PROTOTYPE, proto,
				IARG_CONST_CONTEXT,
				IARG_ORIG_FUNCPTR,
				IARG_THREAD_ID,
				IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
				IARG_END);
		}
	}
	else if (Category == GTHREAD) {
		// nothing is implemented yet.
		// for g_thread_create_full, g_thread_exit, g_thread_join
		// no barrier is implemented in gthread.
	}


}	// void ImageLoad



//-------------------------------------------------------------------
//	Functions for Routine Instrumentation
//-------------------------------------------------------------------

void AnalyzeBarrierRegion(int tid) 
{
	// Report if allocated memory is written but not written back.

	// source code reference for memory allocation is removed.
	//struct sourceLocation* sl;
	string s2;
	vector<struct GlobalVariableStruct>::iterator	it;
	//list<ADDRINT>::iterator	wit;
	set<ADDRINT>::iterator	wit;

	Logger.log("[tid: %d] *** Analyzing unwritten-back writes", tid);
	for (wit = WrittenWordsInThisEpoch[tid].begin(); wit != WrittenWordsInThisEpoch[tid].end(); wit++)
	{
		// check global variable
		BOOL done = false;
		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
		{
			if ( (*wit >= (*it).addr) &&
				 (*wit < (*it).addr + (*it).size) ) {
				Logger.warn("0x%lx for %s (offset %d) is not written back.", *wit, (*it).name.c_str(), (int) (*wit - (*it).addr));
				done = true;
				break;
			}
		}
		if (done)
			continue;

		// check allocated memory
		s2 = MATracker.getVariableName(*wit);
		ADDRINT	allocAddr;
		int	allocSize;

		for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++) 
		{
			if (s2 == (*it).name) {
				allocAddr = (*it).allocAddr;
				allocSize = (*it).allocSize;
				Logger.warn("0x%lx, allocated in %s (0x%lx, offset %d, size %lx), is not written back.", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), allocSize);
				break;
			}
		}

			
		/*
		sl = MATracker.getSource(*WrittenWordsIterator[i]);
		if (sl != NULL) {
			printf("variable is allocated in col: %d line: %d, filename: %s\n", sl->col, sl->line, sl->filename.c_str());
		}
		else
			Logger.warn("variable source is null\n");
			//printf("sl is null\n");
		*/
	}
	Logger.log("[tid: %d] *** Analysis for writeback is done.", tid);
}


void AnalyzeWritebacksAcrossThreads()
{
	Logger.log("*** Analyzing writebacks in the epoch across threads");

	map<ADDRINT, int>::iterator wbit, wbit2;

	for (int i = 0; i < NumThreads; i++)
	{
		for (wbit = WrittenBackInThisEpoch[i].begin(); wbit != WrittenBackInThisEpoch[i].end(); wbit++)
		{
			for (int j = i+1; j < NumThreads; j++)
			{
				for (wbit2 = WrittenBackInThisEpoch[j].begin(); wbit2 != WrittenBackInThisEpoch[j].end(); wbit2++)
				{
					if ( ((*wbit).first + (*wbit).second) < (*wbit2).first )
						// writeback address of comprison is bigger than original address
						break;
					
					if ( (*wbit).first < ((*wbit2).first + (*wbit2).second) ) {
						if ( ((*wbit).first + (*wbit).second) > (*wbit2).first ) {
							Logger.error("tid: %d and tid: %d makes conflict in writeback", i, j);
							Logger.error("addr range (0x%lx, %x), (0x%lx, %x)", (*wbit).first, (*wbit).second, (*wbit2).first, (*wbit2).second);
						}
					}
				}	// writeback traversal for tid j
			}	// for j
		}	// writeback traversal for tid i
	}	// for i

	for (int i = 0; i < NumThreads; i++)
		WrittenBackInThisEpoch[i].clear();

	Logger.log("*** Analysis for writebacks across threads is done.");
}


void CheckBarrierResult(THREADID tid, int ret)
{
	// The reference manual of Pin tool says return value has ADDRINT type,
	// but it does not make sense. With unsigned type, ret is recognized as FFFF for -1.
	// Thus, ret is declared as int.

	GetLock(&Lock, tid+1);
	//printf("[LOG] [tid: %d] returned pthread_barrier_wait with %d\n", tid, ret);

	// phase proceeding in each thread
	//LC[tid].phase++;

	if (ret == 0) {
		// meaning tid-th thread arrives at the barrier

		// writeback is checked for this epoch.
		Logger.log("tid: %d has reached to barrier %d", tid, BarrierCount);
		AnalyzeBarrierRegion(tid);
		WrittenWordsInThisEpoch[tid].clear();
	}
	else if (ret == -1) {
		// meaning if (ret == PTHREAD_BARRIER_SERIAL_THREAD)
		// If return value is -1, the last coming thread
		//StatsCounter::allNextPhase();		
		Logger.log("tid: %d has reached to barrier %d", tid, BarrierCount);
		AnalyzeBarrierRegion(tid);
		Logger.log("Barrier region %d ended.", BarrierCount);
		AnalyzeWritebacksAcrossThreads();
		BarrierCount++;
		Logger.log("***********************");
	}

	ReleaseLock(&Lock);
}


void CheckBarrierResultBefore(THREADID tid)
{
	//GetLock(&Lock, tid+1);
	Logger.log("[tid: %d] reached to barrier %d", tid, BarrierCount);

	// phase proceeding in each thread
	//LC[tid].phase++;

	//AnalyzeBarrierRegion(tid);
	//WrittenWordsInThisEpoch[tid].clear();

	//if (++CurrentBarrierArrival == NumThreads - 1) {
	if (++CurrentBarrierArrival == BarrierNumber) {
		// Because we do not count main thread, NumThreads - 1 is used.

		// [DRD] reset all word status

		for (GlobalVariableVecIterator = GlobalVariableVec.begin();
			GlobalVariableVecIterator != GlobalVariableVec.end();
			++GlobalVariableVecIterator)
		{
			int i, j;
			for (i = 0, j = 0; j < (*GlobalVariableVecIterator).size; i++, j += WORD_SIZE) 
			{
				(*GlobalVariableVecIterator).pState[i].state = 0;
				(*GlobalVariableVecIterator).pState[i].proc = 9999;
				(*GlobalVariableVecIterator).pState[i].segment = 0;
				(*GlobalVariableVecIterator).pState[i].lock = 0;
			}
		}
		MATracker.clear();
		Ordering.clear();

		Logger.log("*** Epoch %d ended ***\n\n", BarrierCount);
		BarrierCount++;
		CurrentBarrierArrival = 0;
		for (int i = 0; i < MAX_THREADS; i++) 
			SegmentCount[i] = 0;
	}

	//Logger.log("[tid: %d] reached out of barrier %d", tid, BarrierCount);
	//ReleaseLock(&Lock);
}

void CheckBarrierResultBeforeGOMPImplicit()
{
	Logger.log("Reached to GOMP implicit barrier %d", BarrierCount);

	// phase proceeding in each thread
	//LC[tid].phase++;

	for (int i = 0; i < BarrierNumber; i++) 
		AnalyzeBarrierRegion(i);
	for (int i = 0; i < BarrierNumber; i++) 
		WrittenWordsInThisEpoch[i].clear();

	// For OpenMP, this function is called only by master thread.
	// [TODO] This is not sure if it is okay to call writeback across threads test now.
	AnalyzeWritebacksAcrossThreads();
	Logger.log("*** Epoch %d ended ***\n\n", BarrierCount);
	BarrierCount++;
}



/*
//	This is replaced with ImageLoad.
void VallocBefore(THREADID tid)
{
	GetLock(&Lock, tid+1);
	fprintf(Trace, "[tid: %d] valloc starts\n", tid);
	fflush(Trace);
	ReleaseLock(&Lock);
}


void VallocAfter(THREADID tid, int ret)
{
	GetLock(&Lock, tid+1);
	fprintf(Trace, "[tid: %d]   valloc returns with %d\n", tid, ret);
	fflush(Trace);
	ReleaseLock(&Lock);
}
*/


void lockWrapperBefore(THREADID tid)
{
	MutexLocked[tid] = Locked;
	Logger.log("[tid: %d] Lock at routine", tid);
}


void unlockWrapperBefore(THREADID tid)
{
	MutexLocked[tid] = Unlocked;
	Logger.log("[tid: %d] Unlock at routine", tid);
}


//-------------------------------------------------------------------
//	Routine Instrumentation
//-------------------------------------------------------------------
VOID Routine(RTN rtn, VOID *v)
{
	string s = RTN_Name(rtn);

	RTN_Open(rtn);

	// pthread_barrier_wait is contained in libpthread.so.0 when dynamically linked.
	// main segment can have this function when statically linked.
	// Current SPLASH-2 kernels with static linking have pthread_barrier_wait as a separate function.
	// IPOINT_AFTER may not recognize the end of the function, but for pthread_barrier_wait,
	// it seems to be working.

	/*
	if (s == "pthread_barrier_wait")
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) CheckBarrierResult,
			IARG_THREAD_ID,
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
	*/

	/*
	//	Instead of check barrier result after the function call, before the function call is preferred here.
	//	When pthread_barrier_wait returns -1, it does not mean all other threads are waiting for this thread.
	//	Other threads can proceed, so analysis cannot make the correct result in this case.
	if (s == "pthread_barrier_wait")
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) CheckBarrierResultBefore,
			IARG_THREAD_ID,
			IARG_END);
	*/

	// pmcthread_barrier_wait is made for very correct result.
	if (s == "pmcthread_barrier_wait")
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) CheckBarrierResultBefore,
			IARG_THREAD_ID,
			IARG_END);


/*
	// This routine has a problem in exit point.
	// Pin does not guarantee every exit point is captured with this routine.
	// In addition, valloc can appear as extended name such as __libc_valloc.
	// 
	// Current solution is to make function wrapper for valloc.
	if (s == "valloc" || s == "__libc_valloc") {
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) VallocBefore,
			IARG_THREAD_ID,
			IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR) VallocAfter,
			IARG_THREAD_ID, 
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
	}
*/
/*
	char *c = (char *) s.c_str();

	//if (s == "pthread_mutex_lock")
	if (strstr(c, "pthread_mutex_lock")) {
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) lockWrapperBefore,
			IARG_THREAD_ID,
			IARG_END);
	}

	if (strstr(c, "pthread_mutex_unlock")) {
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR) unlockWrapperBefore,
			IARG_THREAD_ID,
			IARG_END);
	}
*/
	RTN_Close(rtn);
}



//-------------------------------------------------------------------
//	Functions for Instruction Instrumentation
//-------------------------------------------------------------------

VOID ReadsMemBefore (ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressRead, UINT32 memoryReadSize)
{
	ADDRINT startWordAddress;
	//, endWordAddress, startOffset;
	//ADDRINT offsetMask = 0x3;

	// Before main running, we do not track read/write access.
	if (!MainRunning)
		return;

	if (DuringBarrierFunc[tid] == true)
		return;
	if (DuringCondFunc[tid] == true)
		return;
	if (MutexLocked[tid] == DuringLockFunc)
		return;

	// Source code tracing
	INT32	col, line;
	string	filename;
	PIN_LockClient();
	PIN_GetSourceLocation(applicationIp, &col, &line, &filename);
	PIN_UnlockClient();

	GetLock(&Lock, tid+1);

	bool	inAlloc = MATracker.contain(memoryAddressRead);
	bool	inGlobal = isGlobalVariable(memoryAddressRead);


	if (inAlloc || inGlobal) {
		// File trace is disabled for now.
		//fprintf(Trace, "[tid: %d] %d Read address = 0x%lx\n", tid, BarrierCount, memoryAddressRead);
		//fflush(Trace);
		NumReads[tid].count++;
		//ReleaseLock(&Lock);

		if (MutexLocked[tid] == Locked) {
			Logger.temp("[tid: %d] epoch: %d Locked / Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);
			// if (inGlobal) 
			//Logger.log("[tid: %d] epoch: %d Locked / Read address = 0x%lx from %s", 
			//	tid, BarrierCount, memoryAddressRead, getGlobalVariableName(memoryAddressRead));
			//else
			//Logger.log("[tid: %d] epoch: %d Locked / Read address = 0x%lx from %s (alloc)", 
			//	tid, BarrierCount, memoryAddressRead, MATracker.getVariableName(memoryAddressRead).c_str());
		}
		else {
			Logger.temp("[tid: %d] epoch: %d Read address = 0x%lx", tid, BarrierCount, memoryAddressRead);
			//if (inGlobal
			//Logger.log("[tid: %d] epoch: %d Read address = 0x%lx from %s",
			//	tid, BarrierCount, memoryAddressRead, getGlobalVariableName(memoryAddressRead));
			//else
			//Logger.log("[tid: %d] epoch: %d Read address = 0x%lx from %s (alloc)", 
			//	tid, BarrierCount, memoryAddressRead, MATracker.getVariableName(memoryAddressRead).c_str());
		}


		startWordAddress = memoryAddressRead & ADDR_MASK;
		//endWordAddress = (memoryAddressRead + memoryReadSize) & ADDR_MASK;
		//startOffset = memoryAddressRead & offsetMask;

		for (ADDRINT a = startWordAddress; a < memoryAddressRead + memoryReadSize; a += WORD_BYTES)
		{
			struct WordStatus *pStatus;
			if (inGlobal)
				pStatus = wordStatusForGlobalVariable(a);
			else
				pStatus = MATracker.wordStatus(a);
			Logger.log("[tid: %d] before Ordering.established in read", tid);
			int prevSeg = -1;
			if (pStatus->proc != 9999)
				prevSeg = Ordering.established(pStatus->proc, tid);
			Logger.log("[tid: %d] after Ordering.established in read", tid);

			switch (pStatus->state) {
			case 0: // virgin
				if (MutexLocked[tid] == Locked)
					pStatus->state = 5;
				else
					pStatus->state = 1;
				pStatus->proc = tid;
				pStatus->epoch = BarrierCount;
				pStatus->segment = SegmentCount[tid];
				pStatus->lock = MutexLock[tid];

				pStatus->src.col = col;
				pStatus->src.line = line;
				pStatus->src.filename = filename;
				break;

			case 1: // read
				if (MutexLocked[tid] == Locked) {
					if (pStatus->epoch < BarrierCount) {
						// no warning
						// because of epoch ordering
					}
					else if (prevSeg >= pStatus->segment) {
						// no warning
						// because of segment ordering
					}
					else {
						Logger.warn("[tid: %d] Locked read for previoulsy non-locked (on rd state): addr 0x%lx", tid, a);
						if (inGlobal)
							Logger.warn("variable %s offset %d(0x%lx)", 
							getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						else
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("previously read by %d in location: col %d line %d file %s", 
						pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
						Logger.warn("read by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
					}
		
					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}


				if (tid != pStatus->proc) {
					if (pStatus->epoch < BarrierCount) {
						pStatus->state = 1;	// stay
					}
					else if (prevSeg >= pStatus->segment) {
						pStatus->state = 1;	// stay because there is ordering between prev read and current read.
					}
					else
						pStatus->state = 3;	// no ordering

					pStatus->proc = tid;
				}

				// if tid is the same, stay at the same state.
				pStatus->epoch = BarrierCount;
				pStatus->segment = SegmentCount[tid];
				pStatus->lock = MutexLock[tid];	

				pStatus->src.col = col;
				pStatus->src.line = line;
				pStatus->src.filename = filename;
				break;

			case 2: // write
				if (MutexLocked[tid] == Locked) {
					if (pStatus->epoch < BarrierCount) {
						// no warning
					}
					//else if (Ordering.established(pStatus->segment, SegmentCount[tid]) > -1)
					else if (prevSeg >= pStatus->segment) {
						// segment ordering
					}
					// temporarily commented
					else {
						Logger.warn("[tid: %d] Locked read for previoulsy non-locked (on wr state): addr 0x%lx", tid, a);
						if (inGlobal) 
							Logger.warn("variable %s offset %d(0x%lx)", 
							getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						else
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("previously written by %d in location: col %d line %d file %s", 
						pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
						Logger.warn("read by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
					}
		
					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}


				if (tid != pStatus->proc) {
					if (pStatus->epoch < BarrierCount)
						break;
					if (prevSeg >= pStatus->segment)
						// ordering.
						// but stay at write state with previous info.
						// maintain 'write' col, line, filename for future use.
						break;
					// [FIXME] this has problems.

					// no ordering, thus a data race.
					Logger.warn("[tid: %d] going to racy due to unlocked read (on wr state): addr 0x%lx", tid, a);
					if (inGlobal)
						Logger.warn("variable %s offset %d(0x%lx)", 
						getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
					else
						Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
						MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
					Logger.warn("previously written by %d in epoch %d segment %d \n\tat location: col %d line %d file %s", 
					pStatus->proc, pStatus->epoch, pStatus->segment, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
					Logger.warn("read by %d in epoch %d segment %d \n\tat location: col %d line %d file %s", 
					tid, BarrierCount, SegmentCount[tid], col, line, filename.c_str());

					pStatus->state = 4;
					// maintain all other information for future race detection.
					// proc, segment, lock, src
				}

				// if read by the written thread,
				// stay at the same state, and no information is updated.
				break;
			
			case 3: // shared read
				/*
				if (MutexLocked[tid] == Locked) {
					Logger.warn("[tid: %d] Locked read for previoulsy non-locked (on shared rd state): addr 0x%lx", tid, a);
					Logger.warn("%s (alloc) offset %d(0x%lx)", 
					MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
					Logger.warn("previously read by %d in location: col %d line %d file %s", 
					pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
					Logger.warn("read by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
		
					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}
				*/

				pStatus->proc = tid;
				//pStatus->lock = MutexLock[tid];
				pStatus->epoch = BarrierCount;
				pStatus->segment = SegmentCount[tid];

				pStatus->src.col = col;
				pStatus->src.line = line;
				pStatus->src.filename = filename;
				break;

			case 4: // racy
				if (MutexLocked[tid] == Locked) {
					Logger.warn("[tid: %d] Locked read for previoulsy non-locked (on racy state): addr 0x%lx", tid, a);
					if (inGlobal)
						Logger.warn("variable %s offset %d(0x%lx)", 
						getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
					else
						Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
						MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
					Logger.warn("previously written by %d in epoch %d segment %d \n\tat location: col %d line %d file %s", 
					pStatus->proc, pStatus->epoch, pStatus->segment, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
					Logger.warn("read by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());

					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}

				// otherwise, once entered into racy state, it does not exit.
				break;

			case 5: // locked
	
				if (MutexLocked[tid] == Unlocked) {
					if (pStatus->epoch < BarrierCount) {
						// no warning
					}
					//else if (Ordering.established(pStatus->segment, SegmentCount[tid]) > -1)
					else if (prevSeg >= pStatus->segment) {
						// segment ordering
					}
					// temporarily commented
					else {
						Logger.warn("[tid: %d] Unlocked read for previoulsy locked (on locked state): addr 0x%lx", tid, a);
						if (inGlobal)
							Logger.warn("variable %s offset %d(0x%lx)", 
							getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						else
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("previously locked by %d in location: col %d line %d file %s", 
						pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
						Logger.warn("read by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
					}
		
					pStatus->state = 1;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}

				/*
				if (MutexLock[tid] != pStatus->lock) {
					Logger.warn("[tid: %d] Locked read for previoulsy non-locked (on shared rd state): addr 0x%lx", tid, a);
					Logger.warn("%s (alloc) offset %d(0x%lx)", 
					getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
					Logger.warn("previously read by %d in location: col %d line %d file %s", 
					pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
					Logger.warn("read by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
		
					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}
				*/

				pStatus->state = 5;
				pStatus->proc = tid;
				pStatus->epoch = BarrierCount;
				pStatus->segment = SegmentCount[tid];
				pStatus->lock = MutexLock[tid];

				pStatus->src.col = col;
				pStatus->src.line = line;
				pStatus->src.filename = filename;
				break;
			}



			/*
			We are now not interested in coherent states.

			// invalidation test
			if ( (* (MATracker.bitVector(a)) )[tid*2] == 1) {
				if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 1) {
					// means 'need invalidation'
					Logger.error("[tid: %d] read without invalidation: addr=0x%lx, %s (offset %ld 0x%lx)", tid, a, MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
				}
				// '10' means write valid. So, no action.
			}
			else if ( (* (MATracker.bitVector(a)) )[tid*2+1] == 0) {
				// means currently invalid state
				Logger.temp("read at unloaded state");
				(* (MATracker.bitVector(a)) )[tid*2+1] = 1;	// changed to read valid state
			}
			*/
		}	// end for
	}
	ReleaseLock(&Lock);
}


VOID WritesMemBefore(ADDRINT applicationIp, THREADID tid, ADDRINT memoryAddressWrite, UINT32 memoryWriteSize)
{
	ADDRINT startWordAddress;
	//, endWordAddress, startOffset;
	//ADDRINT offsetMask = 0x3;

	// Before main running, we do not track read/write access.
	if (!MainRunning)
		return;

	// During pthread synchronization functions, we disable read/write tracking.
	if (DuringBarrierFunc[tid] == true)
		return;
	if (DuringCondFunc[tid] == true)
		return;
	if (MutexLocked[tid] == DuringLockFunc)
		return;

	// Source code tracing
	INT32	col, line;
	string	filename;
	PIN_LockClient();
	PIN_GetSourceLocation(applicationIp, &col, &line, &filename);
	PIN_UnlockClient();


	GetLock(&Lock, tid+1);
	bool	inAlloc = MATracker.contain(memoryAddressWrite);
	bool	inGlobal = isGlobalVariable(memoryAddressWrite);

	if (inAlloc || inGlobal) {
		//GetLock(&Lock, tid+1);
		//fprintf(Trace, "[tid: %d] %d Write address = 0x%lx\n", tid, BarrierCount, memoryAddressWrite);
		//fflush(Trace);
		NumWrites[tid].count++;
		//ReleaseLock(&Lock);

		if (MutexLocked[tid] == Locked) {
			Logger.temp("[tid: %d] epoch: %d Locked / Write address = 0x%lx", tid, BarrierCount, memoryAddressWrite);
			//if (inGlobal)
			//Logger.log("[tid: %d] epoch: %d Locked / Write address = 0x%lx to %s (alloc)",
			//	tid, BarrierCount, memoryAddressWrite, MATracker.getVariableName(memoryAddressWrite).c_str());
			//else
			//Logger.log("[tid: %d] epoch: %d Locked / Write address = 0x%lx to %s",
			//	tid, BarrierCount, memoryAddressWrite, getGlobalVariableName(memoryAddressWrite));
		}
		else {
			Logger.temp("[tid: %d] epoch: %d Write address = 0x%lx", tid, BarrierCount, memoryAddressWrite);
			//if (inGlobal)
			//Logger.log("[tid: %d] epoch:%d Write address = 0x%lx to %s",
			//	tid, BarrierCount, memoryAddressWrite, getGlobalVariableName(memoryAddressWrite));
			//else
			//Logger.log("[tid: %d] epoch: %d Write address = 0x%lx to %s (alloc)",
			//	tid, BarrierCount, memoryAddressWrite, MATracker.getVariableName(memoryAddressWrite).c_str());
		}

		startWordAddress = memoryAddressWrite & ADDR_MASK;
		//endWordAddress = (memoryAddressWrite + memoryWriteSize) & ADDR_MASK;
		//startOffset = memoryAddressWrite & offsetMask;

		for (ADDRINT a = startWordAddress; a < memoryAddressWrite + memoryWriteSize; a += WORD_SIZE)
		{
			struct WordStatus *pStatus;
			if (inGlobal)
				pStatus = wordStatusForGlobalVariable(a);
			else
				pStatus = MATracker.wordStatus(a);
			Logger.log("[tid: %d] before Ordering.established in write", tid);
			int prevSeg = -1;
			if (pStatus->proc != 9999)
				prevSeg = Ordering.established(pStatus->proc, tid);
			Logger.log("[tid: %d] after Ordering.established in write", tid);

			switch (pStatus->state) {
			case 0: // virgin
				if (MutexLocked[tid] == Locked)
					pStatus->state = 5;
				else
					pStatus->state = 2;
				pStatus->proc = tid;
				pStatus->epoch = BarrierCount;
				pStatus->segment = SegmentCount[tid];
				pStatus->lock = MutexLock[tid];

				pStatus->src.col = col;
				pStatus->src.line = line;
				pStatus->src.filename = filename;
				break;

			case 1: // read
				if (MutexLocked[tid] == Locked) {
					if (pStatus->epoch < BarrierCount) {
						// no warning
						// because of epoch ordering
					}
					else if (prevSeg >= pStatus->segment) {
						// no warning
						// because of segment ordering
					}
					else {
						Logger.warn("[tid: %d] Locked write for previoulsy non-locked (on rd state): addr 0x%lx", tid, a);
						if (inGlobal)
							Logger.warn("variable %s offset %d(0x%lx)", 
							getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						else
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("previously read by tid %d in location: col %d line %d file %s", 
						pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
						Logger.warn("written by tid %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
					}
		
					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}

				if (tid != pStatus->proc) {
					if (pStatus->epoch < BarrierCount) {
						pStatus->state = 1;	// stay
					}
					else if (prevSeg >= pStatus->segment) {
						pStatus->state = 2;	// go to write state because there is ordering between prev read and current write.
					}
					else {
						pStatus->state = 4;	// no ordering, so racy

						Logger.warn("[tid: %d] going to racy due to unlocked write (on rdr state): addr 0x%lx", tid, a);
						if (inGlobal)
							Logger.warn("variable %s offset %d(0x%lx)", 
							getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						else
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("previously read by %d in epoch %d segment %d \n\tat location: col %d line %d file %s", 
						pStatus->proc, pStatus->epoch, pStatus->segment, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
						Logger.warn("written by %d in epoch %d segment %d \n\tat location: col %d line %d file %s", 
						tid, BarrierCount, SegmentCount[tid], col, line, filename.c_str());
					}
					pStatus->proc = tid;
				}
				else {
					pStatus->state = 2;		// if same tid, go to write state
				}

				pStatus->epoch = BarrierCount;
				pStatus->segment = SegmentCount[tid];
				pStatus->lock = MutexLock[tid];	

				pStatus->src.col = col;
				pStatus->src.line = line;
				pStatus->src.filename = filename;
				break;


			case 2: // write
				if (MutexLocked[tid] == Locked) {
					if (pStatus->epoch < BarrierCount) {
						// no warning
					}
					else if (prevSeg >= pStatus->segment) {
						// segment ordering
					}
					else {
						Logger.warn("[tid: %d] Locked write for previoulsy non-locked (on wr state): addr 0x%lx", tid, a);
						if (inGlobal)
							Logger.warn("variable %s offset %d(0x%lx)", 
							getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						else
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("previously written by %d in location: col %d line %d file %s", 
						pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
						Logger.warn("written by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
					}
		
					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}

				if (tid != pStatus->proc) {
					if (pStatus->epoch < BarrierCount) {
						// ordering.
						pStatus->proc = tid;
						pStatus->epoch = BarrierCount;
						pStatus->segment = SegmentCount[tid];
						pStatus->lock = MutexLock[tid];

						pStatus->src.col = col;
						pStatus->src.line = line;
						pStatus->src.filename = filename;
						break;
					}
					if (prevSeg >= pStatus->segment) {
						// ordering.
						pStatus->proc = tid;
						pStatus->epoch = BarrierCount;
						pStatus->segment = SegmentCount[tid];
						pStatus->lock = MutexLock[tid];

						pStatus->src.col = col;
						pStatus->src.line = line;
						pStatus->src.filename = filename;
						break;
					}

					// no ordering, thus a data race.
					Logger.warn("[tid: %d] going to racy due to unlocked write (on wr state): addr 0x%lx", tid, a);
					if (inGlobal)
						Logger.warn("variable %s offset %d(0x%lx)", 
						getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
					else
						Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
						MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
					Logger.warn("previously written by %d in location: col %d line %d file %s", 
					pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
					Logger.warn("write by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());

					pStatus->state = 4;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}
				else {
					// if tid is the same,
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}

			
			case 3: // shared read
				if (MutexLocked[tid] == Locked) {
					if (pStatus->epoch < BarrierCount) {
						// no warning
					}
					//else if (Ordering.established(pStatus->segment, SegmentCount[tid]) > -1)
					else if (prevSeg >= pStatus->segment) {
						// segment ordering
					}
					else {
						Logger.warn("[tid: %d] Locked write for previoulsy non-locked (on shared rd state): addr 0x%lx", tid, a);
						if (inGlobal) 
							Logger.warn("variable %s offset %d(0x%lx)", 
							getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						else
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("previously read by %d in epoch %d, segment %d\n\tat location: col %d line %d file %s", 
						pStatus->proc, pStatus->epoch, pStatus->segment, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
						Logger.warn("write by %d in epoch %d, segment %d\n\tat location: col %d line %d file %s", 
						tid, BarrierCount, SegmentCount[tid], col, line, filename.c_str());
					}
		
					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}


				if (tid != pStatus->proc) {
					if (pStatus->epoch < BarrierCount) {
						// no warning
						pStatus->state = 2;
						pStatus->proc = tid;
						pStatus->epoch = BarrierCount;
						pStatus->segment = SegmentCount[tid];
						pStatus->lock = MutexLock[tid];
				
						pStatus->src.col = col;
						pStatus->src.line = line;
						pStatus->src.filename = filename;
						break;
					}
					else if (prevSeg >= pStatus->segment) {
						pStatus->state = 2;
						pStatus->proc = tid;
						pStatus->epoch = BarrierCount;
						pStatus->segment = SegmentCount[tid];
						pStatus->lock = MutexLock[tid];
				
						pStatus->src.col = col;
						pStatus->src.line = line;
						pStatus->src.filename = filename;
						break;
					}

					Logger.warn("[tid: %d] going to racy due to Unlocked write (on shared rd state): addr 0x%lx", tid, a);
					if (inGlobal)
						Logger.warn("variable %s offset %d(0x%lx)", 
						getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
					else
						Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
						MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
					Logger.warn("previously read by %d in epoch %d segment %d\n\tat location: col %d line %d file %s", 
					pStatus->proc, pStatus->epoch, pStatus->segment, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
					Logger.warn("write by %d in epoch %d segment %d\n\tat location: col %d line %d file %s", 
					tid, BarrierCount, SegmentCount[tid], col, line, filename.c_str());

					pStatus->state = 4;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];
				
					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
				}
				else {
					pStatus->state = 2;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];
				
					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
				}
				break;


			case 4: // racy
				if (MutexLocked[tid] == Locked) {
					Logger.warn("[tid: %d] Locked write for previoulsy non-locked (on racy state): addr 0x%lx", tid, a);
					if (inGlobal)
						Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
						getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
					else
						Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
						MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
					Logger.warn("previously written by %d in location: col %d line %d file %s", 
					pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
					Logger.warn("write by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());

					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}

				// otherwise, once entered into racy state, it does not exit.
				break;

			case 5: // locked
				if (MutexLocked[tid] == Unlocked) {
					if (tid == pStatus->proc) {
						// if the same processor, we do not handle this case as an error.
					}
					else {
						Logger.warn("[tid: %d] Unlocked write for previoulsy locked (on locked state): addr 0x%lx", tid, a);
						if (inGlobal)
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
						else
							Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
							MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
						Logger.warn("previously read/write by %d in location: col %d line %d file %s", 
						pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
						Logger.warn("write by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
					}


					pStatus->state = 1;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}

				if (MutexLock[tid] != pStatus->lock) {
					Logger.warn("[tid: %d] Locked write but different lock (on locked state): addr 0x%lx", tid, a);
					Logger.warn("previous= 0x%lx, now= 0x%lx", pStatus->lock, MutexLock[tid]);
					if (inGlobal)
						Logger.warn("variable %s offset %d(0x%lx)", 
						getGlobalVariableName(a), offsetInGlobalVariable(a), offsetInGlobalVariable(a));
					else
						Logger.warn("variable %s (alloc) offset %d(0x%lx)", 
						MATracker.getVariableName(a).c_str(), MATracker.getOffset(a), MATracker.getOffset(a));
					Logger.warn("previously read/write by %d in location: col %d line %d file %s", 
					pStatus->proc, pStatus->src.col, pStatus->src.line, pStatus->src.filename.c_str());
					Logger.warn("write by %d in location: col %d line %d file %s", tid, col, line, filename.c_str());
		
					pStatus->state = 5;
					pStatus->proc = tid;
					pStatus->epoch = BarrierCount;
					pStatus->segment = SegmentCount[tid];
					pStatus->lock = MutexLock[tid];

					pStatus->src.col = col;
					pStatus->src.line = line;
					pStatus->src.filename = filename;
					break;
				}

				pStatus->state = 5;
				pStatus->proc = tid;
				pStatus->epoch = BarrierCount;
				pStatus->segment = SegmentCount[tid];
				pStatus->lock = MutexLock[tid];

				pStatus->src.col = col;
				pStatus->src.line = line;
				pStatus->src.filename = filename;
				break;

			}

		}

	}

	if (AfterAlloc[tid]) {
		// Standard library malloc returns pointer to the variable in rax.
		// So, I guess the first write instruction with rax after malloc call has the pointer assignment.
		//
		// Currently checking if this instruction is for malloc statement is ugly.
		// [TODO] Find the better way without string comparison
		// printf("%s\n", DisAssemblyMap[applicationIp].c_str());
        char instr[100];
		int  len;
		strcpy(instr, DisAssemblyMap[applicationIp].c_str());
		len = strlen(instr);
		#ifdef __64BIT__
		if (strstr(DisAssemblyMap[applicationIp].c_str(), "rax")) {
		#else
		//if (strstr(DisAssemblyMap[applicationIp].c_str(), "eax")) {
		//if (strstr(instr, "eax")) {
		if ((instr[len-3] == 'e') && (instr[len-2] == 'a') && (instr[len-1] == 'x')) {
		#endif
			Logger.log("[tid: %d] afterAlloc %s", tid, instr);
			Logger.log("[tid: %d] Memory allocation was done in location: col %d line %d file %s", tid, col, line, filename.c_str());
			MATracker.addSource(col, line, filename, tid);

			// Global variable tracing
			int done = -1;
			
			for (GlobalVariableVecIterator = GlobalVariableVec.begin(); GlobalVariableVecIterator != GlobalVariableVec.end(); GlobalVariableVecIterator++)
			{
				if ((*GlobalVariableVecIterator).addr == memoryAddressWrite) {
					MATracker.addVariableName((*GlobalVariableVecIterator).name, 0, tid);
					(*GlobalVariableVecIterator).allocAddr = MATracker.prevAddr[tid];
					(*GlobalVariableVecIterator).allocSize = MATracker.prevSize[tid];
					//(*GlobalVariableVecIterator).attachState();
					MATracker.addVariableName((*GlobalVariableVecIterator).name, 0, tid);
					Logger.log("allocation is passed to %s offset 0.\n", (*GlobalVariableVecIterator).name.c_str());
					done = 1;
				}
				else if ( ((*GlobalVariableVecIterator).addr < memoryAddressWrite) &&
					(memoryAddressWrite < (*GlobalVariableVecIterator).addr + (*GlobalVariableVecIterator).size) ) {
					//int offset = ((*GlobalVariableVecIterator).addr + (*GlobalVariableVecIterator).size - memoryAddressWrite);
					int offset = memoryAddressWrite - (*GlobalVariableVecIterator).addr;
					MATracker.addVariableName((*GlobalVariableVecIterator).name, offset, tid);
					Logger.log("allocation is passed to %s offset %d.\n", (*GlobalVariableVecIterator).name.c_str(), offset);
					done = 2;
				}
			}
			

			// Allocated memory tracing
			if (done == -1) {
				if (MATracker.contain(memoryAddressWrite)) {
					if ((memoryAddressWrite >= MATracker.prevAddr[tid]) &&
					    (memoryAddressWrite < MATracker.prevAddr[tid] + MATracker.prevSize[tid])) {
						Logger.log("self allocation: 0x%x into 0x%x, 0x%x\n", 
						memoryAddressWrite, MATracker.getBase(memoryAddressWrite), MATracker.getOffset(memoryAddressWrite));
						string s = MATracker.getVariableName(memoryAddressWrite);
						string s2 = "self-allocated " + s;
						ADDRINT offset = MATracker.getOffset(memoryAddressWrite);
						MATracker.addVariableName(s2, offset, tid);
					}
					else {				
						string s = MATracker.getVariableName(memoryAddressWrite);
						string s2 = "allocated " + s;
						ADDRINT offset = MATracker.getOffset(memoryAddressWrite);
						MATracker.addVariableName(s2, offset, tid);
						Logger.log("allocation is done for %s offset %d.", s2.c_str(), offset);
						Logger.log("0x%x, 0x%x\n", MATracker.getBase(memoryAddressWrite), offset);
						done = 3;
					}
				}
			}

			if (done == -1) {
				Logger.log("allocation is done, but not found in global variable or allocated address for 0x%x.", memoryAddressWrite);
				Logger.log("[tid: %d] Memory allocation was done in location: col %d line %d file %s", tid, col, line, filename.c_str());
				for (GlobalVariableVecIterator = GlobalVariableVec.begin(); GlobalVariableVecIterator != GlobalVariableVec.end(); GlobalVariableVecIterator++) 
				{
					Logger.debug("%s: 0x%x size %d", (*GlobalVariableVecIterator).name.c_str(),
						(*GlobalVariableVecIterator).addr, (*GlobalVariableVecIterator).size);
				}
				string s = "unknown ";
				MATracker.addVariableName(s, MATracker.prevAddr[tid], tid);
			}
			AfterAlloc[tid] = false;
		}
	}
	ReleaseLock(&Lock);
}	// void WritesMemBefore



//-------------------------------------------------------------------
//	Instruction Instrumentation
//-------------------------------------------------------------------

VOID Instruction(INS ins, void * v)
{
	// Finally, we will target parall worker threads only, which has threadid > 0.
	// This requires SESC to equip processor 0 with ideal memory, and instrumenting function drops its job in case of threadid 0.
	// At this moment, instrumentation targets all threads including main thread.

	//UINT32 tid = PIN_ThreadId();
	//GetLock(&Lock, tid+1);
	UINT32 memOperands = INS_MemoryOperandCount(ins);
	// Checker functions
	// if (memOperands > 1)
	//	printf("multi: %lx: %d: %s\n", INS_Address(ins), memOperands, INS_Disassemble(ins).c_str());
	// if (INS_IsAtomicUpdate(ins))
	//	printf("atomic %lx: %d: %s\n", INS_Address(ins), memOperands, INS_Disassemble(ins).c_str());


	// Iterate over each memory operand of the instruction
	for (UINT32 memOp = 0; memOp < memOperands; memOp++) 
	{
		DisAssemblyMap[INS_Address(ins)] = INS_Disassemble(ins);
		//AllMemInstructions.inc();
		//printf("INS_Address(ins) = 0x%lx\n", INS_Address(ins));

		// INS_InsertPredicatedCall is identical to INS_InsertCall except predicated instructions.
		// Predicated instructions are CMOVcc, FCMOVcc and REPped string ops.


		if (INS_MemoryOperandIsRead(ins, memOp)) {
			// read operation

			// jmp, call, ret do read, but these are for control flow.
			// More data cache related, not our concern.			
			if (!(INS_IsBranch(ins) || INS_IsCall(ins) || INS_IsRet(ins)))
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) ReadsMemBefore,
					IARG_INST_PTR,
					IARG_THREAD_ID,
					IARG_MEMORYOP_EA, memOp,
					IARG_MEMORYREAD_SIZE,
					IARG_END);
			
		}


		if (INS_MemoryOperandIsWritten(ins, memOp)) {
			// write operation

			// call instruction does write, but this is for control flow, not our concern.			
			if (!INS_IsCall(ins))
				INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) WritesMemBefore,
					IARG_INST_PTR,// application IP
					IARG_THREAD_ID, 
					IARG_MEMORYOP_EA, memOp,
					IARG_MEMORYWRITE_SIZE,
					IARG_END);
			
		}

	}	// end of for loop, memOp
	//ReleaseLock(&Lock);
}	// void Instruction



//-------------------------------------------------------------------
//	Thread Tracker
//-------------------------------------------------------------------

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *V)
{	
	int i;
	GetLock(&Lock, tid+1);

	Logger.log("[tid: %d] *** thread is started.\n", tid);

	// MaxThreads
	NumThreads++;
	if (MaxThreads < NumThreads)
		MaxThreads = NumThreads;
	
	if (NumThreads == 2) {
		// if first thread spawning, we need to check current writeback status.

		for (i = 0; i < MAX_THREADS; i++) {
			WrittenWordsInAnEpoch[i].push_back(WrittenWordsInThisEpoch[i]);
			ReadWordsInAnEpoch[i].push_back(ReadWordsInThisEpoch[i]);
		}

		//AnalyzeBarrierRegion(0);
		for (i = 0; i < MAX_THREADS; i++) {
			WrittenWordsInThisEpoch[i].clear();
			ReadWordsInThisEpoch[i].clear();
		}

		// [DRD] reset all word status

		for (GlobalVariableVecIterator = GlobalVariableVec.begin();
			GlobalVariableVecIterator != GlobalVariableVec.end();
			++GlobalVariableVecIterator)
		{
			int i, j;
			for (i = 0, j = 0; j < (*GlobalVariableVecIterator).size; i++, j += WORD_SIZE) 
			{
				(*GlobalVariableVecIterator).pState[i].state = 0;
				(*GlobalVariableVecIterator).pState[i].proc = 9999;
				(*GlobalVariableVecIterator).pState[i].segment = 0;
				(*GlobalVariableVecIterator).pState[i].lock = 0;
			}
		}
		MATracker.clear();
		Ordering.clear();


		Logger.log("*** Epoch %d ended ***\n", BarrierCount);
		BarrierCount++;
		for (int i = 0; i < MAX_THREADS; i++) 
			SegmentCount[i] = 0;
	}

	ReleaseLock(&Lock);
}


VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 flags, VOID *V)
{
	GetLock(&Lock, tid+1);
	
	Logger.log("[tid: %d] *** thread is finished.\n", tid);

	NumThreads--;

	//AnalyzeBarrierRegion(tid);
	WrittenWordsInThisEpoch[tid].clear();

	if (NumThreads == 1) {
		// [DRD] reset all word status

		for (GlobalVariableVecIterator = GlobalVariableVec.begin();
			GlobalVariableVecIterator != GlobalVariableVec.end();
			++GlobalVariableVecIterator)
		{
			int i, j;
			for (i = 0, j = 0; j < (*GlobalVariableVecIterator).size; i++, j += WORD_SIZE) 
			{
				(*GlobalVariableVecIterator).pState[i].state = 0;
				(*GlobalVariableVecIterator).pState[i].proc = 9999;
				(*GlobalVariableVecIterator).pState[i].lock = 0;
			}
		}
		MATracker.clear();
		Ordering.clear();

		Logger.log("*** Epoch %d ended ***\n", BarrierCount);
		BarrierCount++;
		for (int i = 0; i < MAX_THREADS; i++) 
			SegmentCount[i] = 0;
	}
	
	ReleaseLock(&Lock);
}



//-------------------------------------------------------------------
//	Finalize
//-------------------------------------------------------------------

VOID FinalAnalysis()
{
	Logger.log("\n\n *** Final Analysis ***\n");
	// Basic read/write info per thread
	for (int i = 0; i < MaxThreads; i++) {
		Logger.log("tid=%d, reads=%ld, writes=%ld\n", i, NumReads[i].count, NumWrites[i].count);
	}


	// Report if allocated memory is written but not written back.

	// source code reference for memory allocation is removed.
	//struct sourceLocation* sl;
	string s2;
	vector<struct GlobalVariableStruct>::iterator	it;
	//list<ADDRINT>::iterator	wit;
	set<ADDRINT>::iterator		wit;

	for (int i = 0; i < MaxThreads; i++) {
		Logger.log("In thread %d,\n", i);
		for (wit = WrittenWordsInThisEpoch[i].begin(); wit != WrittenWordsInThisEpoch[i].end(); wit++)
		{
			// check global variable
			BOOL done = false;
			for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++)
			{
				if ( (*wit >= (*it).addr) &&
					 (*wit < (*it).addr + (*it).size) ) {
					Logger.log("0x%lx for %s (offset %d) is not written back.\n", *wit, (*it).name.c_str(), (int) (*wit - (*it).addr));
					done = true;
					break;
				}
			}
			if (done)
				continue;

			// check allocated memory
			s2 = MATracker.getVariableName(*wit);
			ADDRINT	allocAddr;
			int	allocSize;

			for (it = GlobalVariableVec.begin(); it != GlobalVariableVec.end(); it++) 
			{
				if (s2 == (*it).name) {
					allocAddr = (*it).allocAddr;
					allocSize = (*it).allocSize;
					Logger.log("0x%lx, allocated in %s (0x%lx, offset %d, size %lx), is not written back.\n", *wit,  s2.c_str(), allocAddr, (int) (*wit - allocAddr), allocSize);
					break;
				}
			}

			
			/*
			sl = MATracker.getSource(*WrittenWordsIterator[i]);
			if (sl != NULL) {
				printf("variable is allocated in col: %d line: %d, filename: %s\n", sl->col, sl->line, sl->filename.c_str());
			}
			else
				Logger.warn("variable source is null\n");
				//printf("sl is null\n");
			*/

		}
	}
}	// void FinalAnalysis


VOID Fini(INT32 code, VOID *v)
{
	// Anything required for final analysis should be written here.
	// [FIXME] final analysis is commented out temporarilly.
	//FinalAnalysis();

	Logger.close();

	printf("\n\n# of threads were running: %d\n", MaxThreads);
	printf("# of barrier regions: %d\n", BarrierCount+1);
}



//-------------------------------------------------------------------
//	Print Usage
//-------------------------------------------------------------------

INT32 Usage()
{
	PIN_ERROR("Checker Tool for PMC Architecture\n\n" + KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}


//-------------------------------------------------------------------
//	Read Variable Info File
//-------------------------------------------------------------------

VOID ReadVariableInfo(char *filename)
{
	FILE		*fp;
	char		line[100];
	char		id[100];
	ADDRINT		addr;
	int			size;
	string		name;


	fp = fopen(filename, "r");
	if (fp == NULL) {
		Logger.error("file cannot be opened: %s", filename);
		return ;
	}
	while ( fgets(line, 100, fp) != NULL) {
		#ifdef __64BIT__
		sscanf(line, "%s %lx %x", id, &addr, &size);
		#else
		sscanf(line, "%s %x %x", id, &addr, &size);
		#endif
		if (ExcludePotentialSystemVariables) {
			if (id[0] == '.')
				continue;
			//if (id[0] == '_')
			//	continue;
			if (!strcmp("stdin", id) || !strcmp("stdout", id) || !strcmp("stderr", id))
				continue;
		}
		name = id;
		GlobalVariableVec.push_back(GlobalVariableStruct(name, addr, size, 0, 0));
	}		

	fclose(fp);
}



//-------------------------------------------------------------------
//	Read Configuration File
//-------------------------------------------------------------------

VOID ReadConfigurationFile(const char *filename)
{
	FILE		*fp;
	char		line[100];
	char		*str;


	fp = fopen(filename, "r");
	if (fp == NULL) {
		Logger.error("Config file cannot be opened: %s", filename);
		return ;
	}

	while ( fgets(line, 100, fp) != NULL) {
		str = strtok(line, "=\n\t ");
		if (str == NULL)
			continue;
		if (strlen(str) < 3)
			continue;

		if ((str[0] == '/') && (str[1] == '/'))	// comment
			continue;
		
		// Category
		if (!strcasecmp(str, "category")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "pthread")) {
				Category = PTHREAD;
			}
			else if (!strcasecmp(str, "openmp")) {
				Category = OPENMP;
			}
			else if (!strcasecmp(str, "gthread")) {
				Category = GTHREAD;
			}
		}

		// Display
		if (!strcasecmp(str, "display")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "none")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_NONE);
			}
			else if (!strcasecmp(str, "error")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_ERROR);
			}
			else if (!strcasecmp(str, "warning")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_WARNING);
			}
			else if (!strcasecmp(str, "log")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_LOG);
			}
			else if (!strcasecmp(str, "debug")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_DEBUG);
			}
			else if (!strcasecmp(str, "temp")) {
				Logger.setDisplayLevel(WindyLogger::DISPLAY_TEMP_DEBUG);
			}
		}

		if (!strcasecmp(str, "file")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "none")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_NONE);
			}
			else if (!strcasecmp(str, "error")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_ERROR);
			}
			else if (!strcasecmp(str, "warning")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_WARNING);
			}
			else if (!strcasecmp(str, "log")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_LOG);
			}
			else if (!strcasecmp(str, "debug")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_DEBUG);
			}
			else if (!strcasecmp(str, "temp")) {
				Logger.setFileoutLevel(WindyLogger::FILEOUT_TEMP_DEBUG);
			}
		}

		if (!strcasecmp(str, "suggestion")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				Suggestion = true;
			}
			else if (!strcasecmp(str, "false")) {
				Suggestion = false;
			}
		}

		if (!strcasecmp(str, "filename")) {
			str = strtok(NULL, "=\n\t ");
			strcpy(OutputFileName, str);
		}

		if (!strcasecmp(str, "max_worker_threads")) {
			str = strtok(NULL, "=\n\t ");
			MaxWorkerThreads = atoi(str);
		}

		if (!strcasecmp(str, "cache_line_size")) {
			str = strtok(NULL, "=\n\t ");
			CacheLineSize = atoi(str);
		}

		if (!strcasecmp(str, "global_variable_file")) {
			str = strtok(NULL, "=\n\t ");
			strcpy(VariableFileName, str);
		}

		if (!strcasecmp(str, "exclude_potential_system_variables")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				ExcludePotentialSystemVariables = true;
			}
			else if (!strcasecmp(str, "false")) {
				ExcludePotentialSystemVariables = false;
			}
		}	

		if (!strcasecmp(str, "tracking_after_main")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				AfterMainTracking = true;
			}
			else if (!strcasecmp(str, "false")) {
				AfterMainTracking = false;
			}
		}	

		if (!strcasecmp(str, "mem_alloc_function")) {
			str = strtok(NULL, "=\n\t ");
			printf("mem_alloc_function = %s\n", str);
		}

		if (!strcasecmp(str, "mem_dealloc_function")) {
			str = strtok(NULL, "=\n\t ");
			printf("mem_dealloc_function = %s\n", str);
		}

		if (!strcasecmp(str, "tracking_master_thread_only")) {
			str = strtok(NULL, "=\n\t ");
			if (!strcasecmp(str, "true")) {
				MasterThreadOnlyAllocFree = true;
			}
			else if (!strcasecmp(str, "false")) {
				MasterThreadOnlyAllocFree = false;
			}
		}	
	}

	fclose(fp);
}


//	key for accessing TLS storage in the threads. initialized once in main()
static  TLS_KEY tls_key;

//	function to access thread-specific data
thread_data_t* get_tls(THREADID threadid)
{
	thread_data_t* tdata =
		static_cast<thread_data_t*>(PIN_GetThreadData(tls_key, threadid));
	return tdata;
}



//-------------------------------------------------------------------
//	Main Function
//-------------------------------------------------------------------

int main(int argc, char * argv[]) 
{
	// Initialization
	// [TODO] Giving arguments through pin execution was not successful.
	// if possible, having an argument for configuration file name is desirable.
	PIN_InitSymbols();
	if (PIN_Init(argc, argv))
		return Usage();

	// initialization before configuration
	// These will be overwritten by configuration if there are corresponding configuration items in the file.
	Category = UNKNOWN;
	Suggestion = true;
	strcpy(OutputFileName, "drd.out");
	MaxWorkerThreads = 32;
	CacheLineSize = 64;
	strcpy(VariableFileName, "variable_info.txt");
	ExcludePotentialSystemVariables = true;
	AfterMainTracking = true;
	MainRunning = false;
	MasterThreadOnlyAllocFree = false;

	// Configuration file
	ReadConfigurationFile(configFileName);
	if (AfterMainTracking == true)
		MainRunning = false;
	else
		MainRunning = true;

	// file for log output
	OutputFile = fopen(OutputFileName, "w");
	Logger.setOutputFile(OutputFile);

	InitLock(&Lock);
	MaxThreads = 0;
	NumThreads = 0;
	CurrentBarrierArrival = 0;
	BarrierCount = 0;
	for (int i = 0; i < MAX_THREADS; i++) {
		NumReads[i].count = NumWrites[i].count = 0;
		AfterAlloc[i] = false;
		SegmentCount[i] = 0;
	}

	ReadVariableInfo(VariableFileName);
	Logger.log("*** Global Variable List starts");
	for (GlobalVariableVecIterator = GlobalVariableVec.begin(); GlobalVariableVecIterator != GlobalVariableVec.end(); GlobalVariableVecIterator++) 
	{
		Logger.log("%s: addr=0x%lx, len=0x%x", (*GlobalVariableVecIterator).name.c_str(), (*GlobalVariableVecIterator).addr, (*GlobalVariableVecIterator).size);
	}
	Logger.log("*** Global Variable List ends\n");


	// Instrumentation
	// At image level,
	IMG_AddInstrumentFunction(ImageLoad, 0);

	// At routine level,
	//RTN_AddInstrumentFunction(Routine, 0);

	// At instruction level,
	INS_AddInstrumentFunction(Instruction, 0);

	// Add special functions
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();		// this never returns
	return 0;
}

