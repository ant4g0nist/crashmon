//
//  crashmon.h
//  crashmon
//
//  Created by ant4g0nist on 01/11/2021.
//

#ifndef crashmon_h
#define crashmon_h

#include "lldb/API/LLDB.h"

struct m1Wrangler
{
    char current_case[1024];
    lldb::pid_t pid;
    lldb::SBTarget target;
    lldb::SBDebugger debugger;
};

struct CrashDetails
{
    int code;
    uint64_t address;
    char exception[256];
    char code_m[256];
};

struct m1Wrangler * m1WranglerInit(int argc, const char * argv[], char* envp[]);
void m1WranglerDestroy(struct m1Wrangler* wrangler);
bool analyseThread(lldb::SBProcess process, lldb::SBThread thread);
void dumpFunctionTrail(lldb::SBThread thread, uint32_t depth);

#endif /* crashmon_h */
