//
//  crashmon.mm
//  crashmon
//
//  Created by ant4g0nist on 01/11/2021.
//

#import <unistd.h>
#import <ptrauth.h>
#import <sys/signal.h>
#include <mach-o/dyld.h>
#import <lldb/API/LLDB.h>
#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import "config.h"
#import "crashmon.h"
#import "tracer.h"
#import "helpers.h"

extern char **environ;
const char* arch        = "arm64-apple-macosx11.1.0";
const char* platform    = "host";

using namespace lldb;

NSString* sha256HashFor(NSString* input)
{
    const char* str = [input UTF8String];
    unsigned char result[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(str, strlen(str), result);
    
    NSMutableString *ret = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH*2];
    for(int i = 0; i<CC_SHA256_DIGEST_LENGTH; i++)
    {
        [ret appendFormat:@"%02x",result[i]];
    }
    
    return ret;
}

void copy_cwe_variables()
{
    char ** envp = environ;
    char * prefix = "CWE_";
    size_t prefix_len = strlen(prefix);
    char *equals, *env_name;
    while (*envp != NULL) {
        if (strncmp(*envp, prefix, prefix_len) == 0) {
            equals = strchr(*envp, '=');
            if (! equals) {
                fprintf(stderr, "Error: bad environment variable %s", *envp);
                exit(RET_ERROR);
            }
            env_name = strdup(*envp);
            if (! env_name) {
                perror("strndup");
                exit(RET_ERROR);
            }
            env_name[ (size_t)(equals-*envp) ] = 0;
            if (putenv(*envp + prefix_len) != 0) {
                perror("putenv");
                exit(RET_ERROR);
            }
            unsetenv(env_name);
            free(env_name);
            envp = environ;  //we have to restart since environ may have been relocated to grow.
        } else {
            envp++;
        }
    }
}

const char * stateAsCString(StateType state)
{
    const char * result = "<unknown>";
    
    switch (state) {
        case eStateInvalid:
            result = "eStateInvalid";
            break;
        
        case eStateUnloaded:
            result = "eStateUnloaded";
            break;
            
        case eStateConnected:
            result =  "eStateConnected";
            break;
            
        case eStateAttaching:
            result = "eStateAttaching";
            break;
            
        case eStateLaunching:
            result = "eStateLaunching";
            break;
            
        case eStateStopped:
            result = "eStateStopped";
            break;
            
        case eStateRunning:
            result = "eStateRunning";
            break;
            
        case eStateStepping:
            result = "eStateStepping";
            break;
            
        case eStateCrashed:
            result = "eStateCrashed";
            break;
            
        case eStateDetached:
            result = "eStateDetached";
            break;
            
        case eStateExited:
            result = "eStateExited";
            break;
            
        case eStateSuspended:
            result = "eStateSuspended";
            break;
    }
    
    return result;
}

bool ThreadHasStopReason(lldb::SBThread &thread) {
    bool result = false;
    switch (thread.GetStopReason())
    {
        case lldb::eStopReasonTrace:
        case lldb::eStopReasonPlanComplete:
        case lldb::eStopReasonBreakpoint:
        case lldb::eStopReasonWatchpoint:
        case lldb::eStopReasonInstrumentation:
        case lldb::eStopReasonSignal:
        case lldb::eStopReasonException:
        case lldb::eStopReasonExec:
            result  = true;
            break;
              
        case lldb::eStopReasonThreadExiting:
        case lldb::eStopReasonInvalid:
        case lldb::eStopReasonNone:
            break;
    }
    
    return result;
}

bool ThreadHasCrashReason(lldb::SBThread &thread) {
    bool result = false;
    switch (thread.GetStopReason())
    {
        case lldb::eStopReasonSignal:
        case lldb::eStopReasonException:
            result  = true;
            break;
            
        case lldb::eStopReasonTrace:
        case lldb::eStopReasonPlanComplete:
        case lldb::eStopReasonBreakpoint:
        case lldb::eStopReasonWatchpoint:
        case lldb::eStopReasonInstrumentation:
        case lldb::eStopReasonThreadExiting:
        case lldb::eStopReasonInvalid:
        case lldb::eStopReasonExec:
        case lldb::eStopReasonNone:
            break;
    }
    
    return result;
}

// returns thread index on exception/signal else -1
int checkIfCrash(SBProcess process)
{
    for( int i=0; i< process.GetNumThreads(); i++)
    {
        SBThread thread = process.GetThreadAtIndex(i);
        const bool has_reason = ThreadHasCrashReason(thread);
        if (has_reason)
        {
            return i;
        }
    }

    return -1;
}

const char* runCommandAndFetchOutput(lldb::SBCommandInterpreter interpreter, const char* cmd){
    
    lldb::SBCommandReturnObject result;
    interpreter.HandleCommand(cmd, result);
    const char *op = result.GetOutput();
    const char *er = result.GetError();
    if (result.IsValid())
        return op;
    
    debugn("error : %s, cmd: %s",er, cmd);
    return er;
}

// caller is responsible for calling m1WranglerDestroy
struct m1Wrangler * m1WranglerInit(int argc, const char * argv[], char* envp[])
{
    lldb::pid_t attach_pid = 0;
    struct m1Wrangler * wrangler = (struct m1Wrangler * )malloc(sizeof(struct m1Wrangler));
    
    uint32_t timeout = TIMEOUT;

    if(getenv("CW_TIMEOUT"))
    {
        timeout        = atoi(getenv("CW_TIMEOUT"));
    }

    NSLog(@"timeout: %d", timeout);
    char * attach_pid_str = getenv("CW_ATTACH_PID");
    char * current_case   = getenv("CW_CURRENT_CASE");
    NSData * current_case_data = [[NSData alloc] init];

    if (current_case)
    {
        strncpy(wrangler->current_case, current_case, strlen(current_case));
        current_case_data = [NSData dataWithContentsOfFile:[NSString stringWithUTF8String:current_case]];
    }
        
    if(attach_pid_str)
    {
        attach_pid = atoi(attach_pid_str);
        wrangler->pid = attach_pid;
    }

    char * log_dir = getenv("CW_LOG_DIR");
    if (! log_dir) {
        log_dir = DEFAULT_LOG_DIR;
    }    

    // Use a sentry object to properly initialize/terminate LLDB.
    SBDebugger::Initialize();
    
    SBDebugger debugger(SBDebugger::Create());
    SBCommandInterpreter command_interpreter = debugger.GetCommandInterpreter();
    debugger.SetAsync(false);
    
    if (!debugger.IsValid())
        die("Failed to create debugger!");

    wrangler->debugger = debugger;
    SBError error;
    SBTarget target = debugger.CreateTarget(argv[1], arch, platform, false, error);
    
    if (!error.Success())
    {
      die("error: %s\n", error.GetCString());
    }
    
    wrangler->target = target;
    
    SBFileSpec exe = target.GetExecutable();
    debugn("target: %s", exe.GetFilename());
    
    copy_cwe_variables();

    uint32_t launch_flags = eLaunchFlagDisableASLR|eLaunchFlagStopAtEntry;
    
    SBListener listener = SBListener("crashmon");
    SBLaunchInfo launch_info = target.GetLaunchInfo();
    
    launch_info.SetExecutableFile(exe, true);
    launch_info.SetArguments(&argv[2], true);
    launch_info.SetLaunchFlags(launch_flags);
    launch_info.SetListener(listener);
    launch_info.SetEnvironmentEntries((const char**)environ, false);

    SBProcess process;
    
    if(!attach_pid)
    {
        process = target.Launch(launch_info, error);
    }
    else
    {
        process = target.AttachToProcessWithID(listener, attach_pid, error);
    }
    if (!error.Success())
    {
        die("error: %s\n", error.GetCString());
    }
    
    debugn("Process pid: %lld", process.GetProcessID());
    NSString *processName = [[NSProcessInfo processInfo] processName];

    runCommandAndFetchOutput(command_interpreter, "command script import ~/lisa.py");        
    
    debugger.SetAsync(true);
    
    process.Continue();
    
    bool done = false;
    while (!done)
    {
        SBEvent event = SBEvent();
        if (listener.WaitForEvent(timeout, event))
        {
            StateType state = SBProcess::GetStateFromEvent(event);
            if (SBProcess::EventIsProcessEvent(event))
            {
                if (state==lldb::eStateStopped)
                {
                    int t = checkIfCrash(process);
                    if (t == -1)
                    {
                        process.Continue();
                    }
                    else
                    {
                        bool should_die = false;
                        for( int i=0; i< process.GetNumThreads(); i++)
                        {
                            SBThread thread = process.GetThreadAtIndex(i);
                            const bool has_reason = ThreadHasCrashReason(thread);
                            
                            if (has_reason)
                            {
                                wrangler->exit_status = 1;
                                write_crashlog(command_interpreter, process, thread, current_case, current_case_data, log_dir);
                                should_die = true;
                            }
                        }

                        if (should_die)
                            goto die;
                        else
                            process.Continue();
                    }
                }
                else if (state == lldb::eStateCrashed)
                {
                    goto die;
                }
                else if (state == lldb::eStateExited)
                {
                    debugn("exited : %u", process.GetExitStatus());
                    goto die;
                }
            }
        }
        else
        {
            //raise timeout
            debugn("Timeout received! dying!!!");
            wrangler->exit_status = 2;
            process.Kill();
            done = true;
        }
    }

die:
    // dumpStdout(process);
    debugger.Destroy(debugger);
    SBDebugger::Terminate();
    
    return wrangler;
}


void m1WranglerDestroy(struct m1Wrangler* wrangler)
{
    free(wrangler);
}

bool isSignal(SBThread thread)
{
    if (thread.GetStopReason() == lldb::eStopReasonSignal)
        return true;
    
    return false;
}

bool isException(SBThread thread)
{
    if (thread.GetStopReason() == lldb::eStopReasonException)
        return true;
    
    return false;
}

bool getException(const char* stop_desc, struct CrashDetails * exception)
{
    NSString *stopDesc = [NSString stringWithFormat:@"%s", stop_desc];
    NSRange start = [stopDesc rangeOfString:@"EXC_"];
    NSRange end   = [stopDesc rangeOfString:@" "];
    NSString *crash_reason = [stopDesc substringWithRange:NSMakeRange(start.location, end.location)];
    strncpy(exception->exception,  [crash_reason UTF8String], end.location-start.location);
    
    start   = [stopDesc rangeOfString:@"code="];
    end     = [stopDesc rangeOfString:@","];

    NSString * code_s = [stopDesc substringWithRange:NSMakeRange(start.location+start.length, end.location-start.location-start.length)];
    int code = atoi([code_s UTF8String]);
    exception->code = code;
    
    return true;
}

NSString* getFunctionTrailHash(SBThread thread)
{
    SBFrame frame     = thread.GetFrameAtIndex(0);
    SBValue registers = frame.GetRegisters().GetValueAtIndex(0);
        
    addr64_t crash_pc     =  registers.GetChildMemberWithName("pc").GetValueAsUnsigned();
    
    uint32_t frames_count = thread.GetNumFrames() > MAX_FRAMES ? MAX_FRAMES : thread.GetNumFrames();
    
    NSMutableString * function_trail = [[NSMutableString alloc] init];
   
    [function_trail appendString:[NSString stringWithFormat:@"%llx", crash_pc]];
    
    while(frames_count>0)
    {
        [function_trail appendString:@"->"];
        SBFrame frame = thread.GetFrameAtIndex(frames_count-1);
        const char* function_name = frame.GetFunctionName();
        
        if (function_name!=NULL)
            [function_trail appendString:[NSString stringWithFormat:@"%s", function_name]];
        else
        {
            addr64_t pc = frame.GetRegisters().GetValueAtIndex(0).GetChildMemberWithName("pc").GetValueAsUnsigned();
            pc = pc & 0x0fffffffff; // ptrauth_strip(pc, ptrauth_key_asia);
            [function_trail appendString:[NSString stringWithFormat:@"0x%llx", pc]];
        }
        frames_count -=1 ;
    }
    
    return sha256HashFor(function_trail);
}

void dumpFunctionTrail(SBThread thread, uint32_t depth)
{
    SBFrame frame = thread.GetFrameAtIndex(0);
    SBValue registers = frame.GetRegisters().GetValueAtIndex(0);
    
    uint32_t frames_count = thread.GetNumFrames();
    
    depth = (depth > frames_count) ? frames_count : depth;

    while(depth>0)
    {
        debug(RED "->");
        SBFrame frame = thread.GetFrameAtIndex(depth-1);
        const char* function_name = frame.GetFunctionName();
        
        if (function_name!=NULL)
        {
            debug("%s", function_name);
        }
        
        else
        {
            addr64_t pc = frame.GetRegisters().GetValueAtIndex(0).GetChildMemberWithName("pc").GetValueAsUnsigned();
            pc = pc & 0x0fffffffff; // ptrauth_strip(pc, ptrauth_key_asia);
            //PAC uses the useless high 28bits of VA as PAC on arm64e, so we only need to take the lower 36bits as the actual VA.
            debug("0x%llx", pc);
        }
        
        depth -= 1;
    }
    debugn("");
}

bool write_crashlog(SBCommandInterpreter command_interpreter, SBProcess process, SBThread thread, char* current_case, NSData * poc, char* log_dir)
{
    char* stop_desc = (char *) malloc(1024);
    thread.GetStopDescription(stop_desc, 1024);
    
    bool is_signal      = isSignal(thread);
    bool is_exception   = isException(thread);
    
    uint32_t frames_count = thread.GetNumFrames();
    SBFrame frame = thread.GetFrameAtIndex(0);
    
    const char* function_name = frame.GetFunctionName();
    SBValueList registers = frame.GetRegisters();
    addr_t pc = frame.GetPC();

    NSString* trail_hash = getFunctionTrailHash(thread);
    
    // save crash
    context_title("Crash Context");

    NSString * _exploitable_json = [NSString stringWithUTF8String:runCommandAndFetchOutput(command_interpreter, "exploitable")];
    NSData *data = [_exploitable_json dataUsingEncoding:NSUTF8StringEncoding];
    NSDictionary *exploitable_json = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];

    NSLog(@"%@", exploitable_json);

    NSError * error = nil;
    NSFileManager *fileManager = [NSFileManager defaultManager]; 
    
    NSString *is_exploitable = [exploitable_json valueForKey:@"av_is_exploitable"];
    NSString *exception = [exploitable_json valueForKey:@"crash_code"];

    NSString* crashFolder = [NSString stringWithFormat:@"%s/exploitable_%@/%@/%s",log_dir, is_exploitable, exception,  [trail_hash UTF8String]];
    [fileManager createDirectoryAtPath:crashFolder withIntermediateDirectories:YES attributes:nil error:&error];

    [_exploitable_json writeToFile:[crashFolder stringByAppendingPathComponent:@"crash.log"] atomically:YES encoding:NSUTF8StringEncoding error:&error];

    if(current_case)
    {
        NSString *pocPath     = [NSString stringWithUTF8String:current_case];
        [poc writeToFile:[crashFolder stringByAppendingPathComponent:[pocPath lastPathComponent]] atomically:YES];
    }
    
    NSString *logmsg = [NSString stringWithFormat:@"crash saved to %@", crashFolder];
    context_title([logmsg UTF8String]);

    free(stop_desc);

    return true;
}