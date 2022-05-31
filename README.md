# crashmon
crashmon - A CrashWrangler replacement based on LLDB

Crashmon, same as CrashWrangelr, is a LLDB wrapper together with [Lisa.py](https://github.com/ant4g0nist/lisa.py) that can be used to determine if a crash is an exploitable security issue, and if a crash is a duplicate of another known crash.

# Usage

========= Build Instruction =========
```sh
macOSResearch ✗ git clone https://github.com/ant4g0nist/crashmon
macOSResearch ✗ cd crashmon
crashmon git:(main) ✗ make
crashmon git:(main) ✗ make install
```

![example](https://raw.githubusercontent.com/ant4g0nist/crashmon/main/imgs/example.png)

For debugging macOS System Applications/Services, it is expected that you disable SIP as crashmon uses LLDB.

### ========= Environment Variable Reference =========
CW_CURRENT_CASE: 
Path of the test case file that is being open in the target application.
If set, crashmon will read and save the content of the test case file to triaged crash folder. This will be handy while fuzzing!

CW_ATTACH_PID:
If set, use this pid as the process to monitor for crashes.  
e.g. 
env CW_ATTACH_PID=12313 CW_CURRENT_CASE=foo ./crashmon
or 
sudo env CW_ATTACH_PID=12313 CW_CURRENT_CASE=foo ./crashmon

CW_LOG_DIR: (Default ./crashlogs)
The directory to output crashlogs to.

CW_JSON_STDOUT: (Default false)
Write exploitable output as json to stdout.

CWE_*:
 If there are any environment variables prefixed with CWE_, delete the prefix and set the environment variable in the child.  This does not apply when using CW_ATTACH_PID or CW_REGISTER_LAUNCHD_NAME.

### ========= crashmon return values =========
No crash = 0
Crash = 1
Timeout = 2

### ========= Exploitability algorithm =========

The algorithm for determining exploitability looks like this:

Exploitable if
	Crash on write instruction
	Crash executing invalid address
	Crash calling an invalid address
	Illegal instruction exception
	Abort due to -fstack-protector, _FORTIFY_SOURCE, heap corruption detected
	Stack trace of crashing thread contains certain functions such as malloc, free, szone_error, objc_MsgSend, etc.

Not exploitable if
	Divide by zero exception
	Stack grows too large due to recursion
	Null dereference(read or write)
	Other abort
	Crash on read instruction

## PS
This is meant to be used just as an initial triage system! Don't really 100% on the crashmon's output as there might be bugs in `lisa.py`. I appreciate pull requests. 

So, it's recommended to run the test case again with libgmalloc(3) on, and see if the crash changes to one that is considered to be exploitable.

## todo
- [x] add lisa.py exploitable checks
- [ ] test moreeee
- [ ] follow xpc services (target function -> 'xpc_connection_get_pid'. Usecase: Safari->WebContent)

### thanks
- @apple for crashwrangler
- LLVM