all: crashmon

CXX=clang++
CXXFLAGS= -framework foundation -Iincludes/ -framework LLDB -F/Applications/Xcode.app/Contents/SharedFrameworks/ -std=c++11
LDFLAGS="-Wl,-rpath,/Applications/Xcode.app/Contents/SharedFrameworks/"

crashmon.o:
	$(shell mkdir bin/)
	$(CXX) -Iincludes/ -std=c++11 -c crashmon.mm -o bin/$@

main.o:
	$(CXX) -Iincludes/ -std=c++11 -c main.mm -o bin/$@

crashmon: crashmon.o main.o
	$(CXX) $(CXXFLAGS) $(LDFLAGS) bin/*.o -o bin/$@

clean:
	rm bin/*

test:
	cd tests && make && cd -
	./bin/crashmon ./tests/binaries/abort abort.c
	./bin/crashmon ./tests/binaries/bad_func_call bad_func_call.c
	./bin/crashmon ./tests/binaries/badsyscall badsyscall.c
	./bin/crashmon ./tests/binaries/cfrelease_null -framework Foundation cfrelease_null.c
	./bin/crashmon ./tests/binaries/cpp_crash cpp_crash.cpp
	./bin/crashmon ./tests/binaries/crashexec crashexec.c
	./bin/crashmon ./tests/binaries/crashread crashread.c
	./bin/crashmon ./tests/binaries/crashwrite crashwrite.c
	./bin/crashmon ./tests/binaries/divzero divzero.c
	./bin/crashmon ./tests/binaries/exploitable_jit exploitable_jit.c
	./bin/crashmon ./tests/binaries/fastMalloc fastMalloc.cpp
	./bin/crashmon ./tests/binaries/illegal_libdispatch illegal_libdispatch.c
	./bin/crashmon ./tests/binaries/illegalinstruction illegalinstruction.c
	./bin/crashmon ./tests/binaries/invalid_address_64 invalid_address_64.c
	./bin/crashmon ./tests/binaries/malloc_abort malloc_abort.c
	./bin/crashmon ./tests/binaries/nocrash nocrash.c
	./bin/crashmon ./tests/binaries/null_objc_msgSend null_objc_msgSend.c
	./bin/crashmon ./tests/binaries/nullderef nullderef.c
	./bin/crashmon ./tests/binaries/objc_crash -framework Foundation objc_crash.m
	./bin/crashmon ./tests/binaries/read_and_write_instruction read_and_write_instruction.c
	./bin/crashmon ./tests/binaries/recursive_write recursive_write.c
	./bin/crashmon ./tests/binaries/stack_buffer_overflow stack_buffer_overflow.c
	./bin/crashmon ./tests/binaries/uninit_heap uninit_heap.c
	./bin/crashmon ./tests/binaries/variable_length_stack_buffer variable_length_stack_buffer.c