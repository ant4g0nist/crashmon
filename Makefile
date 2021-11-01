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