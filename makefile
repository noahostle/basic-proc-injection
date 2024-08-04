CC = gcc
CFLAGS = -m64
LDFLAGS = -shared -Wl,--subsystem,windows
SHELL=cmd


all: clean dll.dll inject.exe 


dll.dll: dll.c
	$(CC) $(LDFLAGS) -o dll.dll dll.c

inject.exe: inject.c
	$(CC) $(CFLAGS) -o inject.exe inject.c


clean:
	del dll.dll 
	del inject.exe
