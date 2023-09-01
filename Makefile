CC=g++

CFLAGS= -Wall -lncrypt -lcrypt32 $(ARGS)

all: create_key.exe delete_key.exe export_key.exe sign.exe

create_key.exe: src/create_key.cpp
	$(CC) $? -o bin/$@ $(CFLAGS)

delete_key.exe: src/delete_key.cpp
	$(CC) $? -o bin/$@ $(CFLAGS)

export_key.exe: src/export_key.cpp
	$(CC) $? -o bin/$@ $(CFLAGS)

sign.exe: src/sign.cpp
	$(CC) $? -o bin/$@ $(CFLAGS)

clean:
	rm -rf bin/*.exe