
C_FLAGS := $(shell pkg-config --cflags json-c samba-hostconfig samba-util)
LIBS := $(shell pkg-config --libs json-c samba-hostconfig samba-util)

all: db_vfs.so

db_vfs.o: db_vfs.c
	gcc -Wall -fPIC -c db_vfs.c -I../samba/source3/ -I../samba/lib/ $(C_FLAGS)

db_vfs.so: db_vfs.o
	gcc -shared -o db_vfs.so db_vfs.o $(LIBS)
