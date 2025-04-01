C = gcc
CFLAGS = -g -Wall -Wextra -Wshadow -Wunreachable-code -Wredundant-decls \
		 -pthread -Wmissing-declarations -Wold-style-definition \
		 -Wmissing-prototypes -Wdeclaration-after-statement \
		 -Wno-return-local-addr -Wunsafe-loop-optimizations \
		 -Wuninitialized -Werror -Wno-unused-parameter
LDFLAGS = -lcrypt

PROGS = thread_crypt
INCLUDES = thread_crypt.h

all: $(PROGS)

$(PROGS): $(PROGS).o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(PROGS).o: $(PROGS).c $(INCLUDES)
	$(CC) $(CFLAGS) -c $<

clean cls:
	rm -f $(PROGS) *.o

push:
	git add thread_crypt.c Makefile
	git commit -m "Updating git repo"

TARFILES = thread_crypt.c Makefile
TARNAME = lab3_$(LOGNAME).tar.gz

tar:
	tar cvfa $(TARNAME) $(TARFILES)

.PHONY: tar
