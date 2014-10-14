INCLUDE_DIRS = 
LIB_DIRS = 

CDEFS=
CFLAGS= -Wall -O0 -fprofile-arcs -ftest-coverage -g $(INCLUDE_DIRS) $(CDEFS)
LIBS= 

PRODUCT=enigma3

HFILES=
CFILES= enigma3.c

SRCS= ${HFILES} ${CFILES}
OBJS= ${CFILES:.c=.o}

all: enigma3

clean:
	-rm -f *.o *.d *.exe enigma3 *.gcov *.gcda *.gcno *.out

enigma3: enigma3.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

depend:

.c.o:
	$(CC) -MD $(CFLAGS) -c $<
