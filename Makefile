all: clean
	gcc -lm -lcrypt -o 2cI 2cI.c ./libs/libHW4.a
	gcc -lm -lcrypt -o 2cII 2cII.c ./libs/libHW4.a
	gcc -lm -lcrypt -o 2cIII 2cIII.c ./libs/libHW4.a

clean:
	rm -f *.o 2cI 2cII 2cIII
