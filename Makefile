all :
	cd src && make all

clean :
	cd src && make clean

help :
	cd src && make help

test :
	./test.sh

report :
	cd src && make report

.PHONY: all clean help test report