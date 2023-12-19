obj-m += vuln.o

all:
	make -C /home/zabi/Desktop/rootkit/rootkit/linux-5.15.130 M=$(shell realpath ./) modules
clean:
	rm -f *~
	make -C /home/zabi/Desktop/rootkit/rootkit/linux-5.15.130 M=$(shell realpath ./) clean || true

distclean: clean
	rm -f vuln.c