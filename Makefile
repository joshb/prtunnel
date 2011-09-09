PREFIX=/usr/local
CC=gcc
CFLAGS=-Wall -ansi -pedantic -D_GNU_SOURCE
CFLAGS+= -DIPV6
OBJS=connect.o direct.o direct6.o http.o socks5.o proxy.o main.o

prtunnel:	$(OBJS)
	$(CC) $(OBJS) -o prtunnel

install:
	install -c prtunnel $(PREFIX)/bin/prtunnel
	install -c prtunnel.1 $(PREFIX)/man/man1/prtunnel.1

uninstall:
	rm -f $(PREFIX)/bin/prtunnel
	rm -f $(PREFIX)/man/man1/prtunnel.1

clean:
	rm -f prtunnel
	rm -f $(OBJS)

connect.o: connect.c
direct.o: direct.c
direct6.o: direct6.c
http.o: http.c
socks5.o: socks5.c
proxy.o: proxy.c
main.o: main.c
