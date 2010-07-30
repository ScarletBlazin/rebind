CC=gcc
CFLAGS=-g -O -W -Wuninitialized -Wall -Wextra -Wshadow -static
LIBS=-L ./readline -L ./termcap
INCS=-I .
HTML=html.h
PNG=png.h
HTML_PY=../dev/htmltoc.py
PNG_PY=../dev/pngtoc.py
TARGET=rebind

$(TARGET): sqlite.o termcap.a readline.a common.o sql.o socklib.o iptables.o dns.o fifo.o filter.o attack.o callback.o proxy.o config.o console.o
	$(CC) $(TARGET).c -o $(TARGET) *.o -ldl -lpthread -lreadline -ltermcap $(CFLAGS) $(LIBS) $(INCS)

sql.o:
	$(CC) -c sql.c $(CFLAGS) $(LIBS) $(INCS)

dns.o: 
	$(CC) -c dns.c $(CFLAGS) $(LIBS) $(INCS)

attack.o: $(HTML)
	$(CC) -c attack.c $(CFLAGS) $(LIBS) $(INCS)

callback.o: $(HTML)
	$(CC) -c callback.c $(CFLAGS) $(LIBS) $(INCS)

proxy.o: $(HTML) $(PNG)
	$(CC) -c proxy.c $(CFLAGS) $(LIBS) $(INCS)

socklib.o:
	$(CC) -c socklib.c $(CFLAGS) $(LIBS) $(INCS)

iptables.o:
	$(CC) -c iptables.c $(CFLAGS) $(LIBS) $(INCS)

fifo.o:
	$(CC) -c fifo.c $(CFLAGS) $(LIBS) $(INCS)

filter.o:
	$(CC) -c filter.c $(CFLAGS) $(LIBS) $(INCS)

config.o:
	$(CC) -c config.c $(CFLAGS) $(LIBS) $(INCS)

console.o:
	$(CC) -c console.c $(CFLAGS) $(LIBS) $(INCS)

sqlite.o:
	$(CC) -c sqlite3/sqlite3.c -o sqlite.o

common.o:
	$(CC) -c common.c $(CFLAGS) $(LIBS) $(INCS)

termcap.a:
	(cd termcap && (test -e libtermcap.a || (./configure && make)))

readline.a:
	(cd readline && (test -e libreadline.a || (./configure && make)))

$(HTML):
	($(HTML_PY) www/index.html $(HTML) PROXY_HTML) && \
	($(HTML_PY) www/payload.html $(HTML) PAYLOAD) && \
	($(HTML_PY) www/crossdomain.html $(HTML) POST_HTML)

$(PNG):
	($(PNG_PY) www/header.png $(PNG) HEADER_PNG) && \
	($(PNG_PY) www/header_bg.png $(PNG) HEADER_BG_PNG) && \
	($(PNG_PY) www/footer_bg.png $(PNG) FOOTER_BG_PNG) && \
	($(PNG_PY) www/body_bg.png $(PNG) BODY_BG_PNG)

install:
	cp $(TARGET) ../bin/$(TARGET)

cleanheaders:
	rm -f $(HTML) $(PNG)

clean: cleanheaders
	rm -f *~
	ls -1 *.o | grep -v sqlite | xargs -i rm -f {}
	rm -f $(TARGET)
	
cleanall: clean
	rm -f *.o
	(cd termcap && make clean)
	(cd readline && make clean)
