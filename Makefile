tarsier: tarsier.c
	cc -o $@ -larchive -lcrypto $<

install: tarsier
	install -m 555 tarsier /usr/local/bin/tarsier
	install -m 444 tarsier.1 /usr/local/man/man1/tarsier.1
