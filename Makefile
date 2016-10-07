tarsier: tarsier.c
	cc -o $@ -larchive -lcrypto $<

install: tarsier
	install -m 555 tarsier /usr/local/bin/tarsier
