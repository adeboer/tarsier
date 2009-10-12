tarsier: tarsier.c
	cc -o $@ -larchive -lssl $<

install: tarsier
	install -m 555 tarsier /usr/local/bin/tarsier
