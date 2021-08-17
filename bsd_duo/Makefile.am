AM_CPPFLAGS = -I$(top_srcdir)/compat -I$(top_srcdir)/lib @OPENSSL_INCLUDES@

sbin_PROGRAMS = bsd_duo

bsd_duo_SOURCES = common.h bsd_duo.c login.c
bsd_duo_LDADD = $(top_builddir)/lib/libduo.la $(top_builddir)/compat/libcompat.la @OPENSSL_LDFLAGS@ @OPENSSL_LIBS@ -lutil

notrans_dist_man8_MANS = bsd_duo.8

install-exec-hook:
	-chown root $(DESTDIR)$(sbindir)/bsd_duo && \
	 chmod 4755 $(DESTDIR)$(sbindir)/bsd_duo

install-data-local:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)
	-@if [ ! -f $(DESTDIR)$(sysconfdir)/bsd_duo.conf ]; then \
	  cp bsd_duo.conf $(DESTDIR)$(sysconfdir)/bsd_duo.conf; \
	  echo "Created ${DESTDIR}$(sysconfdir)/bsd_duo.conf"; \
	  echo "Please edit it to add your Duo integration and secret keys"; \
	else \
	  echo "Found existing ${DESTDIR}$(sysconfdir)/bsd_duo.conf - updating permissions"; \
	fi
	-chown $(DUO_PRIVSEP_USER) $(DESTDIR)$(sysconfdir)/bsd_duo.conf
	-chmod 600 $(DESTDIR)$(sysconfdir)/bsd_duo.conf

EXTRA_DIST = bsd_duo.conf
