AM_CPPFLAGS += -I$(top_srcdir)/tests/utils -I$(srcdir)

if HAVE_LIBLTTNG_UST_CTL
noinst_PROGRAMS = gen-ust-events
gen_ust_events_SOURCES = gen-ust-events.c tp.c tp.h
gen_ust_events_LDADD = -llttng-ust -lurcu-percpu \
		$(top_builddir)/tests/utils/libtestutils.la \
		-lrseq -lcpu-op \
		$(DL_LIBS)
endif
