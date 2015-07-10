# libevent-magic
# See COPYING for copyright and license details.

NAME = event-magic
VERSION = 0.5

LIBSRCDIR = libsrc
LIBOBJDIR = libobj
LIBOUTDIR = libout

EXSRCDIR = examples
EXOBJDIR = examplesobj
EXOUTDIR = examplesout

INCDIR = include


LIBDIRS = $(LIBOUTDIR) $(LIBOBJDIR)
EXDIRS = $(EXOUTDIR) $(EXOBJDIR)
DIRS = $(LIBDIRS) $(EXDIRS)


CFLAGS += -std=gnu99 -pedantic -Wall -I$(INCDIR)
DEBUG = 1

ifeq (1,$(DEBUG))
CFLAGS += -g -Wextra
else
CFLAGS += -O2
endif

LDFLAGS += -levent -levent_openssl -lssl -lcrypto -lpcre

LIBCFLAGS := $(CFLAGS) -fPIC
LIBLDFLAGS := $(LDFLAGS) -shared

EXLDFLAGS := $(LDFLAGS) -l$(NAME) -Llibout/

LIBSOURCES = $(wildcard $(LIBSRCDIR)/*.c)
LIBOBJECTS = $(patsubst $(LIBSRCDIR)/%.c,$(LIBOBJDIR)/%.o,$(LIBSOURCES))
LIBBIN = $(LIBOUTDIR)/lib$(NAME).so

EXSOURCES = $(wildcard $(EXSRCDIR)/*.c)
EXOBJECTS = $(patsubst $(EXSRCDIR)/%.c,$(EXOBJDIR)/%.o,$(EXSOURCES))
EXBINS = $(patsubst $(EXSRCDIR)/%.c,$(EXOUTDIR)/%,$(wildcard $(EXSRCDIR)/*.c))

SOURCES = $(LIBSOURCES) $(EXSOURCES)
HEADERS = $(wildcard $(LIBSRCDIR)/*.h) $(wildcard $(EXSRCDIR)/*.h) $(wildcard $(INCDIR)/*.h)

.PHONY: all clean default lib examples debug install uninstall

default: clean lib

all: lib examples

lib: $(LIBBIN)

examples: $(EXBINS)

debug:
	$(MAKE) DEBUG=1

#	$(foreach var,$(EXBINS),$(CC) $(EXSRCDIR)/$(var).c $(LDFLAGS) $(CFLAGS) -o $(EXOUTDIR)/$(var); )

$(LIBBIN): % : %.$(VERSION)
# TODO -f should really not be necessary, why is the recipe run, when the file exists?
	cd $(LIBOUTDIR) ; ln -sf $(patsubst $(LIBOUTDIR)/%,%,$^) $(patsubst $(LIBOUTDIR)/%,%,$@)


$(LIBBIN).$(VERSION): $(LIBOBJECTS) | $(LIBOUTDIR)
	$(CC) $^ -o $@ $(LIBLDFLAGS)
	chmod 755 $@

$(EXBINS): $(EXOUTDIR)/% : $(EXOBJDIR)/%.o | $(EXOUTDIR) $(LIBBIN)
	$(CC) $^ -o $@ $(EXLDFLAGS) $(CFLAGS)


$(LIBOBJECTS): $(LIBOBJDIR)/%.o : $(LIBSRCDIR)/%.c | $(LIBOBJDIR)
	$(CC) -c $< -o $@ $(LIBCFLAGS)

$(EXOBJECTS): $(EXOBJDIR)/%.o : $(EXSRCDIR)/%.c | $(EXOBJDIR)
	$(CC) -c $< -o $@ $(CFLAGS)


$(DIRS):
	mkdir -p $@


VALGRINDCALLFILE = valgrindcall
valgrind: $(VALGRINDCALLFILE)
	tools/startvalgrind $(VALGRINDCALLFILE) $(CALL)

format: $(SOURCES) $(HEADERS)
	tools/format $^

tab_format: $(SOURCES) $(HEADERS)
	tools/tab_format $^


prefix ?= /usr/local/
INSTALLDIR = $(prefix)
LIBINSTALLDIR = $(prefix)lib/

install: $(LIBBIN).$(VERSION)
	install -m 0755 $^ $(LIBINSTALLDIR)
	cd $(LIBINSTALLDIR) ; ln -fs $(patsubst $(LIBOUTDIR)/%,%,$(LIBBIN).$(VERSION)) $(patsubst $(LIBOUTDIR)/%,%,$(LIBBIN))

uninstall:
	cd $(LIBINSTALLDIR) ; rm -rf $(patsubst $(LIBOUTDIR)/%,$(LIBINSTALLDIR)/%*,$(LIBBIN))

clean::
	rm -rf $(DIRS)
