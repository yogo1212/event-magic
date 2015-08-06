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
LIBHEADERS = $(wildcard $(INCDIR)/$(NAME)/*.h)
LIBBIN = $(LIBOUTDIR)/lib$(NAME).so

EXSOURCES = $(wildcard $(EXSRCDIR)/*.c)
EXOBJECTS = $(patsubst $(EXSRCDIR)/%.c,$(EXOBJDIR)/%.o,$(EXSOURCES))
EXBINS = $(patsubst $(EXSRCDIR)/%.c,$(EXOUTDIR)/%,$(wildcard $(EXSRCDIR)/*.c))

SOURCES = $(LIBSOURCES) $(EXSOURCES)
HEADERS = $(wildcard $(LIBSRCDIR)/*.h) $(wildcard $(EXSRCDIR)/*.h) $(LIBHEADERS)

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

test:
	echo $(HEADERS)


VALGRINDCALLFILE = valgrindcall
valgrind: $(VALGRINDCALLFILE)
	tools/startvalgrind $(VALGRINDCALLFILE) $(CALL)

format: $(SOURCES) $(HEADERS)
	tools/format $^

tab_format: $(SOURCES) $(HEADERS)
	tools/tab_format $^


prefix ?= /usr/local

INSTALLDIR = $(prefix)/
LIBINSTALLDIR = $(INSTALLDIR)lib/
HEADERINSTALLDIR = $(INSTALLDIR)include/$(NAME)/
EXAMPLESINSTALLDIR = $(INSTALLDIR)bin/

INSTALL_BIN_CMD=install -m 0755

install_lib: $(LIBBIN).$(VERSION)
	mkdir -p $(LIBINSTALLDIR)
	$(INSTALL_BIN_CMD) $^ $(LIBINSTALLDIR)
	cd $(LIBINSTALLDIR) ; ln -fs $(patsubst $(LIBOUTDIR)/%,%,$(LIBBIN).$(VERSION)) $(patsubst $(LIBOUTDIR)/%,%,$(LIBBIN))

install_headers: $(LIBHEADERS)
	mkdir -p $(HEADERINSTALLDIR)
	install $(LIBHEADERS) $(HEADERINSTALLDIR)
	#TODO remove $(HEADERINSTALLDIR) if empty

install_examples: $(EXBINS)
	mkdir -p $(EXAMPLESINSTALLDIR)
	$(INSTALL_BIN_CMD) $^ $(EXAMPLESINSTALLDIR)

install: install_lib install_headers install_examples

uninstall_lib:
	rm -f $(patsubst $(LIBOUTDIR)/%,$(LIBINSTALLDIR)/%*,$(LIBBIN))

uninstall_headers:
	echo $(LIBHEADERS)
	rm -f $(patsubst $(INCDIR)/$(NAME)/%,$(HEADERINSTALLDIR)/%,$(LIBHEADERS))

uninstall_examples:
	rm -f $(patsubst $(EXOUTDIR)/%,$(EXAMPLESINSTALLDIR)/%,$(EXBINS))

uninstall: uninstall_lib uninstall_headers uninstall_examples

clean::
	rm -rf $(DIRS)
