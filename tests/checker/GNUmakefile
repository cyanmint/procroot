# Standalone build for the "-N"/"--proc" PID-namespace virtualization
# checker.  It has no dependency on PRoot's own build system: it is a
# single self-contained C program meant to be run *under* PRoot.
#
# Usage:
#   make                 # build ./checker (dynamically linked)
#   make static          # build ./checker statically linked
#   make clean

CC       ?= gcc
CFLAGS   += -Wall -Wextra -O2
LDFLAGS  +=

.PHONY: all static clean

all: checker

static: LDFLAGS += -static
static: checker

checker: checker.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	$(RM) checker
