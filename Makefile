#
# Author: Gagan Malvi <malvi@aospa.co>
# Date: 2022-12-22
#

CC := gcc
BINARIES_DIRECTORY := binaries
PROGRAMS := $(wildcard *.c)

# Flags to be passed to the C compiler.
OPENMP_CFLAGS := -fopenmp
X86_64_V3_CFLAGS += \
	-march=x86-64-v3

EXTRA_CFLAGS := \
	-Ofast \
	-Wall \
	-Werror

all:
	for program in $(PROGRAMS); do \
		echo -e "\033[0;34m[-]\033[0m Building: \033[0;31m$$program...\033[0m" ; \
		# if $(BINARIES_DIRECTORY) does not exist, create it. \
		[ -d $(BINARIES_DIRECTORY) ] || mkdir $(BINARIES_DIRECTORY); \
		$(CC) $(X86_64_V3_CFLAGS) $(EXTRA_CFLAGS) $(OPENMP_CFLAGS) $$program -o $(BINARIES_DIRECTORY)/$${program%.*}; \
	done

no-compiler-optimizations: 
	for program in $(PROGRAMS); do \
		echo -e "\033[0;34m[-]\033[0m Building: \033[0;31m$$program...\033[0m" ; \
		# if $(BINARIES_DIRECTORY) does not exist, create it. \
		[ -d $(BINARIES_DIRECTORY) ] || mkdir $(BINARIES_DIRECTORY); \
		$(CC) $(OPENMP_CFLAGS) $$program -o $(BINARIES_DIRECTORY)/$${program%.*}; \
	done

clean:
	rm -rf $(BINARIES_DIRECTORY)/*