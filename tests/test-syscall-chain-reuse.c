/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <stdio.h>
#include <stdlib.h>

#include <talloc.h>

#include "arch.h"
#include "cli/note.h"
#include "syscall/chain.h"
#include "syscall/sysnum.h"
#include "tracee/reg.h"

static word_t registers[USERARG_1 + 1];

void note(const Tracee *tracee, Severity severity, Origin origin,
	const char *message, ...)
{
	(void)tracee;
	(void)severity;
	(void)origin;
	(void)message;
}

word_t peek_reg(const Tracee *tracee, RegVersion version, Reg reg)
{
	(void)tracee;
	(void)version;
	return registers[reg];
}

void poke_reg(Tracee *tracee, Reg reg, word_t value)
{
	(void)tracee;
	registers[reg] = value;
}

word_t get_systrap_size(Tracee *tracee)
{
	(void)tracee;
	return 4;
}

Sysnum get_sysnum(const Tracee *tracee, RegVersion version)
{
	(void)tracee;
	(void)version;
	return (Sysnum)registers[SYSARG_NUM];
}

word_t detranslate_sysnum(Abi abi, Sysnum sysnum)
{
	(void)abi;
	return (word_t)sysnum;
}

int main(void)
{
	Tracee *tracee = talloc_zero(NULL, Tracee);
	int status;

	if (tracee == NULL)
		return 1;
	registers[INSTR_POINTER] = 0x1000;
	status = register_chained_syscall(tracee, PR_openat,
		1, 2, 3, 4, 5, 6);
	if (status < 0) {
		printf("INITIAL_CHAIN_REGISTER=%d\n", status);
		TALLOC_FREE(tracee);
		return 1;
	}
	chain_next_syscall(tracee);
	if (registers[SYSARG_NUM] != (word_t)PR_openat) {
		printf("FIRST_CHAIN_SYSCALL=%lu\n",
			(unsigned long)registers[SYSARG_NUM]);
		TALLOC_FREE(tracee);
		return 1;
	}
	status = talloc_set_memlimit(tracee, talloc_total_size(tracee));
	if (status < 0) {
		printf("SET_MEMLIMIT=%d\n", status);
		TALLOC_FREE(tracee);
		return 1;
	}
	status = register_chained_syscall(tracee, PR_close,
		55, 0, 0, 0, 0, 0);
	printf("CHAIN_REUSE_STATUS=%d\n", status);
	if (status < 0) {
		puts("CHAIN_REUSE_ALLOC_FREE=FAIL");
		TALLOC_FREE(tracee);
		return 1;
	}
	chain_next_syscall(tracee);
	if (registers[SYSARG_NUM] != (word_t)PR_close ||
	    registers[SYSARG_1] != 55) {
		puts("CHAIN_REUSE_ARGS=FAIL");
		TALLOC_FREE(tracee);
		return 1;
	}
	puts("CHAIN_REUSE_ALLOC_FREE=PASS");
	TALLOC_FREE(tracee);
	return 0;
}
