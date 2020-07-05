/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>

void raw_vmcall(uint64_t vmcall_nr, void* args, long n)
{
	long ret;

	asm volatile("vmcall"
	             : "=a"(ret)
	             : "D"(vmcall_nr), "S"(args), "d"(n));
}

void print_cstr(char* str, long n) {
	for(int i = 0; i < n; i += 1)
		printf("%c", *(str+i));
}

void print_num(long num, long format) {
	if (format == 16) {
		printf("%lx ", num);
	} else {
		printf("%ld ", num);
	}
}