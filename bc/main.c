#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#ifdef KLEE
#include <klee/klee.h>
#endif

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/inet_diag.h>

#define bool int
#define false  0
#define true   1

#define u16 uint16_t
#define SOCK_BINDPORT_LOCK	8

struct inet_diag_entry {
	const __be32 *saddr;
	const __be32 *daddr;
	u16 sport;
	u16 dport;
	u16 family;
	u16 userlocks;
};

#ifndef DEBUG
#define log(msg, ...)
#else

#define log(msg, ...) printf(msg, ##__VA_ARGS__)

const char * op_name(unsigned char code) {
	switch (code) {
		case INET_DIAG_BC_S_COND:
			return "INET_DIAG_BC_S_COND";
		case INET_DIAG_BC_D_COND:
			return "INET_DIAG_BC_D_COND";
		case INET_DIAG_BC_S_GE:
			return "INET_DIAG_BC_S_GE";
		case INET_DIAG_BC_S_LE:
			return "INET_DIAG_BC_S_LE";
		case INET_DIAG_BC_D_GE:
			return "INET_DIAG_BC_D_GE";
		case INET_DIAG_BC_D_LE:
			return "INET_DIAG_BC_D_LE";
		case INET_DIAG_BC_AUTO:
			return "INET_DIAG_BC_AUTO";
		case INET_DIAG_BC_JMP:
			return "INET_DIAG_BC_JMP";
		case INET_DIAG_BC_NOP:
			return "INET_DIAG_BC_NOP";
	}
	return "Unknown";
}
#endif


static int bitstring_match(const __be32 *a1, const __be32 *a2, int bits)
{
	int words = bits >> 5;

	bits &= 0x1f;

	if (words) {
		if (memcmp(a1, a2, words << 2))
			return 0;
	}
	if (bits) {
		__be32 w1, w2;
		__be32 mask;

		w1 = a1[words];
		w2 = a2[words];

		mask = htonl((0xffffffff) << (32 - bits));

		if ((w1 ^ w2) & mask)
			return 0;
	}

	return 1;
}

static int inet_diag_bc_run(const void * bc, int len,
		const struct inet_diag_entry *entry)
{
#ifdef DEBUG
	const void * orig_bc = bc;
#endif
	while (len > 0) {
		int yes = 1;
		const struct inet_diag_bc_op *op = bc;

		switch (op->code) {
			case INET_DIAG_BC_NOP:
				break;
			case INET_DIAG_BC_JMP:
				yes = 0;
				break;
			case INET_DIAG_BC_S_GE:
				yes = entry->sport >= op[1].no;
				break;
			case INET_DIAG_BC_S_LE:
				yes = entry->sport <= op[1].no;
				break;
			case INET_DIAG_BC_D_GE:
				yes = entry->dport >= op[1].no;
				break;
			case INET_DIAG_BC_D_LE:
				yes = entry->dport <= op[1].no;
				break;
			case INET_DIAG_BC_AUTO:
				yes = !(entry->userlocks & SOCK_BINDPORT_LOCK);
				break;
			case INET_DIAG_BC_S_COND:
			case INET_DIAG_BC_D_COND: {
				const struct inet_diag_hostcond *cond;
				const __be32 *addr;

				cond = (const struct inet_diag_hostcond *)(op + 1);
				if (cond->port != -1 &&
						cond->port != (op->code == INET_DIAG_BC_S_COND ?
							entry->sport : entry->dport)) {
					yes = 0;
					break;
				}

				if (op->code == INET_DIAG_BC_S_COND)
					addr = entry->saddr;
				else
					addr = entry->daddr;

				if (cond->family != AF_UNSPEC &&
						cond->family != entry->family) {
					if (entry->family == AF_INET6 &&
							cond->family == AF_INET) {
						if (addr[0] == 0 && addr[1] == 0 &&
								addr[2] == htonl(0xffff) &&
								bitstring_match(addr + 3,
									cond->addr,
									cond->prefix_len))
							break;
					}
					yes = 0;
					break;
				}

				if (cond->prefix_len == 0)
					break;
				if (bitstring_match(addr, cond->addr,
							cond->prefix_len))
					break;
				yes = 0;
				break;
			}
		}

		log("pos %04ld len %04d: %15s (%d) - yes %5d no %5d - %s\n", bc - orig_bc, len, op_name(op->code), op->code, op->yes, op->no, yes ? "true" : "false");

		if (yes) {
			len -= op->yes;
			bc += op->yes;
		} else {
			len -= op->no;
			bc += op->no;
		}
	}
	return len == 0;
}

static int valid_cc(const void *bc, int len, int cc)
{
	while (len >= 0) {
		const struct inet_diag_bc_op *op = bc;

		log("cc %d len %d - %s (%d) - yes %d no %d\n", cc, len, op_name(op->code), op->code, op->yes, op->no);

		if (cc > len) {
			log("valid_cc failed - cc greater than len\n");
			return 0;
		}
		if (cc == len) {
			log("valid_cc passed\n");
			return 1;
		}
		if (op->yes < 4 || op->yes & 3) {
			log("valid_cc failed - yes not 4-aligned\n");
			return 0;
		}
		len -= op->yes;
		bc  += op->yes;
	}
	log("valid_cc failed - len ran out\n");
	return 0;
}

/* Validate an inet_diag_hostcond. */
static bool valid_hostcond(const struct inet_diag_bc_op *op, int len,
		int *min_len)
{
	struct inet_diag_hostcond *cond;
	int addr_len;

	/* Check hostcond space. */
	*min_len += sizeof(struct inet_diag_hostcond);
	if (len < *min_len)
		return false;
	cond = (struct inet_diag_hostcond *)(op + 1);

	/* Check address family and address length. */
	switch (cond->family) {
		case AF_UNSPEC:
			addr_len = 0;
			break;
		case AF_INET:
			addr_len = sizeof(struct in_addr);
			break;
		case AF_INET6:
			addr_len = sizeof(struct in6_addr);
			break;
		default:
			return false;
	}
	*min_len += addr_len;
	if (len < *min_len)
		return false;

	/* Check prefix length (in bits) vs address length (in bytes). */
	if (cond->prefix_len > 8 * addr_len)
		return false;

	return true;
}

/* Validate a port comparison operator. */
static bool valid_port_comparison(const struct inet_diag_bc_op *op,
		int len, int *min_len)
{
	/* Port comparisons put the port in a follow-on inet_diag_bc_op. */
	*min_len += sizeof(struct inet_diag_bc_op);
	if (len < *min_len)
		return false;
	return true;
}

static int inet_diag_bc_audit(const void *bytecode, int bytecode_len)
{
	const void *bc = bytecode;
	int  len = bytecode_len;

	while (len > 0) {
		int min_len = sizeof(struct inet_diag_bc_op);
		const struct inet_diag_bc_op *op = bc;

		log("%s (%d) - yes %d no %d\n", op_name(op->code), op->code, op->yes, op->no);

		switch (op->code) {
			case INET_DIAG_BC_S_COND:
			case INET_DIAG_BC_D_COND:
				if (!valid_hostcond(bc, len, &min_len))
					return -EINVAL;
				break;
			case INET_DIAG_BC_S_GE:
			case INET_DIAG_BC_S_LE:
			case INET_DIAG_BC_D_GE:
			case INET_DIAG_BC_D_LE:
				if (!valid_port_comparison(bc, len, &min_len))
					return -EINVAL;
				break;
			case INET_DIAG_BC_AUTO:
			case INET_DIAG_BC_JMP:
			case INET_DIAG_BC_NOP:
				break;
			default:
				return -EINVAL;
		}

		if (op->code != INET_DIAG_BC_NOP) {
			if (op->no < min_len || op->no > len + 4 || op->no & 3)
				return -EINVAL;
			if (op->no < len &&
					!valid_cc(bytecode, bytecode_len, len - op->no))
				return -EINVAL;
		}

		if (op->yes < min_len || op->yes > len + 4 || op->yes & 3)
			return -EINVAL;
		bc  += op->yes;
		len -= op->yes;
	}
	return len == 0 ? 0 : -EINVAL;
}

int read_file(char * filename, char *buffer, long length)
{
	FILE *fp;
	long fsize, total = 0, num_read;

	fp = fopen(filename, "rb");
	if (!fp)
		return -1;

	//Get the size
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if(fsize > length)
		fsize = length;

	while (total < fsize)
	{
		num_read = fread(buffer + total, 1, fsize, fp);
		total += num_read;
	}

	fclose(fp);

	return fsize;
}

#ifdef KLEE
#define FUZZ_BUFFER_SIZE 256
#elif defined(KLEE_DEBUG)
#define FUZZ_BUFFER_SIZE 256
#else
#define FUZZ_BUFFER_SIZE (64*1024)
#endif


static void run_test(char * buffer, int length, u16 family, struct inet_diag_entry * entry) {
	entry->family = family;
	entry->userlocks = 0;
	log("family %hu, userlocks %d\n", family, entry->userlocks);
	inet_diag_bc_run(buffer, length, entry);
	entry->userlocks = 1;
	log("family %hu, userlocks %d\n", family, entry->userlocks);
	inet_diag_bc_run(buffer, length, entry);
}

int main(int argc, char **argv)
{
	struct x509_certificate * cert;
	char * fuzz_filename;
	int fuzz_length;
	struct inet_diag_entry entry;
	__be32 saddr[32];
	__be32 daddr[32];
	char * fuzz_buffer;

	fuzz_buffer = malloc(FUZZ_BUFFER_SIZE);
	if(!fuzz_buffer) {
		printf("Failed to allocate fuzz buffer\n");
		return 1;
	}

#ifndef KLEE
	if(argc < 2) {
		printf("Usage: bc filename\n");
		return 1;
	}
	fuzz_filename = argv[1];
#endif

	//Setup the fake entry
	memset(&entry, 0, sizeof(entry));
	memset(&saddr, 0, sizeof(saddr));
	memset(&daddr, 0, sizeof(daddr));
	entry.saddr = (__be32 *)&saddr;
	entry.daddr = (__be32 *)&daddr;
	entry.sport = 16*1024;
	entry.dport = 32*1024;

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif

#ifdef __AFL_LOOP
	while (__AFL_LOOP(1000)) {
#endif

		memset(fuzz_buffer, 0, FUZZ_BUFFER_SIZE);

#ifdef KLEE
		unsigned short size;
		klee_make_symbolic(&size, sizeof(short), "size");
		size &= 0xff;

		klee_assume(size < FUZZ_BUFFER_SIZE);
		fuzz_length = size;
		if(fuzz_length == 0)
			return 1;

		klee_make_symbolic(fuzz_buffer, FUZZ_BUFFER_SIZE, "buffer");

#else

		fuzz_length = read_file(fuzz_filename, fuzz_buffer, FUZZ_BUFFER_SIZE);
		if(fuzz_length < 0)
#ifdef __AFL_LOOP
			continue;
#else
		return 1;
#endif
#endif

		if(inet_diag_bc_audit(fuzz_buffer, fuzz_length)) {
			log("Audit failed\n");
#ifdef __AFL_LOOP
			continue;
#else
			return 1;
#endif
		}

		run_test(fuzz_buffer, fuzz_length, AF_UNSPEC, &entry);
		run_test(fuzz_buffer, fuzz_length, AF_INET, &entry);
		run_test(fuzz_buffer, fuzz_length, AF_INET6, &entry);

#ifdef __AFL_LOOP
	}
#endif

	free(fuzz_buffer);

	return 0;
}

