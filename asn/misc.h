#ifndef __MISC_H__
#define __MISC_H__

#define fips_enabled 0

#define unlikely(x)  x
#ifdef DEBUG
#define pr_devel printf
#define pr_debug printf
#define pr_warn printf
#define pr_err printf
#define printk printf
#else
#define pr_devel(...)
#define pr_debug(...)
#define pr_warn(...)
#define pr_err(...)
#define printk(...)
#endif

#define u8 unsigned char
#define u16 unsigned short
#define time64_t int64_t
#define bool int

//Taken from include/linux/err.h:

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void * ERR_PTR(long error)
{
	return (void *) error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

int read_file(char * filename, char *buffer, long length);

#endif //__MISC_H__
