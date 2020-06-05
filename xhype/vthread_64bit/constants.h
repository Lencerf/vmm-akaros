#ifndef __CONSTANTS_H__
#define __CONSTANTS_H__
#define KiB (1 << 10)
#define MiB (1 << 20)
#define GiB (1 << 30)
#define PAGESIZE (1 << 12)

#ifndef ALIGNUP
#define ALIGNUP(x, a) (((x - 1) & ~(a - 1)) + a)
#endif

#ifndef ALIGNDOWN
#define ALIGNDOWN(x, a) (-(a) & (x))
#endif

#endif