#ifndef DynTypes_h__
#define DynTypes_h__


#if defined HAVE_STDINT_H
#include <stdint.h>
#else
#if defined __LCC__ || defined __DMC__ || defined LINUX || defined __APPLE__
#if defined HAVE_INTTYPES_H
#include <inttypes.h>
#else
#include <stdint.h>
#endif
#elif !defined __STDC_VERSION__ || __STDC_VERSION__ < 199901L
/* The ISO C99 defines the int16_t and int_32t types. If the compiler got
* here, these types are probably undefined.
*/
#if defined __MACH__
#include <ppc/types.h>
typedef unsigned short int  uint16_t;
typedef unsigned long int   uint32_t;
#elif defined __FreeBSD__
#include <inttypes.h>
#else
typedef short int           int16_t;
typedef unsigned short int  uint16_t;
#if defined SN_TARGET_PS2
typedef int               int32_t;
typedef unsigned int      uint32_t;
#else
typedef long int          int32_t;
typedef unsigned long int uint32_t;
#endif
#if defined __WIN32__ || defined _WIN32 || defined WIN32
typedef __int64	          int64_t;
typedef unsigned __int64  uint64_t;
#define HAVE_I64
#elif defined __GNUC__
typedef long long         int64_t;
typedef unsigned long long uint64_t;
#define HAVE_I64
#endif
#endif
#endif
#define HAVE_STDINT_H
#endif

typedef unsigned char uint8_t;



#endif // DynTypes_h__
