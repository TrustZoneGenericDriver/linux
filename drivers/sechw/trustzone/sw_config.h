/* 
 * config variable declaration
 */

#ifndef SW_CONFIG
#define SW_CONFIG
#if defined(__GNUC__) && \
        defined(__GNUC_MINOR__) && \
defined(__GNUC_PATCHLEVEL__) && \
((__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)) \
> 40600
#define USE_ARCH_EXTENSION_SEC 1
#else
#define USE_ARCH_EXTENSION_SEC 0
#endif
#endif
