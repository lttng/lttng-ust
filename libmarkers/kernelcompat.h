#ifndef KERNELCOMPAT_H
#define KERNELCOMPAT_H

#include <string.h>

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define KERN_DEBUG
#define KERN_NOTICE

static inline void *ERR_PTR(long error)
{
        return (void *) error;
}


#include <stdint.h>

typedef uint16_t u16;
typedef uint32_t u32;


#include <pthread.h>

#define DEFINE_MUTEX(m) pthread_mutex_t (m) = PTHREAD_MUTEX_INITIALIZER;

#define mutex_lock(m) pthread_mutex_lock(m)

#define mutex_unlock(m) pthread_mutex_unlock(m)


#include <stdlib.h>

#define kmalloc(s, t) malloc(s)
#define kzalloc(s, t) malloc(s)
#define kfree(p) free((void *)p)
#define kstrdup(s, t) strdup(s)


#include <stdio.h>
#define printk(fmt, args...) printf(fmt, ## args)



#define smp_rmb()
#define smp_wmb()


#define read_barrier_depends()
#define smp_read_barrier_depends()


#define rcu_assign_pointer(a, b)
#endif /* KERNELCOMPAT_H */
