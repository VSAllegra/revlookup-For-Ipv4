#ifndef _XPTHREAD_H_
#define _XPTHREAD_H_

#include <pthread.h>

#include "mu.h"


#define xpthread_create(thread, attr, start_routine, arg) \
    do { \
        int err = pthread_create(thread, attr, start_routine, arg); \
        if (err != 0) \
            mu_die_errno(err, "pthread_create"); \
    } while (0)

#define xpthread_join(thread, retval) \
    do { \
        int err = pthread_join(thread, retval); \
        if (err != 0) \
            mu_die_errno(err, "pthread_join"); \
    } while (0)

#define xpthread_mutexattr_init(attr) \
    do { \
        int err = pthread_mutexattr_init(attr); \
        if (err != 0) \
            mu_die_errno(err, "pthread_mutexattr_init"); \
    } while (0)

#define xpthread_mutexattr_settype(attr, type) \
    do { \
        int err = pthread_mutexattr_settype(attr, type); \
        if (err != 0) \
            mu_die_errno(err, "pthread_mutexattr_settype"); \
    } while (0)

#define xpthread_mutexattr_destroy(attr) \
    do { \
        int err = pthread_mutexattr_destroy(attr); \
        if (err != 0) \
            mu_die_errno(err, "pthread_mutexattr_destroy"); \
    } while (0)

#define xpthread_mutex_init(mutex, attr) \
    do { \
        int err = pthread_mutex_init(mutex, attr); \
        if (err != 0) \
            mu_die_errno(err, "pthread_mutex_init"); \
    } while (0)

#define xpthread_mutex_destroy(mutex) \
    do { \
        int err = pthread_mutex_destroy(mutex); \
        if (err != 0) \
            mu_die_errno(err, "pthread_mutex_destroy"); \
    } while (0)

#define xpthread_mutex_lock(mutex) \
    do { \
        int err = pthread_mutex_lock(mutex); \
        if (err != 0) \
            mu_die_errno(err, "pthread_mutex_lock"); \
    } while (0)

#define xpthread_mutex_unlock(mutex) \
    do { \
        int err = pthread_mutex_unlock(mutex); \
        if (err != 0) \
            mu_die_errno(err, "pthread_mutex_unlock"); \
    } while (0)

#define xpthread_cond_init(cond, attr) \
    do { \
        int err = pthread_cond_init(cond, attr); \
        if (err != 0) \
            mu_die_errno(err, "pthread_cond_init"); \
    } while (0)

#define xpthread_cond_destroy(cond) \
    do { \
        int err = pthread_cond_destroy(cond); \
        if (err != 0) \
            mu_die_errno(err, "pthread_cond_destroy"); \
    } while (0)

#define xpthread_cond_wait(cond, mutex) \
    do { \
        int err = pthread_cond_wait(cond, mutex); \
        if (err != 0) \
            mu_die_errno(err, "pthread_cond_wait"); \
    } while (0)

#define xpthread_cond_signal(cond) \
    do { \
        int err = pthread_cond_signal(cond); \
        if (err != 0) \
            mu_die_errno(err, "pthread_cond_signal"); \
    } while (0)

#define xpthread_cond_broadcast(cond) \
    do { \
        int err = pthread_cond_broadcast(cond); \
        if (err != 0) \
            mu_die_errno(err, "pthread_cond_broadcast"); \
    } while (0)


#endif /* _XPTHREAD_H_ */