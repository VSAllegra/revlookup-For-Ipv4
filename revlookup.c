#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "xpthread.h"
#include "mu.h"
#include "uthash.h"


struct ipdomain {
    char ip_key[INET_ADDRSTRLEN]; /*key */
    char domain[NI_MAXHOST];
    UT_hash_handle hh;
};


struct ipdomain_hashtable {
    struct ipdomain *nodes;
    pthread_mutex_t lock;
};


struct ipdomain_hashtable *g_ipdomain_ht = NULL;

static bool
is_ipv4_str(const char *s)
{
    struct sockaddr_in sai;
    int err; 

    err = inet_pton(AF_INET, s, &sai.sin_addr);
    if (err == 1){
        return true;
    }else 
        mu_panic("inet_pton returned %d (%s)\n", err, strerror(errno));
}


struct tpool {
    /* circular queue: an array where each element is a char[INET_ADDRSTRLEN] */
    char (*queue)[INET_ADDRSTRLEN];
    size_t max_queue_size;
    size_t sidx;
    size_t eidx; /* exclusive */
    /* 
     * need an explicit count of items in queue to disambiguate sidx == edix, which could
     * mean either empty or full
     */
    size_t queue_size;  

    /* queue locking and signaling */
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_not_empty; /* producer inserts to empty queue */
    pthread_cond_t queue_not_full;  /* consumer dequeues from full queue */
    pthread_cond_t queue_empty;     /* consumer dequeues and makes queue empty */
    bool shutdown;                  /* queue is empty and producer has no more data */

    /* worker threads */
    size_t num_threads;
    pthread_t *threads;
};


struct worker_arg {
    struct tpool *tpool;
    unsigned int id;
};


static struct ipdomain *
ipdomain_new(const char *ip_str, const char *domain)
{
    MU_NEW(ipdomain, node);
    size_t len;

    len = mu_strlcpy(node->ip_key, ip_str, sizeof(node->ip_key));
    assert(len < sizeof(node->ip_key));

    len = mu_strlcpy(node->domain, domain, sizeof(node->domain));
    assert(len < sizeof(node->domain));

    return node;
}


static void
ipdomain_free(struct ipdomain *node)
{
    free(node);
}


static struct ipdomain_hashtable *
ipdomain_hashtable_new(void)
{
    MU_NEW(ipdomain_hashtable, ht);
    pthread_mutexattr_t attr;

    ht->nodes = NULL;

    xpthread_mutexattr_init(&attr);
    xpthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    xpthread_mutex_init(&ht->lock, &attr);
    xpthread_mutexattr_destroy(&attr);

    return ht;

}

static void
ipdomain_hashtable_free(struct ipdomain_hashtable *ht)
{
    struct ipdomain *node, *tmp;

    HASH_ITER(hh, ht->nodes, node, tmp) {
        HASH_DEL(ht->nodes, node);
        ipdomain_free(node);
    }

    xpthread_mutex_destroy(&ht->lock);
    free(ht);
}


static bool
ipdomain_hashtable_has(struct ipdomain_hashtable *ht, const char *ip_str)
{
    bool found = false;
    struct ipdomain *node = NULL;

    xpthread_mutex_lock(&ht->lock);

    HASH_FIND_STR(ht->nodes, ip_str, node);
    if (node != NULL)
        found = true;

    xpthread_mutex_unlock(&ht->lock);

    return found;
}


static void
ipdomain_hashtable_insert(struct ipdomain_hashtable *ht, const char *ip_str, const char *domain)
{
    struct ipdomain *node;

    xpthread_mutex_lock(&ht->lock);

    HASH_FIND_STR(ht->nodes, ip_str, node);
    if (node != NULL)
        goto done;

    node = ipdomain_new(ip_str, domain);
    HASH_ADD_STR(ht->nodes, ip_key, node);

done:
    xpthread_mutex_unlock(&ht->lock);
}


static void
ipdomain_hashtable_print(const struct ipdomain_hashtable *ht)
{
    size_t i = 1;
    struct ipdomain *node, *tmp;

    HASH_ITER(hh, ht->nodes, node, tmp) {
        printf("%6zu: %s => %s\n", i, node->ip_key, node->domain);
        i++;
    } 
}


/* For all tpool_queue_* functions, the caller must hold tpool->queue_lock */

static size_t
tpool_queue_size(const struct tpool *tpool)
{
    return tpool->queue_size;
}


static bool
tpool_queue_is_empty(const struct tpool *tpool)
{
    return tpool->queue_size == 0;
}


static bool
tpool_queue_is_full(const struct tpool *tpool)
{
    return tpool->queue_size == tpool->max_queue_size;
}


/* Precondition: queue is not empty */
static void
tpool_queue_dequeue(struct tpool *tpool, char *dst, size_t dst_size)
{
    size_t len;

    assert(!tpool_queue_is_empty(tpool));

    len = mu_strlcpy(dst, tpool->queue[tpool->sidx], dst_size);
    assert(len < dst_size);

    tpool->sidx = (tpool->sidx + 1) % tpool->max_queue_size;
    tpool->queue_size--;
}


/* Precondition: queue is not full */
static void
tpool_queue_insert(struct tpool *tpool, char *ip_str)
{
    size_t len;

    assert(!tpool_queue_is_full(tpool));

    len = mu_strlcpy(tpool->queue[tpool->eidx], ip_str, INET_ADDRSTRLEN);
    assert(len < INET_ADDRSTRLEN);

    tpool->eidx = (tpool->eidx + 1) % tpool->max_queue_size;
    tpool->queue_size++;
}


static struct worker_arg *
worker_arg_new(struct tpool *tpool, unsigned int id)
{
    MU_NEW(worker_arg, w);

    w->tpool = tpool;
    w->id = id;

    return w;
}


static void
worker_arg_free(struct worker_arg *w)
{
    free(w);
}


static void *
tpool_worker(void *arg /* worker_arg */)
{
    struct worker_arg *w = arg;
    struct tpool *tpool = w->tpool;

    /* 
     * TODO
     * worker: take an IP address from the queue; if IP is not in hashtable,
     * then try to resovle it to a domain name, and insert the
     * (IP, domain name) into the hashtable.
     */
    MU_UNUSED(w);
    MU_UNUSED(tpool);

    return NULL;
}


static void
tpool_add_work(struct tpool *tpool, char *ip_str)
{
    tpool_queue_insert(tpool, ip_str);
    /* 
     * TODO 
     * manager: add an IP address to the queue
     */
}


static void
tpool_wait_finish(struct tpool *tpool)
{
    /* 
     * TODO 
     * manager: wait for workers to drain any data that is still in the queue, and
     * then join all worker threads
     */
    MU_UNUSED(tpool);
}


static struct tpool *
tpool_new(size_t num_worker_threads, size_t max_queue_size)
{
    MU_NEW(tpool, tpool);
    pthread_mutexattr_t attr;
    struct worker_arg *w;
    unsigned int i;

    tpool->num_threads = num_worker_threads;
    tpool->max_queue_size = max_queue_size;
    tpool->queue = mu_mallocarray(max_queue_size, INET_ADDRSTRLEN);

    xpthread_mutexattr_init(&attr);
    xpthread_mutexattr_settype(&attr, PTHREAD_MUTEX_ERRORCHECK);
    xpthread_mutex_init(&tpool->queue_lock, NULL);
    xpthread_mutexattr_destroy(&attr);

    xpthread_cond_init(&tpool->queue_not_empty, NULL);
    xpthread_cond_init(&tpool->queue_not_full, NULL);
    xpthread_cond_init(&tpool->queue_empty, NULL);

    tpool->threads = mu_mallocarray(num_worker_threads, sizeof(pthread_t));
    for (i = 0; i < num_worker_threads; i++) {
        w = worker_arg_new(tpool, i);
        mu_pr_debug("manager: spawning worker %u", w->id);
        xpthread_create(&tpool->threads[i], NULL, tpool_worker, w);
    }

    return tpool;
}


static void
tpool_free(struct tpool *tpool)
{
    xpthread_mutex_destroy(&tpool->queue_lock);
    xpthread_cond_destroy(&tpool->queue_not_empty);
    xpthread_cond_destroy(&tpool->queue_not_full);
    xpthread_cond_destroy(&tpool->queue_empty);

    free(tpool->threads);
    free(tpool->queue);
    free(tpool);
}


static void
tpool_process_file(struct tpool *tpool, char *input_file)
{
    FILE * fh;
    ssize_t len = 0;
    size_t n = 0;
    char * line = NULL;

    MU_UNUSED(tpool);



    fh = fopen(input_file, "r");
    if (fh == NULL)
        mu_die_errno(errno, "can't open");
    while(1){
        errno = 0 
        len = getline(&line, &n, fh)
        if (len == -1){
            if (errno != 0)
                mu_die_errno(errno, "error reading the file")
            goto out;
        }

        mu_str_chomp(line);
        if ( !is_ipv4_str(line)) 
            mu_stderr("%s : invalid IPv4 string: \"%s\"", input_file);
    
        printf("%s\n", line);
      
    }

out: 
    free(line);
    fclose(fh);
}


int 
main(int argc,char *argv[])
{
    struct tpool *tpool;

    if(argc != 2)
        mu_die("Usage: %s IF_LIST_FILE", argv[0]);
    
    tpool = tpool_new(4, 2);
    tpool_process_file(tpool, argv[1]);

    tpool_free(tpool);


    return 0;
}