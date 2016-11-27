/* Redis Object implementation.
 *
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "server.h"
#include <math.h>
#include <ctype.h>

#ifdef __CYGWIN__
#define strtold(a,b) ((long double)strtod((a),(b)))
#endif

/* ===================== Creation and parsing of objects ==================== */

robj *createObject(int type, void *ptr) {
    robj *o = zmalloc(sizeof(*o));
    o->type = type;
    o->encoding = OBJ_ENCODING_RAW;
    o->ptr = ptr;
    o->refcount = 1;

    return o;
}

/* Set a special refcount in the object to make it "shared":
 * incrRefCount and decrRefCount() will test for this special refcount
 * and will not touch the object. This way it is free to access shared
 * objects such as small integers from different threads without any
 * mutex.
 *
 * A common patter to create shared objects:
 *
 * robj *myobject = makeObjectShared(createObject(...));
 *
 */
robj *makeObjectShared(robj *o) {
    serverAssert(o->refcount == 1);
    o->refcount = OBJ_SHARED_REFCOUNT;
    return o;
}

/* Create a string object with encoding OBJ_ENCODING_RAW, that is a plain
 * string object where o->ptr points to a proper sds string. */
robj *createRawStringObject(const char *ptr, size_t len) {
    return createObject(OBJ_STRING, sdsnewlen(ptr,len));
}

/* Create a string object with encoding OBJ_ENCODING_EMBSTR, that is
 * an object where the sds string is actually an unmodifiable string
 * allocated in the same chunk as the object itself. */
robj *createEmbeddedStringObject(const char *ptr, size_t len) {
    robj *o = zmalloc(sizeof(robj)+sizeof(struct sdshdr8)+len+1);
    struct sdshdr8 *sh = (void*)(o+1);

    o->type = OBJ_STRING;
    o->encoding = OBJ_ENCODING_EMBSTR;
    o->ptr = sh+1;
    o->refcount = 1;

    sh->len = len;
    sh->alloc = len;
    sh->flags = SDS_TYPE_8;
    if (ptr) {
        memcpy(sh->buf,ptr,len);
        sh->buf[len] = '\0';
    } else {
        memset(sh->buf,0,len+1);
    }
    return o;
}

/* Create a string object with EMBSTR encoding if it is smaller than
 * OBJ_ENCODING_EMBSTR_SIZE_LIMIT, otherwise the RAW encoding is
 * used.
 *
 * The current limit of 39 is chosen so that the biggest string object
 * we allocate as EMBSTR will still fit into the 64 byte arena of jemalloc. */
#define OBJ_ENCODING_EMBSTR_SIZE_LIMIT 44
robj *createStringObject(const char *ptr, size_t len) {
    if (len <= OBJ_ENCODING_EMBSTR_SIZE_LIMIT)
        return createEmbeddedStringObject(ptr,len);
    else
        return createRawStringObject(ptr,len);
}

robj *createStringObjectFromLongLong(long long value) {
    robj *o;
    if (value >= 0 && value < OBJ_SHARED_INTEGERS) {
        incrRefCount(shared.integers[value]);
        o = shared.integers[value];
    } else {
        if (value >= LONG_MIN && value <= LONG_MAX) {
            o = createObject(OBJ_STRING, NULL);
            o->encoding = OBJ_ENCODING_INT;
            o->ptr = (void*)((long)value);
        } else {
            o = createObject(OBJ_STRING,sdsfromlonglong(value));
        }
    }
    return o;
}

/* Create a string object from a long double. If humanfriendly is non-zero
 * it does not use exponential format and trims trailing zeroes at the end,
 * however this results in loss of precision. Otherwise exp format is used
 * and the output of snprintf() is not modified.
 *
 * The 'humanfriendly' option is used for INCRBYFLOAT and HINCRBYFLOAT. */
robj *createStringObjectFromLongDouble(long double value, int humanfriendly) {
    char buf[256];
    int len = ld2string(buf,sizeof(buf),value,humanfriendly);
    return createStringObject(buf,len);
}

/* Duplicate a string object, with the guarantee that the returned object
 * has the same encoding as the original one.
 *
 * This function also guarantees that duplicating a small integere object
 * (or a string object that contains a representation of a small integer)
 * will always result in a fresh object that is unshared (refcount == 1).
 *
 * The resulting object always has refcount set to 1. */
robj *dupStringObject(const robj *o) {
    robj *d;

    serverAssert(o->type == OBJ_STRING);

    switch(o->encoding) {
    case OBJ_ENCODING_RAW:
        return createRawStringObject(o->ptr,sdslen(o->ptr));
    case OBJ_ENCODING_EMBSTR:
        return createEmbeddedStringObject(o->ptr,sdslen(o->ptr));
    case OBJ_ENCODING_INT:
        d = createObject(OBJ_STRING, NULL);
        d->encoding = OBJ_ENCODING_INT;
        d->ptr = o->ptr;
        return d;
    default:
        serverPanic("Wrong encoding.");
        break;
    }
}

void freeStringObject(robj *o) {
    if (o->encoding == OBJ_ENCODING_RAW) {
        sdsfree(o->ptr);
    }
}

void incrRefCount(robj *o) {
    if (o->refcount != OBJ_SHARED_REFCOUNT) o->refcount++;
}

void decrRefCount(robj *o) {
    if (o->refcount == 1) {
        switch(o->type) {
        case OBJ_STRING: freeStringObject(o); break;
        default: serverPanic("Unknown object type"); break;
        }
        zfree(o);
    } else {
        if (o->refcount <= 0) serverPanic("decrRefCount against refcount <= 0");
        if (o->refcount != OBJ_SHARED_REFCOUNT) o->refcount--;
    }
}

/* This variant of decrRefCount() gets its argument as void, and is useful
 * as free method in data structures that expect a 'void free_object(void*)'
 * prototype for the free method. */
void decrRefCountVoid(void *o) {
    decrRefCount(o);
}

/* This function set the ref count to zero without freeing the object.
 * It is useful in order to pass a new object to functions incrementing
 * the ref count of the received object. Example:
 *
 *    functionThatWillIncrementRefCount(resetRefCount(CreateObject(...)));
 *
 * Otherwise you need to resort to the less elegant pattern:
 *
 *    *obj = createObject(...);
 *    functionThatWillIncrementRefCount(obj);
 *    decrRefCount(obj);
 */
robj *resetRefCount(robj *obj) {
    obj->refcount = 0;
    return obj;
}

int checkType(client *c, robj *o, int type) {
    if (o->type != type) {
        addReply(c,shared.wrongtypeerr);
        return 1;
    }
    return 0;
}

int isSdsRepresentableAsLongLong(sds s, long long *llval) {
    return string2ll(s,sdslen(s),llval) ? C_OK : C_ERR;
}

int isObjectRepresentableAsLongLong(robj *o, long long *llval) {
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
    if (o->encoding == OBJ_ENCODING_INT) {
        if (llval) *llval = (long) o->ptr;
        return C_OK;
    } else {
        return isSdsRepresentableAsLongLong(o->ptr,llval);
    }
}

/* Try to encode a string object in order to save space */
robj *tryObjectEncoding(robj *o) {
    long value;
    sds s = o->ptr;
    size_t len;

    /* Make sure this is a string object, the only type we encode
     * in this function. Other types use encoded memory efficient
     * representations but are handled by the commands implementing
     * the type. */
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);

    /* We try some specialized encoding only for objects that are
     * RAW or EMBSTR encoded, in other words objects that are still
     * in represented by an actually array of chars. */
    if (!sdsEncodedObject(o)) return o;

    /* It's not safe to encode shared objects: shared objects can be shared
     * everywhere in the "object space" of Redis and may end in places where
     * they are not handled. We handle them only as values in the keyspace. */
     if (o->refcount > 1) return o;

    /* Check if we can represent this string as a long integer.
     * Note that we are sure that a string larger than 20 chars is not
     * representable as a 32 nor 64 bit integer. */
    len = sdslen(s);
    if (len <= 20 && string2l(s,len,&value)) {
        /* This object is encodable as a long. Try to use a shared object. */
        if (o->encoding == OBJ_ENCODING_RAW) sdsfree(o->ptr);
        o->encoding = OBJ_ENCODING_INT;
        o->ptr = (void*) value;
        return o;
    }

    /* If the string is small and is still RAW encoded,
     * try the EMBSTR encoding which is more efficient.
     * In this representation the object and the SDS string are allocated
     * in the same chunk of memory to save space and cache misses. */
    if (len <= OBJ_ENCODING_EMBSTR_SIZE_LIMIT) {
        robj *emb;

        if (o->encoding == OBJ_ENCODING_EMBSTR) return o;
        emb = createEmbeddedStringObject(s,sdslen(s));
        decrRefCount(o);
        return emb;
    }

    /* We can't encode the object...
     *
     * Do the last try, and at least optimize the SDS string inside
     * the string object to require little space, in case there
     * is more than 10% of free space at the end of the SDS string.
     *
     * We do that only for relatively large strings as this branch
     * is only entered if the length of the string is greater than
     * OBJ_ENCODING_EMBSTR_SIZE_LIMIT. */
    if (o->encoding == OBJ_ENCODING_RAW &&
        sdsavail(s) > len/10)
    {
        o->ptr = sdsRemoveFreeSpace(o->ptr);
    }

    /* Return the original object. */
    return o;
}

/* Get a decoded version of an encoded object (returned as a new object).
 * If the object is already raw-encoded just increment the ref count. */
robj *getDecodedObject(robj *o) {
    robj *dec;

    if (sdsEncodedObject(o)) {
        incrRefCount(o);
        return o;
    }
    if (o->type == OBJ_STRING && o->encoding == OBJ_ENCODING_INT) {
        char buf[32];

        ll2string(buf,32,(long)o->ptr);
        dec = createStringObject(buf,strlen(buf));
        return dec;
    } else {
        serverPanic("Unknown encoding type");
    }
}

/* Compare two string objects via strcmp() or strcoll() depending on flags.
 * Note that the objects may be integer-encoded. In such a case we
 * use ll2string() to get a string representation of the numbers on the stack
 * and compare the strings, it's much faster than calling getDecodedObject().
 *
 * Important note: when REDIS_COMPARE_BINARY is used a binary-safe comparison
 * is used. */

#define REDIS_COMPARE_BINARY (1<<0)
#define REDIS_COMPARE_COLL (1<<1)

int compareStringObjectsWithFlags(robj *a, robj *b, int flags) {
    serverAssertWithInfo(NULL,a,a->type == OBJ_STRING && b->type == OBJ_STRING);
    char bufa[128], bufb[128], *astr, *bstr;
    size_t alen, blen, minlen;

    if (a == b) return 0;
    if (sdsEncodedObject(a)) {
        astr = a->ptr;
        alen = sdslen(astr);
    } else {
        alen = ll2string(bufa,sizeof(bufa),(long) a->ptr);
        astr = bufa;
    }
    if (sdsEncodedObject(b)) {
        bstr = b->ptr;
        blen = sdslen(bstr);
    } else {
        blen = ll2string(bufb,sizeof(bufb),(long) b->ptr);
        bstr = bufb;
    }
    if (flags & REDIS_COMPARE_COLL) {
        return strcoll(astr,bstr);
    } else {
        int cmp;

        minlen = (alen < blen) ? alen : blen;
        cmp = memcmp(astr,bstr,minlen);
        if (cmp == 0) return alen-blen;
        return cmp;
    }
}

/* Wrapper for compareStringObjectsWithFlags() using binary comparison. */
int compareStringObjects(robj *a, robj *b) {
    return compareStringObjectsWithFlags(a,b,REDIS_COMPARE_BINARY);
}

/* Wrapper for compareStringObjectsWithFlags() using collation. */
int collateStringObjects(robj *a, robj *b) {
    return compareStringObjectsWithFlags(a,b,REDIS_COMPARE_COLL);
}

/* Equal string objects return 1 if the two objects are the same from the
 * point of view of a string comparison, otherwise 0 is returned. Note that
 * this function is faster then checking for (compareStringObject(a,b) == 0)
 * because it can perform some more optimization. */
int equalStringObjects(robj *a, robj *b) {
    if (a->encoding == OBJ_ENCODING_INT &&
        b->encoding == OBJ_ENCODING_INT){
        /* If both strings are integer encoded just check if the stored
         * long is the same. */
        return a->ptr == b->ptr;
    } else {
        return compareStringObjects(a,b) == 0;
    }
}

size_t stringObjectLen(robj *o) {
    serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
    if (sdsEncodedObject(o)) {
        return sdslen(o->ptr);
    } else {
        return sdigits10((long)o->ptr);
    }
}

int getDoubleFromObject(const robj *o, double *target) {
    double value;
    char *eptr;

    if (o == NULL) {
        value = 0;
    } else {
        serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
        if (sdsEncodedObject(o)) {
            errno = 0;
            value = strtod(o->ptr, &eptr);
            if (isspace(((const char*)o->ptr)[0]) ||
                eptr[0] != '\0' ||
                (errno == ERANGE &&
                    (value == HUGE_VAL || value == -HUGE_VAL || value == 0)) ||
                errno == EINVAL ||
                isnan(value))
                return C_ERR;
        } else if (o->encoding == OBJ_ENCODING_INT) {
            value = (long)o->ptr;
        } else {
            serverPanic("Unknown string encoding");
        }
    }
    *target = value;
    return C_OK;
}

int getDoubleFromObjectOrReply(client *c, robj *o, double *target, const char *msg) {
    double value;
    if (getDoubleFromObject(o, &value) != C_OK) {
        if (msg != NULL) {
            addReplyError(c,(char*)msg);
        } else {
            addReplyError(c,"value is not a valid float");
        }
        return C_ERR;
    }
    *target = value;
    return C_OK;
}

int getLongDoubleFromObject(robj *o, long double *target) {
    long double value;
    char *eptr;

    if (o == NULL) {
        value = 0;
    } else {
        serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
        if (sdsEncodedObject(o)) {
            errno = 0;
            value = strtold(o->ptr, &eptr);
            if (isspace(((char*)o->ptr)[0]) || eptr[0] != '\0' ||
                errno == ERANGE || isnan(value))
                return C_ERR;
        } else if (o->encoding == OBJ_ENCODING_INT) {
            value = (long)o->ptr;
        } else {
            serverPanic("Unknown string encoding");
        }
    }
    *target = value;
    return C_OK;
}

int getLongDoubleFromObjectOrReply(client *c, robj *o, long double *target, const char *msg) {
    long double value;
    if (getLongDoubleFromObject(o, &value) != C_OK) {
        if (msg != NULL) {
            addReplyError(c,(char*)msg);
        } else {
            addReplyError(c,"value is not a valid float");
        }
        return C_ERR;
    }
    *target = value;
    return C_OK;
}

int getLongLongFromObject(robj *o, long long *target) {
    long long value;

    if (o == NULL) {
        value = 0;
    } else {
        serverAssertWithInfo(NULL,o,o->type == OBJ_STRING);
        if (sdsEncodedObject(o)) {
            if (string2ll(o->ptr,sdslen(o->ptr),&value) == 0) return C_ERR;
        } else if (o->encoding == OBJ_ENCODING_INT) {
            value = (long)o->ptr;
        } else {
            serverPanic("Unknown string encoding");
        }
    }
    if (target) *target = value;
    return C_OK;
}

int getLongLongFromObjectOrReply(client *c, robj *o, long long *target, const char *msg) {
    long long value;
    if (getLongLongFromObject(o, &value) != C_OK) {
        if (msg != NULL) {
            addReplyError(c,(char*)msg);
        } else {
            addReplyError(c,"value is not an integer or out of range");
        }
        return C_ERR;
    }
    *target = value;
    return C_OK;
}

int getLongFromObjectOrReply(client *c, robj *o, long *target, const char *msg) {
    long long value;

    if (getLongLongFromObjectOrReply(c, o, &value, msg) != C_OK) return C_ERR;
    if (value < LONG_MIN || value > LONG_MAX) {
        if (msg != NULL) {
            addReplyError(c,(char*)msg);
        } else {
            addReplyError(c,"value is out of range");
        }
        return C_ERR;
    }
    *target = value;
    return C_OK;
}

char *strEncoding(int encoding) {
    switch(encoding) {
    case OBJ_ENCODING_RAW: return "raw";
    case OBJ_ENCODING_INT: return "int";
    case OBJ_ENCODING_HT: return "hashtable";
    case OBJ_ENCODING_QUICKLIST: return "quicklist";
    case OBJ_ENCODING_ZIPLIST: return "ziplist";
    case OBJ_ENCODING_INTSET: return "intset";
    case OBJ_ENCODING_SKIPLIST: return "skiplist";
    case OBJ_ENCODING_EMBSTR: return "embstr";
    default: return "unknown";
    }
}

/* =========================== Memory introspection ========================== */

/* Release data obtained with getMemoryOverheadData(). */
void freeMemoryOverheadData(struct redisMemOverhead *mh) {
    zfree(mh->db);
    zfree(mh);
}

/* Return a struct redisMemOverhead filled with memory overhead
 * information used for the MEMORY OVERHEAD and INFO command. The returned
 * structure pointer should be freed calling freeMemoryOverheadData(). */
struct redisMemOverhead *getMemoryOverheadData(void) {
    int j;
    size_t mem_total = 0;
    size_t mem = 0;
    size_t zmalloc_used = zmalloc_used_memory();
    struct redisMemOverhead *mh = zcalloc(sizeof(*mh));

    mh->total_allocated = zmalloc_used;
    mh->startup_allocated = server.initial_memory_usage;
    mh->peak_allocated = server.stat_peak_memory;
    mh->fragmentation =
        zmalloc_get_fragmentation_ratio(server.resident_set_size);
    mem_total += server.initial_memory_usage;

    mem = 0;
    if (listLength(server.clients)) {
        listIter li;
        listNode *ln;

        listRewind(server.clients,&li);
        while((ln = listNext(&li))) {
            client *c = listNodeValue(ln);
            mem += getClientOutputBufferMemoryUsage(c);
            mem += sdsAllocSize(c->querybuf);
            mem += sizeof(client);
        }
    }
    mh->clients_normal = mem;
    mem_total+=mem;

    for (j = 0; j < server.dbnum; j++) {
        redisDb *db = server.db+j;
        long long keyscount = dictSize(db->dict);
        if (keyscount==0) continue;

        mh->total_keys += keyscount;
        mh->db = zrealloc(mh->db,sizeof(mh->db[0])*(mh->num_dbs+1));
        mh->db[mh->num_dbs].dbid = j;

        mem = dictSize(db->dict) * sizeof(dictEntry) +
              dictSlots(db->dict) * sizeof(dictEntry*) +
              dictSize(db->dict) * sizeof(robj);
        mh->db[mh->num_dbs].overhead_ht_main = mem;
        mem_total+=mem;

        mh->num_dbs++;
    }

    mh->overhead_total = mem_total;
    mh->dataset = zmalloc_used - mem_total;
    mh->peak_perc = (float)zmalloc_used*100/mh->peak_allocated;

    /* Metrics computed after subtracting the startup memory from
     * the total memory. */
    size_t net_usage = 1;
    if (zmalloc_used > mh->startup_allocated)
        net_usage = zmalloc_used - mh->startup_allocated;
    mh->dataset_perc = (float)mh->dataset*100/net_usage;
    mh->bytes_per_key = mh->total_keys ? (net_usage / mh->total_keys) : 0;

    return mh;
}

/* Helper for "MEMORY allocator-stats", used as a callback for the jemalloc
 * stats output. */
void inputCatSds(void *result, const char *str) {
    /* result is actually a (sds *), so re-cast it here */
    sds *info = (sds *)result;
    *info = sdscat(*info, str);
}

/* This implements MEMORY DOCTOR. An human readable analysis of the Redis
 * memory condition. */
sds getMemoryDoctorReport(void) {
    int empty = 0;          /* Instance is empty or almost empty. */
    int big_peak = 0;       /* Memory peak is much larger than used mem. */
    int high_frag = 0;      /* High fragmentation. */
    int big_client_buf = 0; /* Client buffers are too big. */
    int num_reports = 0;
    struct redisMemOverhead *mh = getMemoryOverheadData();

    if (mh->total_allocated < (1024*1024*5)) {
        empty = 1;
        num_reports++;
    } else {
        /* Peak is > 150% of current used memory? */
        if (((float)mh->peak_allocated / mh->total_allocated) > 1.5) {
            big_peak = 1;
            num_reports++;
        }

        /* Fragmentation is higher than 1.4? */
        if (mh->fragmentation > 1.4) {
            high_frag = 1;
            num_reports++;
        }

        /* Clients using more than 200k each average? */
        long numclients = listLength(server.clients);
        if (mh->clients_normal / numclients > (1024*200)) {
            big_client_buf = 1;
            num_reports++;
        }
    }

    sds s;
    if (num_reports == 0) {
        s = sdsnew(
        "Hi Sam, I can't find any memory issue in your instance. "
        "I can only account for what occurs on this base.");
    } else if (empty == 1) {
        s = sdsnew(
        "Hi Sam, this instance is empty or is using very little memory, "
        "my issues detector can't be used in these conditions. "
        "Please, leave for your mission on Earth and fill it with some data. "
        "The new Sam and I will be back to our programming as soon as I "
        "finished rebooting.");
    } else {
        s = sdsnew("Sam, I detected a few issues in this Redis instance memory implants:\n\n");
        if (big_peak) {
            s = sdscat(s," * Peak memory: In the past this instance used more than 150% the memory that is currently using. The allocator is normally not able to release memory after a peak, so you can expect to see a big fragmentation ratio, however this is actually harmless and is only due to the memory peak, and if the Redis instance Resident Set Size (RSS) is currently bigger than expected, the memory will be used as soon as you fill the Redis instance with more data. If the memory peak was only occasional and you want to try to reclaim memory, please try the MEMORY PURGE command, otherwise the only other option is to shutdown and restart the instance.\n\n");
        }
        if (high_frag) {
            s = sdscatprintf(s," * High fragmentation: This instance has a memory fragmentation greater than 1.4 (this means that the Resident Set Size of the Redis process is much larger than the sum of the logical allocations Redis performed). This problem is usually due either to a large peak memory (check if there is a peak memory entry above in the report) or may result from a workload that causes the allocator to fragment memory a lot. If the problem is a large peak memory, then there is no issue. Otherwise, make sure you are using the Jemalloc allocator and not the default libc malloc. Note: The currently used allocator is \"%s\".\n\n", ZMALLOC_LIB);
        }
        if (big_client_buf) {
            s = sdscat(s," * Big client buffers: The clients output buffers in this instance are greater than 200K per client (on average). This may result from different causes, like Pub/Sub clients subscribed to channels bot not receiving data fast enough, so that data piles on the Redis instance output buffer, or clients sending commands with large replies or very large sequences of commands in the same pipeline. Please use the CLIENT LIST command in order to investigate the issue if it causes problems in your instance, or to understand better why certain clients are using a big amount of memory.\n\n");
        }
        s = sdscat(s,"I'm here to keep you safe, Sam. I want to help you.\n");
    }
    freeMemoryOverheadData(mh);
    return s;
}

/* ======================= The OBJECT and MEMORY commands =================== */

/* This is a helper function for the OBJECT command. We need to lookup keys
 * without any modification of LRU or other parameters. */
robj *objectCommandLookup(client *c, robj *key) {
    dictEntry *de;

    if ((de = dictFind(c->db->dict,key->ptr)) == NULL) return NULL;
    return (robj*) dictGetVal(de);
}

robj *objectCommandLookupOrReply(client *c, robj *key, robj *reply) {
    robj *o = objectCommandLookup(c,key);

    if (!o) addReply(c, reply);
    return o;
}

/* Object command allows to inspect the internals of an Redis Object.
 * Usage: OBJECT <refcount|encoding|idletime> <key> */
void objectCommand(client *c) {
    robj *o;

    if (!strcasecmp(c->argv[1]->ptr,"refcount") && c->argc == 3) {
        if ((o = objectCommandLookupOrReply(c,c->argv[2],shared.nullbulk))
                == NULL) return;
        addReplyLongLong(c,o->refcount);
    } else if (!strcasecmp(c->argv[1]->ptr,"encoding") && c->argc == 3) {
        if ((o = objectCommandLookupOrReply(c,c->argv[2],shared.nullbulk))
                == NULL) return;
        addReplyBulkCString(c,strEncoding(o->encoding));
    } else {
        addReplyError(c,"Syntax error. Try OBJECT (refcount|encoding|idletime|freq)");
    }
}
