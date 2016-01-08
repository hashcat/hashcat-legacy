/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef COMMON_H
#define COMMON_H

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#define __MSVCRT_VERSION__ 0x0700

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <getopt.h>
#include <search.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <gmp.h>

#ifdef OSX
#include <emmintrin.h>
#include <tmmintrin.h>
#else
#include <x86intrin.h>
#endif

#define SHARED_H

#include "constants.h"

#define PROGNAME              (const char *) "hashcat"

#define POTFILE               "hashcat.pot"

#define VERSION_TXT           "2.00"
#define VERSION_BIN           200

#define BLOCK_SIZE            64

#define MIN_THREADS           1
#define MAX_THREADS           512

#define ETC_MAX               (60 * 60 * 24 * 365 * 10)

#ifndef BUFSIZ
#define BUFSIZ 0x2000
#endif

#define CHARSIZ               0x100

#define BYTESWAP(x)   __asm__ __volatile__ ("bswap %0": "=r" (x): "0" (x))

#ifdef __x86_64__
#define BYTESWAP64(x) __asm__ __volatile__ ("bswap %q0": "=r" (x): "0" (x))
#else
#define BYTESWAP64(x) x = \
   ((((x) & 0xff00000000000000ull) >> 56)   \
  | (((x) & 0x00ff000000000000ull) >> 40)   \
  | (((x) & 0x0000ff0000000000ull) >> 24)   \
  | (((x) & 0x000000ff00000000ull) >>  8)   \
  | (((x) & 0x00000000ff000000ull) <<  8)   \
  | (((x) & 0x0000000000ff0000ull) << 24)   \
  | (((x) & 0x000000000000ff00ull) << 40)   \
  | (((x) & 0x00000000000000ffull) << 56))
#endif

#ifndef MIN
#define MIN(a,b) ((a) < (b)) ? (a) : (b)
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b)) ? (a) : (b)
#endif

#ifdef WINDOWS
#include <windows.h>
#include <process.h>
#include <intrin.h>
typedef HANDLE THREAD;
typedef HANDLE MUTEX;
typedef unsigned (__stdcall *PTHREAD_START) (void *);
#define ACCreateThreadEx(Dthread,Dstart,Darg,Did) Dthread = (HANDLE) _beginthreadex (NULL, 0, (PTHREAD_START) Dstart, Darg, 0, Did)
#define ACMutexLock(Dmutex)                       WaitForSingleObject (Dmutex, INFINITE)
#define ACMutexUnlock(Dmutex)                     ReleaseMutex (Dmutex)
#define ACMutexInit(Dmutex)                       Dmutex = CreateMutex (0, FALSE, 0)
#endif

#if defined LINUX || defined OSX || defined FREEBSD
#include <pthread.h>
typedef pthread_t THREAD;
typedef pthread_mutex_t MUTEX;
#define ACCreateThreadEx(Dthread,Dstart,Darg,Did) pthread_create        (&Dthread, NULL, (void *) Dstart, Darg)
#define ACMutexLock(Dmutex)                       pthread_mutex_lock    (&Dmutex)
#define ACMutexUnlock(Dmutex)                     pthread_mutex_unlock  (&Dmutex)
#define ACMutexInit(Dmutex)                       pthread_mutex_init    (&Dmutex, NULL)
#endif

#ifdef WINDOWS
#define SetPriorityLow()    { HANDLE hProc = GetCurrentProcess(); SetPriorityClass (hProc, IDLE_PRIORITY_CLASS);   }
#define SetPriorityNormal() { HANDLE hProc = GetCurrentProcess(); SetPriorityClass (hProc, NORMAL_PRIORITY_CLASS); }
#define SetPriorityHigh()   { HANDLE hProc = GetCurrentProcess(); SetPriorityClass (hProc, HIGH_PRIORITY_CLASS);   }
#endif

#if defined LINUX || defined OSX || defined FREEBSD
#include <sys/resource.h>
#define SetPriorityLow()    setpriority (PRIO_PROCESS, 0, 1)
#define SetPriorityNormal() setpriority (PRIO_PROCESS, 0, 0)
#define SetPriorityHigh()   setpriority (PRIO_PROCESS, 0, -1)
#endif

#ifdef WINDOWS
#define hc_sleep(x) Sleep ((x) * 1000);
#endif

#if defined LINUX || defined OSX || defined FREEBSD
#define hc_sleep(x) sleep ((x));
#endif

#ifdef WINDOWS
typedef UINT8  uint8_t;
typedef UINT16 uint16_t;
typedef UINT32 uint32_t;
typedef UINT64 uint64_t;
typedef INT8   int8_t;
typedef INT16  int16_t;
typedef INT32  int32_t;
typedef INT64  int64_t;
#endif

typedef uint32_t uint;
typedef uint64_t uint64;


/*
 * types
 */

typedef unsigned int bool;

typedef struct
{
  uint8_t     w_buf[16];
  uint8_t     w_len;

} hc_wchar_t;

typedef struct
{
  hc_wchar_t  tbl_buf[4096];
  uint32_t    tbl_cnt;

} tbl_t;

typedef struct
{
  char        cs_buf[CHARSIZ];
  uint32_t    cs_len;
  uint8_t     cs_pos;

  uint8_t     buf_pos;

} cs_t;

typedef struct
{
  uint pke[25];
  uint eapol[64];
  int  eapol_size;
  int  keyver;

} wpa_t;

typedef struct
{
  char *URI_server;
  char *URI_client;

  char *user;
  char *realm;
  char *method;

  char *URI_prefix;
  char *URI_resource;
  char *URI_suffix;

  char *nonce;
  char *nonce_client;
  char *nonce_count;

  char *qop;
  char *directive; // only "MD5" supported, no support for MD5-sess yet

} sip_t;

typedef struct
{
  char          essid[36];

  unsigned char mac1[6];
  unsigned char mac2[6];
  unsigned char nonce1[32];
  unsigned char nonce2[32];

  unsigned char eapol[256];
  int           eapol_size;

  int           keyver;
  unsigned char keymic[16];

} hccap_t;

typedef struct
{
  char     *cache_buf;
  uint64_t  cache_cnt;
  uint64_t  cache_avail;

  char    **words_buf;
  uint32_t *words_len;
  uint64_t  words_cnt;
  uint64_t  words_avail;

} words_t;

typedef struct
{
  char    **rules_buf;
  uint32_t *rules_len;
  uint64_t  rules_cnt;
  uint64_t  rules_avail;

  void *root_rule;

} rules_t;

typedef struct
{
  char *user_name;
  uint  user_len;

} user_t;

typedef union
{
  uint32_t  md4[8];
  uint32_t  md5[4];
  uint32_t  sha1[5];
  uint32_t  sha256[8];
  uint64_t  sha512[8];
  uint32_t  mysql[2];
  uint32_t  descrypt[2];
  uint32_t  bcrypt[6];
  uint64_t  keccak[25];
  uint32_t  gost[8];
  char      plain[64];

} digest_types_u;

typedef struct
{
  digest_types_u buf;

  char *plain;

  uint32_t found;

  user_t *user;

} digest_t;

typedef struct
{
  union
  {
    uint8_t  buf8[128];
    uint32_t buf32[16];
    uint64_t buf64[8];
    __m128i  buf128[4];
  };

} digest_md5_sse2_t;

typedef struct
{
  union
  {
    uint8_t  buf8[128];
    uint32_t buf32[16];
    uint64_t buf64[8];
    __m128i  buf128[4];
  };

} digest_md4_sse2_t;

typedef struct
{
  union
  {
    uint8_t  buf8[160];
    uint32_t buf32[20];
    uint64_t buf64[10];
    __m128i  buf128[5];
  };

} digest_sha1_sse2_t;

typedef struct
{
  union
  {
    uint8_t  buf8[256];
    uint32_t buf32[32];
    uint64_t buf64[16];
    __m128i  buf128[8];
  };

} digest_sha256_sse2_t;

typedef struct
{
  union
  {
    uint8_t  buf8[512];
    uint32_t buf32[64];
    uint64_t buf64[32];
    __m128i  buf128[16];
  };

} digest_sha512_sse2_t;

typedef struct
{
  union
  {
    uint8_t  buf8[192];
    uint32_t buf32[24];
    uint64_t buf64[12];
    __m128i  buf128[6];
  };

} digest_bcrypt_sse2_t;

typedef struct
{
  digest_t **digests_buf;
  uint64_t  digests_cnt;
  uint64_t  digests_avail;
  uint64_t  digests_found;

} index_t;

typedef struct
{
  uint32_t nr_buf[16];
  uint32_t nr_len;

  uint32_t msg_buf[128];
  uint32_t msg_len;

} ikepsk_t;

typedef struct
{
  uint user_len;
  uint domain_len;
  uint srvchall_len;
  uint clichall_len;

  uint userdomain_buf[16];
  uint chall_buf[256];

} netntlm_t;

typedef struct
{
  union
  {
    uint8_t  buf8[256];
    uint32_t buf[64];
    uint64_t buf64[32];
    __m128i  buf128[16];
  };

  uint32_t len;

  char  *debug_buf;
  int    debug_len;

  uint64_t pos;

} plain_t;

typedef struct
{
  char     *salt_plain_buf;
  uint32_t  salt_plain_len;

  plain_t   salt_plain_struct[4];
  plain_t   additional_plain_struct[4];

  char     *salt_prehashed_buf;
  uint32_t  salt_prehashed_len;

  uint32_t *ipad_prehashed_buf;
  uint32_t *opad_prehashed_buf;

  uint64_t *ipad_prehashed_buf64;
  uint64_t *opad_prehashed_buf64;

  uint32_t  netntlmv1_pc;

  netntlm_t *netntlm;
  ikepsk_t  *ikepsk;
  wpa_t     *wpa;
  sip_t     *sip;

  char      md5chap_idbyte;

  uint32_t  keccak_rsiz;
  uint32_t  keccak_mdlen;

  uint32_t  iterations;

  char     *signature;

  index_t **indexes_buf;
  uint64_t  indexes_cnt;
  uint64_t  indexes_avail;
  uint64_t  indexes_found;

  uint32_t scrypt_N;
  uint32_t scrypt_r;
  uint32_t scrypt_p;

} salt_t;

typedef struct
{
  rules_t *rules;
  words_t *words;

  salt_t **salts_buf;

  uint64_t salts_cnt;
  uint64_t salts_avail;
  uint64_t salts_found;

} db_t;

typedef struct
{
  digest_t digest;
  salt_t   *salt;
  void     *esalt;

} hash_t;

typedef struct
{
  char    plain_buf[256];
  int     plain_len;

  hash_t  hash;

  uint    pot_cnt;

} pot_t;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define IN_LEN_MIN    1
#define IN_LEN_MAX    32
#define OUT_LEN_MAX   32 /* Limited by (u32)(1 << pw_len - 1) */
#define ELEM_CNT_MIN  1
#define ELEM_CNT_MAX  8

typedef struct
{
  int len;
  u64 cnt;

} pw_order_t;

typedef struct
{
  u8   *buf;

} elem_t;

typedef struct
{
  u8   *buf;
  int   cnt;

  mpz_t ks_cnt;
  mpz_t ks_pos;

} chain_t;

typedef struct
{
  elem_t  *elems_buf;
  u64      elems_cnt;
  u64      elems_alloc;

  chain_t *chains_buf;
  int      chains_cnt;
  int      chains_pos;
  int      chains_alloc;

  u64      cur_chain_ks_poses[OUT_LEN_MAX];

} db_entry_t;

typedef struct
{
  uint32_t attack_mode;
  uint32_t hash_mode;
  uint32_t hash_type;
  uint32_t debug_mode;
  uint32_t salt_type;
  uint32_t num_threads;
  uint32_t cache_size;
  uint64_t words_skip;
  uint64_t words_limit;
  uint32_t hex_salt;

  uint32_t hashcat_status;
  uint32_t benchmark;

  char    *mask;
  uint32_t maskcnt;
  uint32_t maskpos;
  cs_t    *css_buf;
  uint32_t css_cnt;
  uint32_t pw_len;

  uint32_t perm_min;
  uint32_t perm_max;

  uint32_t table_min;
  uint32_t table_max;
  tbl_t    table_buf[256];

  char     separator;
  uint32_t output_autohex;
  uint32_t username;
  uint32_t show;
  uint32_t left;
  uint32_t remove;
  uint32_t quiet;

  struct timeval timer_paused;
  float          ms_paused;

  uint32_t status_timer;
  uint32_t runtime;
  uint32_t status_automat;

  uint32_t hex_charset;

  char    *file_words;
  char    *file_hashes;
  char    *file_output;
  char    *file_debug;
  char    *file_pot;

  uint32_t output_format;

  uint32_t plain_size_max;

  pot_t   *pot;

} engine_parameter_t;

typedef struct __thread_parameter
{
  uint32_t hash_type;

  uint32_t thread_id;

  uint32_t num_threads;

  uint64_t thread_words_skip;
  uint64_t thread_words_limit;
  uint64_t thread_words_done;

  uint64_t thread_plains_done;

  uint32_t plain_size_max;

  void (*indb) (struct __thread_parameter *, plain_t *, digest_t *, salt_t *);

  void (*hashing) (struct __thread_parameter *, plain_t *);

  int (*compare_digest) (const void *, const void *);

  void (*store_out) (plain_t *, digest_t *, salt_t *);

  void (*store_debug) (char *, int);

  void (*done) ();

  uint32_t *hashcat_status;

  uint32_t (*get_index) (digest_t *);

  db_t *db;

  digest_t *quick_digest;

  cs_t    *css_buf;
  uint32_t css_cnt;
  uint32_t pw_len;

  tbl_t   *table_buf;

  uint32_t debug_mode;
  char    *debug_file;

  uint32_t fake;

  char    separator;

  uint32_t *scrypt_P[4];
  __m128i *scrypt_V;
  __m128i *scrypt_X;
  __m128i *scrypt_Y;

  /**
   * prince
   */

  int order_cnt;

  mpz_t total_ks_cnt;
  mpz_t total_ks_pos;
  mpz_t total_ks_left;

  db_entry_t *db_entries;
  pw_order_t *pw_orders;
  u64        *wordlen_dist;

} thread_parameter_t;

typedef struct
{
  engine_parameter_t *engine_parameter;

  db_t *db;

  struct timeval cache_start;
  struct timeval cache_current;

  uint64_t segment_pos;
  uint64_t segment_cnt;

  uint64_t proc_words;
  uint64_t proc_hashes;
  uint64_t proc_recovered;
  uint64_t proc_saved;

} status_info_t;

typedef struct
{
  uint64_t state[8];

  union
  {
    uint64_t w[16];
    uint8_t  buf[128];
  };

  int len;

} hc_sha512_ctx;

typedef struct
{
  uint32_t state[8];

  union
  {
    uint32_t w[16];
    uint8_t  buf[64];
  };

  int len;

} hc_sha256_ctx;

/*
 * functions
 */

void dump_hex (const char *s, size_t size);

void log_info (const char *fmt, ...);

void log_warning (const char *fmt, ...);

void log_error (const char *fmt, ...);

uint32_t get_random_num (uint32_t min, uint32_t max);

void *mycalloc (size_t nmemb, size_t size);

void *mymalloc (size_t size);

void *malloc_tiny (const size_t size);

void myfree (void *ptr);

void *myrealloc (void *ptr, size_t size);

char *mystrdup (const char *s);

int in_superchop (char *buf);

/*
 * bits rotate/shift
 */

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

#define SHR(x, n) ((x) >> (n))
#define SHR32_SSE(x, n) _mm_srli_epi32 ((x), (n))

#define SHR64_SSE(x, n) _mm_srli_epi64 ((x), (n))

#ifdef __XOP__

#define ROTL32_SSE(x, n) _mm_roti_epi32 ((x), (n))

#define ROTL64_SSE(x, n) _mm_roti_epi64 ((x), (n))
#define ROTR64_SSE(x, n) _mm_roti_epi64 ((x), (-n))

#else

#define ROTL32_SSE(x, n) _mm_or_si128 (_mm_slli_epi32 ((x), (n)), _mm_srli_epi32 ((x), (32 - (n))))

#define ROTL64_SSE(x, n) _mm_or_si128 (_mm_slli_epi64 ((x), (n)), _mm_srli_epi64 ((x), (64 - (n))))
#define ROTR64_SSE(x, n) _mm_or_si128 (_mm_srli_epi64 ((x), (n)), _mm_slli_epi64 ((x), (64 - (n))))

#endif /* __XOP___*/

#ifdef __SSSE3__
#define SWAP64_SSE(v) _mm_shuffle_epi8 (v, _mm_set_epi32 (0x08090a0b, 0x0c0d0e0f, 0x00010203, 0x04050607))
#else
#define SWAP64_SSE(v) \
    _mm_slli_epi64 (v, 56) \
  | _mm_and_si128 (_mm_slli_epi64 (v, 40), _mm_set1_epi64 ((__m64 ) 0x00FF000000000000ULL)) \
  | _mm_and_si128 (_mm_slli_epi64 (v, 24), _mm_set1_epi64 ((__m64 ) 0x0000FF0000000000ULL)) \
  | _mm_and_si128 (_mm_slli_epi64 (v,  8), _mm_set1_epi64 ((__m64 ) 0x000000FF00000000ULL)) \
  | _mm_and_si128 (_mm_srli_epi64 (v,  8), _mm_set1_epi64 ((__m64 ) 0x00000000FF000000ULL)) \
  | _mm_and_si128 (_mm_srli_epi64 (v, 24), _mm_set1_epi64 ((__m64 ) 0x0000000000FF0000ULL)) \
  | _mm_and_si128 (_mm_srli_epi64 (v, 40), _mm_set1_epi64 ((__m64 ) 0x000000000000FF00ULL)) \
  | _mm_srli_epi64 (v, 56)
#endif

#ifdef __SSSE3__
#define SWAP32_SSE(v) _mm_shuffle_epi8 (v, _mm_set_epi32 (0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203))
#else
#define SWAP32_SSE(v) \
    _mm_slli_epi32 (v, 24) \
  | _mm_and_si128 (_mm_slli_epi32 (v, 8), _mm_set1_epi32 (0x00FF0000)) \
  | _mm_and_si128 (_mm_srli_epi32 (v, 8), _mm_set1_epi32 (0x0000FF00)) \
  | _mm_srli_epi32 (v, 24)
#endif

#endif /* COMMON_H */
