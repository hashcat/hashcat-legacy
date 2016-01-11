/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifdef FREEBSD
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/ttydefaults.h>
#endif

#ifdef OSX
#include <sys/sysctl.h>
#endif

#define _FILE_OFFSET_BITS 64
#define _CRT_SECURE_NO_WARNINGS

#include "common.h"
#include "tsearch.h"
#include "rp.h"
#include "engine.h"

// for interactive status prompt
#if defined OSX || defined FREEBSD
#include <termios.h>
#include <sys/ioctl.h>
#endif

#if defined LINUX
#include <termio.h>
#endif

#define USAGE_VIEW      0
#define VERSION_VIEW    0
#define QUIET           0
#define STDOUT_MODE     0
#define STATUS          0
#define STATUS_TIMER    10
#define STATUS_AUTOMAT  0
#define REMOVE          0
#define POTFILE_DISABLE 0
#define OUTFILE_FORMAT  3
#define OUTFILE_AUTOHEX 1
#define HEX_SALT        0
#define BENCHMARK       0
#define HEX_CHARSET     0
#define RUNTIME         0
#define ATTACK_MODE     0
#define HASH_MODE       0
#define DEBUG_MODE      0
#define NUM_THREADS     8
#define CACHE_SIZE      32
#define WORDS_SKIP      0
#define WORDS_LIMIT     0
#define SEPARATOR       ':'
#define USERNAME        0
#define SHOW            0
#define LEFT            0
#define RP_GEN          0
#define RP_GEN_FUNC_MIN 1
#define RP_GEN_FUNC_MAX 4
#define RP_GEN_SEED     0
#define TOGGLE_MIN      1
#define TOGGLE_MAX      16
#define PERM_MIN        2
#define PERM_MAX        10
#define TABLE_MIN       2
#define TABLE_MAX       15
#define INCREMENT       0
#define INCREMENT_MIN   IN_LEN_MIN
#define INCREMENT_MAX   IN_LEN_MAX
#define PW_MIN          1
#define PW_MAX          16
#define WL_DIST_LEN     0
#define WL_MAX          10000000
#define CASE_PERMUTE    0
#define MIN_FUNCS       1
#define MAX_FUNCS       16
#define MAX_CUT_ITER    4

#define TIMESPEC_SUBTRACT(a,b) ((uint64_t) ((a).tv_sec - (b).tv_sec) * 1000000 + (a).tv_usec - (b).tv_usec)

const char *PROMPT = "[s]tatus [p]ause [r]esume [b]ypass [q]uit => ";

#define NUM_DEFAULT_BENCHMARK_ALGORITHMS 72

static uint default_benchmark_algorithms[NUM_DEFAULT_BENCHMARK_ALGORITHMS] =
{
  900,
  0,
  5100,
  100,
  1400,
  1700,
  5000,
  6900,
  400,
  8900,
  23,
  2500,
  5300,
  5400,
  5500,
  5600,
  7300,
  11100,
  11200,
  11400,
  121,
  2611,
  2711,
  2811,
  8400,
  11,
  2612,
  7900,
  21,
  11000,
  124,
  10000,
  3711,
  7600,
  12,
  131,
  132,
  1731,
  200,
  300,
  112,
  141,
  1441,
  1600,
  1421,
  101,
  111,
  1711,
  1000,
  1100,
  500,
  3200,
  7400,
  1800,
  122,
  1722,
  7100,
  6300,
  6700,
  6400,
  6500,
  2400,
  2410,
  5700,
  9200,
  9300,
  5800,
  7200,
  9900,
  10300,
  133,
  5200
};

static const char *USAGE_MINI[] =
{
"Usage: %s [options] hashfile [mask|wordfiles|directories]",
"",
"Try --help for more help.",
NULL
};

static const char *USAGE_BIG[] =
{
"hashcat, advanced password recovery",
"",
"Usage: %s [options] hashfile [mask|wordfiles|directories]",
"",
"=======",
"Options",
"=======",
"",
"* General:",
"",
"  -m,  --hash-type=NUM               Hash-type, see references below",
"  -a,  --attack-mode=NUM             Attack-mode, see references below",
"  -V,  --version                     Print version",
"  -h,  --help                        Print help",
"       --quiet                       Suppress output",
"",
"* Benchmark:",
"",
"  -b,  --benchmark                   Run benchmark",
"",
"* Misc:",
"",
"       --hex-salt                    Assume salt is given in hex",
"       --hex-charset                 Assume charset is given in hex",
"       --runtime=NUM                 Abort session after NUM seconds of runtime",
"       --status                      Enable automatic update of the status-screen",
"       --status-timer=NUM            Seconds between status-screen update",
"       --status-automat              Display the status view in a machine readable format",
"",
"* Files:",
"",
"  -o,  --outfile=FILE                Define outfile for recovered hash",
"       --outfile-format=NUM          Define outfile-format for recovered hash, see references below",
"       --outfile-autohex-disable     Disable the use of $HEX[] in output plains",
"  -p,  --separator=CHAR              Define separator char for hashlists/outfile",
"       --show                        Show cracked passwords only (see --username)",
"       --left                        Show uncracked passwords only (see --username)",
"       --username                    Enable ignoring of usernames in hashfile (Recommended: also use --show)",
"       --remove                      Enable remove of hash once it is cracked",
"       --stdout                      Stdout mode",
"       --potfile-disable             Do not write potfile",
"       --debug-mode=NUM              Defines the debug mode (hybrid only by using rules), see references below",
"       --debug-file=FILE             Output file for debugging rules (see --debug-mode)",
"  -e,  --salt-file=FILE              Salts-file for unsalted hashlists",
"",
"* Resources:",
"",
"  -c,  --segment-size=NUM            Size in MB to cache from the wordfile",
"  -n,  --threads=NUM                 Number of threads",
"  -s,  --words-skip=NUM              Skip number of words (for resume)",
"  -l,  --words-limit=NUM             Limit number of words (for distributed)",
"",
"* Rules:",
"",
"  -r,  --rules-file=FILE             Rules-file use: -r 1.rule",
"  -g,  --generate-rules=NUM          Generate NUM random rules",
"       --generate-rules-func-min=NUM Force NUM functions per random rule min",
"       --generate-rules-func-max=NUM Force NUM functions per random rule max",
"       --generate-rules-seed=NUM     Force RNG seed to NUM",
"",
"* Custom charsets:",
"",
"  -1,  --custom-charset1=CS          User-defined charsets",
"  -2,  --custom-charset2=CS          Example:",
"  -3,  --custom-charset3=CS          --custom-charset1=?dabcdef : sets charset ?1 to 0123456789abcdef",
"  -4,  --custom-charset4=CS          -2 mycharset.hcchr : sets charset ?2 to chars contained in file",
"",
"* Toggle-Case attack-mode specific:",
"",
"       --toggle-min=NUM              Number of alphas in dictionary minimum",
"       --toggle-max=NUM              Number of alphas in dictionary maximum",
"",
"* Mask-attack attack-mode specific:",
"",
"       --increment                   Enable increment mode",
"       --increment-min=NUM           Start incrementing at NUM",
"       --increment-max=NUM           Stop incrementing at NUM",
"",
"* Permutation attack-mode specific:",
"",
"       --perm-min=NUM                Filter words shorter than NUM",
"       --perm-max=NUM                Filter words larger than NUM",
"",
"* Table-Lookup attack-mode specific:",
"",
"  -t,  --table-file=FILE             Table file",
"       --table-min=NUM               Number of chars in dictionary minimum",
"       --table-max=NUM               Number of chars in dictionary maximum",
"",
"* Prince attack-mode specific:",
"",
"       --pw-min=NUM                  Print candidate if length is greater than NUM",
"       --pw-max=NUM                  Print candidate if length is smaller than NUM",
"       --elem-cnt-min=NUM            Minimum number of elements per chain",
"       --elem-cnt-max=NUM            Maximum number of elements per chain",
"       --wl-dist-len                 Calculate output length distribution from wordlist",
"       --wl-max=NUM                  Load only NUM words from input wordlist or use 0 to disable",
"       --case-permute                For each word in the wordlist that begins with a letter",
"                                     generate a word with the opposite case of the first letter",
"",
"==========",
"References",
"==========",
"",
"* Outfile formats:",
"",
"    1 = hash[:salt]",
"    2 = plain",
"    3 = hash[:salt]:plain",
"    4 = hex_plain",
"    5 = hash[:salt]:hex_plain",
"    6 = plain:hex_plain",
"    7 = hash[:salt]:plain:hex_plain",
"    8 = crackpos",
"    9 = hash[:salt]:crackpos",
"   10 = plain:crackpos",
"   11 = hash[:salt]:plain:crackpos",
"   12 = hex_plain:crackpos",
"   13 = hash[:salt]:hex_plain:crackpos",
"   14 = plain:hex_plain:crackpos",
"   15 = hash[:salt]:plain:hex_plain:crackpos",
"",
"* Debug mode output formats (for hybrid mode only, by using rules):",
"",
"    1 = save finding rule",
"    2 = save original word",
"    3 = save original word and finding rule",
"    4 = save original word, finding rule and modified plain",
"",
"* Built-in charsets:",
"",
"   ?l = abcdefghijklmnopqrstuvwxyz",
"   ?u = ABCDEFGHIJKLMNOPQRSTUVWXYZ",
"   ?d = 0123456789",
"   ?s =  !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
"   ?a = ?l?u?d?s",
"   ?b = 0x00 - 0xff",
"",
"* Attack modes:",
"",
"    0 = Straight",
"    1 = Combination",
"    2 = Toggle-Case",
"    3 = Brute-force",
"    4 = Permutation",
"    5 = Table-Lookup",
"    8 = Prince",
"",
"* Hash types:",
"",
"[[ Roll-your-own: Raw Hashes ]]",
"",
"    900 = MD4",
"      0 = MD5",
"   5100 = Half MD5",
"    100 = SHA1",
"   1400 = SHA-256",
"   1700 = SHA-512",
"   5000 = SHA-3(Keccak)",
"   6900 = GOST R 34.11-94",
"  99999 = Plaintext",
"",
"[[ Roll-your-own: Iterated and / or Salted Hashes ]]",
"",
"     10 = md5($pass.$salt)",
"     20 = md5($salt.$pass)",
"     30 = md5(unicode($pass).$salt)",
"     40 = md5($salt.unicode($pass))",
"   3800 = md5($salt.$pass.$salt)",
"   3710 = md5($salt.md5($pass))",
"   4110 = md5($salt.md5($pass.$salt))",
"   4010 = md5($salt.md5($salt.$pass))",
"   4210 = md5($username.0.$pass)",
"   3720 = md5($pass.md5($salt))",
"   3500 = md5(md5(md5($pass)))",
"   3610 = md5(md5($salt).$pass)",
"   3910 = md5(md5($pass).md5($salt))",
"   2600 = md5(md5($pass)",
"   4300 = md5(strtoupper(md5($pass)))",
"   4400 = md5(sha1($pass))",
"    110 = sha1($pass.$salt)",
"    120 = sha1($salt.$pass)",
"    130 = sha1(unicode($pass).$salt)",
"    140 = sha1($salt.unicode($pass))",
"   4500 = sha1(sha1($pass)",
"   4600 = sha1(sha1(sha1($pass)))",
"   4700 = sha1(md5($pass))",
"   4900 = sha1($salt.$pass.$salt)",
"   1410 = sha256($pass.$salt)",
"   1420 = sha256($salt.$pass)",
"   1430 = sha256(unicode($pass).$salt)",
"   1440 = sha256($salt.unicode($pass))",
"   1710 = sha512($pass.$salt)",
"   1720 = sha512($salt.$pass)",
"   1730 = sha512(unicode($pass).$salt)",
"   1740 = sha512($salt.unicode($pass))",
"   1431 = base64(sha256(unicode($pass)))",
"",
"[[ Roll-your-own: Authenticated Hashes ]]",
"",
"     50 = HMAC-MD5 (key = $pass)",
"     60 = HMAC-MD5 (key = $salt)",
"    150 = HMAC-SHA1 (key = $pass)",
"    160 = HMAC-SHA1 (key = $salt)",
"   1450 = HMAC-SHA256 (key = $pass)",
"   1460 = HMAC-SHA256 (key = $salt)",
"   1750 = HMAC-SHA512 (key = $pass)",
"   1760 = HMAC-SHA512 (key = $salt)",
"",
"[[ Generic KDF ]]",
"",
"    400 = phpass",
"   8900 = scrypt",
"",
"[[ Network protocols, Challenge-Response ]]",
"",
"     23 = Skype",
"   2500 = WPA/WPA2",
"   4800 = iSCSI CHAP authentication, MD5(Chap)",
"   5300 = IKE-PSK MD5",
"   5400 = IKE-PSK SHA1",
"   5500 = NetNTLMv1",
"   5500 = NetNTLMv1 + ESS",
"   5600 = NetNTLMv2",
"   7300 = IPMI2 RAKP HMAC-SHA1",
"  10200 = Cram MD5",
"  11100 = PostgreSQL Challenge-Response Authentication (MD5)",
"  11200 = MySQL Challenge-Response Authentication (SHA1)",
"  11400 = SIP digest authentication (MD5)",
"",
"[[ Forums, CMS, E-Commerce, Frameworks, Middleware, Wiki, Management ]]",
"",
"    121 = SMF (Simple Machines Forum)",
"    400 = phpBB3",
"   2611 = vBulletin < v3.8.5",
"   2711 = vBulletin > v3.8.5",
"   2811 = MyBB",
"   2811 = IPB (Invison Power Board)",
"   8400 = WBB3 (Woltlab Burning Board)",
"     11 = Joomla < 2.5.18",
"    400 = Joomla > 2.5.18",
"    400 = Wordpress",
"   2612 = PHPS",
"   7900 = Drupal7",
"     21 = osCommerce",
"     21 = xt:Commerce",
"  11000 = PrestaShop",
"    124 = Django (SHA-1)",
"  10000 = Django (PBKDF2-SHA256)",
"   3711 = Mediawiki B type",
"   7600 = Redmine",
"   3721 = WebEdition CMS",
"",
"[[ Database Server ]]",
"",
"     12 = PostgreSQL",
"    131 = MSSQL(2000)",
"    132 = MSSQL(2005)",
"   1731 = MSSQL(2012)",
"   1731 = MSSQL(2014)",
"    200 = MySQL323",
"    300 = MySQL4.1/MySQL5",
"    112 = Oracle S: Type (Oracle 11+)",
"",
"[[ HTTP, SMTP, LDAP Server ]]",
"",
"    123 = EPi",
"    141 = EPiServer 6.x < v4",
"   1441 = EPiServer 6.x > v4",
"   1600 = Apache $apr1$",
"   1421 = hMailServer",
"    101 = nsldap, SHA-1(Base64), Netscape LDAP SHA",
"    111 = nsldaps, SSHA-1(Base64), Netscape LDAP SSHA",
"   1711 = SSHA-512(Base64), LDAP {SSHA512}",
"",
"[[ Operating-Systems ]]",
"",
"   1000 = NTLM",
"   1100 = Domain Cached Credentials (DCC), MS Cache",
//"   1500 = descrypt, DES(Unix), Traditional DES",
"    500 = md5crypt $1$, MD5(Unix)",
"   3200 = bcrypt $2*$, Blowfish(Unix)",
"   3300 = MD5(Sun)",
"   7400 = sha256crypt $5$, SHA256(Unix)",
"   1800 = sha512crypt $6$, SHA512(Unix)",
"    122 = OSX v10.4",
"    122 = OSX v10.5",
"    122 = OSX v10.6",
"   1722 = OSX v10.7",
"   7100 = OSX v10.8",
"   7100 = OSX v10.9",
"   7100 = OSX v10.10",
"   7100 = OSX v10.11",
"   6300 = AIX {smd5}",
"   6700 = AIX {ssha1}",
"   6400 = AIX {ssha256}",
"   6500 = AIX {ssha512}",
"   2400 = Cisco-PIX",
"   2410 = Cisco-ASA",
"    500 = Cisco-IOS $1$",
"   5700 = Cisco-IOS $4$",
"   9200 = Cisco-IOS $8$",
"   9300 = Cisco-IOS $9$",
"   5800 = Android PIN",
"   7200 = GRUB 2",
"   9900 = Radmin2",
"   7000 = Fortigate (FortiOS)",
"",
"[[ Enterprise Application Software (EAS) ]]",
"",
"  10300 = SAP CODVN H (PWDSALTEDHASH) iSSHA-1",
"    133 = PeopleSoft",
"",
"[[ Password Managers ]]",
"",
"   5200 = Password Safe v3",
"",
NULL
};

uint32_t hashcat_running = 0;

THREAD thr_keypress   = 0;
THREAD thr_removehash = 0;
THREAD thr_runtime    = 0;
THREAD thr_status     = 0;

static const uint32_t INDEX_SIZE[32] =
{
  0x00000000, 0x80000000, 0x40000000, 0x20000000,
  0x10000000, 0x08000000, 0x04000000, 0x02000000,
  0x01000000, 0x00800000, 0x00400000, 0x00200000,
  0x00100000, 0x00080000, 0x00040000, 0x00020000,
  0x00010000, 0x00008000, 0x00004000, 0x00002000,
  0x00001000, 0x00000800, 0x00000400, 0x00000200,
  0x00000100, 0x00000080, 0x00000040, 0x00000020,
  0x00000010, 0x00000008, 0x00000004, 0x00000002
};

static status_info_t status_info __attribute__ ((aligned (16)));

/**
 * princeprocessor
 */

#define DEF_WORDLEN_DIST_CNT 25

static u64 DEF_WORDLEN_DIST[DEF_WORDLEN_DIST_CNT] =
{
  0,
  15,
  56,
  350,
  3315,
  43721,
  276252,
  201748,
  226412,
  119885,
  75075,
  26323,
  13373,
  6353,
  3540,
  1877,
  972,
  311,
  151,
  81,
  66,
  21,
  16,
  13,
  13
};

#define ALLOC_NEW_ELEMS  0x40000
#define ALLOC_NEW_CHAINS 0x10

static void check_realloc_elems (db_entry_t *db_entry)
{
  if (db_entry->elems_cnt == db_entry->elems_alloc)
  {
    const u64 elems_alloc = db_entry->elems_alloc;

    const u64 elems_alloc_new = elems_alloc + ALLOC_NEW_ELEMS;

    db_entry->elems_buf = (elem_t *) realloc (db_entry->elems_buf, elems_alloc_new * sizeof (elem_t));

    if (db_entry->elems_buf == NULL)
    {
      fprintf (stderr, "Out of memory trying to allocate %zu bytes\n", (size_t) elems_alloc_new * sizeof (elem_t));

      exit (-1);
    }

    memset (&db_entry->elems_buf[elems_alloc], 0, ALLOC_NEW_ELEMS * sizeof (elem_t));

    db_entry->elems_alloc = elems_alloc_new;
  }
}

static void check_realloc_chains (db_entry_t *db_entry)
{
  if (db_entry->chains_cnt == db_entry->chains_alloc)
  {
    const u64 chains_alloc = db_entry->chains_alloc;

    const u64 chains_alloc_new = chains_alloc + ALLOC_NEW_CHAINS;

    db_entry->chains_buf = (chain_t *) realloc (db_entry->chains_buf, chains_alloc_new * sizeof (chain_t));

    if (db_entry->chains_buf == NULL)
    {
      fprintf (stderr, "Out of memory trying to allocate %zu bytes\n", (size_t) chains_alloc_new * sizeof (chain_t));

      exit (-1);
    }

    memset (&db_entry->chains_buf[chains_alloc], 0, ALLOC_NEW_CHAINS * sizeof (chain_t));

    db_entry->chains_alloc = chains_alloc_new;
  }
}

static int sort_by_cnt (const void *p1, const void *p2)
{
  const pw_order_t *o1 = (const pw_order_t *) p1;
  const pw_order_t *o2 = (const pw_order_t *) p2;

  // Descending order
  if (o1->cnt > o2->cnt) return -1;
  if (o1->cnt < o2->cnt) return  1;

  return 0;
}

static int sort_by_ks (const void *p1, const void *p2)
{
  const chain_t *f1 = (const chain_t *) p1;
  const chain_t *f2 = (const chain_t *) p2;

  return mpz_cmp (f1->ks_cnt, f2->ks_cnt);
}

static int chain_valid_with_db (const chain_t *chain_buf, const db_entry_t *db_entries)
{
  const u8 *buf = chain_buf->buf;
  const int cnt = chain_buf->cnt;

  int idx;

  for (idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    if (db_entry->elems_cnt == 0) return 0;
  }

  return 1;
}

static int chain_valid_with_cnt_min (const chain_t *chain_buf, const int elem_cnt_min)
{
  const int cnt = chain_buf->cnt;

  if (cnt < elem_cnt_min) return 0;

  return 1;
}

static int chain_valid_with_cnt_max (const chain_t *chain_buf, const int elem_cnt_max)
{
  const int cnt = chain_buf->cnt;

  if (cnt > elem_cnt_max) return 0;

  return 1;
}

static void chain_ks (const chain_t *chain_buf, const db_entry_t *db_entries, mpz_t *ks_cnt)
{
  const u8 *buf = chain_buf->buf;
  const int cnt = chain_buf->cnt;

  mpz_set_si (*ks_cnt, 1);

  int idx;

  for (idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    const u64 elems_cnt = db_entry->elems_cnt;

    mpz_mul_ui (*ks_cnt, *ks_cnt, elems_cnt);
  }
}

static void chain_gen_with_idx (chain_t *chain_buf, const int len1, const int chains_idx)
{
  chain_buf->cnt = 0;

  u8 db_key = 1;

  int chains_shr;

  for (chains_shr = 0; chains_shr < len1; chains_shr++)
  {
    if ((chains_idx >> chains_shr) & 1)
    {
      chain_buf->buf[chain_buf->cnt] = db_key;

      chain_buf->cnt++;

      db_key = 1;
    }
    else
    {
      db_key++;
    }
  }

  chain_buf->buf[chain_buf->cnt] = db_key;

  chain_buf->cnt++;
}

static char *add_elem (db_entry_t *db_entry, char *input_buf, int input_len)
{
  check_realloc_elems (db_entry);

  elem_t *elem_buf = &db_entry->elems_buf[db_entry->elems_cnt];

  elem_buf->buf = malloc_tiny (input_len);

  memcpy (elem_buf->buf, input_buf, input_len);

  db_entry->elems_cnt++;

  return (char *) elem_buf->buf;
}

static void set_chain_ks_poses (const chain_t *chain_buf, const db_entry_t *db_entries, mpz_t *tmp, u64 cur_chain_ks_poses[OUT_LEN_MAX])
{
  const u8 *buf = chain_buf->buf;

  const int cnt = chain_buf->cnt;

  int idx;

  for (idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    const u64 elems_cnt = db_entry->elems_cnt;

    cur_chain_ks_poses[idx] = mpz_fdiv_ui (*tmp, elems_cnt);

    mpz_div_ui (*tmp, *tmp, elems_cnt);
  }
}

static void chain_set_pwbuf_init (const chain_t *chain_buf, const db_entry_t *db_entries, const u64 cur_chain_ks_poses[OUT_LEN_MAX], char *pw_buf)
{
  const u8 *buf = chain_buf->buf;

  const u32 cnt = chain_buf->cnt;

  u32 idx;

  for (idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    const u64 elems_idx = cur_chain_ks_poses[idx];

    memcpy (pw_buf, db_entry->elems_buf[elems_idx].buf, db_key);

    pw_buf += db_key;
  }
}

static void chain_set_pwbuf_increment (const chain_t *chain_buf, const db_entry_t *db_entries, u64 cur_chain_ks_poses[OUT_LEN_MAX], char *pw_buf)
{
  const u8 *buf = chain_buf->buf;

  const int cnt = chain_buf->cnt;

  int idx;

  for (idx = 0; idx < cnt; idx++)
  {
    const u8 db_key = buf[idx];

    const db_entry_t *db_entry = &db_entries[db_key];

    const u64 elems_cnt = db_entry->elems_cnt;

    cur_chain_ks_poses[idx]++;

    const u64 elems_idx = cur_chain_ks_poses[idx];

    if (elems_idx < elems_cnt)
    {
      memcpy (pw_buf, db_entry->elems_buf[elems_idx].buf, db_key);

      break;
    }

    cur_chain_ks_poses[idx] = 0;

    memcpy (pw_buf, db_entry->elems_buf[0].buf, db_key);

    pw_buf += db_key;
  }
}

/**
 * maskprocessor
 */

static void mp_add_cs_buf (char *in_buf, size_t in_len, cs_t *cs)
{
  size_t css_uniq_sz = CHARSIZ * sizeof (uint);

  uint *css_uniq = (uint *) mymalloc (css_uniq_sz);

  memset (css_uniq, 0, css_uniq_sz);

  size_t i;

  for (i = 0; i < cs->cs_len; i++)
  {
    uint8_t u = cs->cs_buf[i];

    css_uniq[u] = 1;
  }

  for (i = 0; i < in_len; i++)
  {
    uint u = in_buf[i] & 0xff;

    if (css_uniq[u] == 1) continue;

    css_uniq[u] = 1;

    cs->cs_buf[cs->cs_len] = u;

    cs->cs_len++;
  }

  myfree (css_uniq);
}

static void mp_expand (char *in_buf, size_t in_len, cs_t *mp_sys, cs_t *mp_usr, int mp_usr_offset, int interpret)
{
  size_t in_pos;

  for (in_pos = 0; in_pos < in_len; in_pos++)
  {
    char p0 = in_buf[in_pos];

    if (interpret == 1 && p0 == '?')
    {
      in_pos++;

      if (in_pos == in_len) break;

      char p1 = in_buf[in_pos];

      switch (p1)
      {
        case 'l': mp_add_cs_buf (mp_sys[0].cs_buf, mp_sys[0].cs_len, mp_usr + mp_usr_offset);
                  break;
        case 'u': mp_add_cs_buf (mp_sys[1].cs_buf, mp_sys[1].cs_len, mp_usr + mp_usr_offset);
                  break;
        case 'd': mp_add_cs_buf (mp_sys[2].cs_buf, mp_sys[2].cs_len, mp_usr + mp_usr_offset);
                  break;
        case 's': mp_add_cs_buf (mp_sys[3].cs_buf, mp_sys[3].cs_len, mp_usr + mp_usr_offset);
                  break;
        case 'a': mp_add_cs_buf (mp_sys[4].cs_buf, mp_sys[4].cs_len, mp_usr + mp_usr_offset);
                  break;
        case 'b': mp_add_cs_buf (mp_sys[5].cs_buf, mp_sys[5].cs_len, mp_usr + mp_usr_offset);
                  break;
        case '?': mp_add_cs_buf (&p0, 1, mp_usr + mp_usr_offset);
                  break;
        default:  log_error ("Syntax error: %s", in_buf);
                  exit (-1);
      }
    }
    else
    {
      if (status_info.engine_parameter->hex_charset)
      {
        in_pos++;

        if (in_pos == in_len)
        {
          log_error ("Syntax error: the hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", in_buf);

          exit (-1);
        }

        char p1 = in_buf[in_pos];

        if ((is_valid_hex_char (p0) == 0) || (is_valid_hex_char (p1) == 0))
        {
          log_error ("Syntax error: invalid hex character detected in mask: %s", in_buf);

          exit (-1);
        }

        char chr = 0;

        chr  = hex_convert (p1) << 0;
        chr |= hex_convert (p0) << 4;

        mp_add_cs_buf (&chr, 1, mp_usr + mp_usr_offset);
      }
      else
      {
        char chr = p0;

        mp_add_cs_buf (&chr, 1, mp_usr + mp_usr_offset);
      }
    }
  }
}

static uint64_t mp_get_sum (uint32_t css_cnt, cs_t *css)
{
  uint64_t sum = 1;

  uint32_t css_pos;

  for (css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    sum *= css[css_pos].cs_len;
  }

  return (sum);
}

static cs_t *mp_gen_css (char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, uint32_t *css_cnt)
{
  cs_t *css = (cs_t *) mycalloc (64, sizeof (cs_t));

  uint32_t mask_pos;
  uint32_t css_pos;

  for (mask_pos = 0, css_pos = 0; mask_pos < mask_len; mask_pos++, css_pos++)
  {
    char p0 = mask_buf[mask_pos];

    if (p0 == '?')
    {
      mask_pos++;

      if (mask_pos == mask_len) break;

      char p1 = mask_buf[mask_pos];

      switch (p1)
      {
        case 'l': mp_add_cs_buf (mp_sys[0].cs_buf, mp_sys[0].cs_len, css + css_pos);
                  break;
        case 'u': mp_add_cs_buf (mp_sys[1].cs_buf, mp_sys[1].cs_len, css + css_pos);
                  break;
        case 'd': mp_add_cs_buf (mp_sys[2].cs_buf, mp_sys[2].cs_len, css + css_pos);
                  break;
        case 's': mp_add_cs_buf (mp_sys[3].cs_buf, mp_sys[3].cs_len, css + css_pos);
                  break;
        case 'a': mp_add_cs_buf (mp_sys[4].cs_buf, mp_sys[4].cs_len, css + css_pos);
                  break;
        case 'b': mp_add_cs_buf (mp_sys[5].cs_buf, mp_sys[5].cs_len, css + css_pos);
                  break;
        case '1': if (mp_usr[0].cs_len == 0) { log_error ("ERROR: custom charset 1 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[0].cs_buf, mp_usr[0].cs_len, css + css_pos);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { log_error ("ERROR: custom charset 2 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[1].cs_buf, mp_usr[1].cs_len, css + css_pos);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { log_error ("ERROR: custom charset 3 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[2].cs_buf, mp_usr[2].cs_len, css + css_pos);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { log_error ("ERROR: custom charset 4 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[3].cs_buf, mp_usr[3].cs_len, css + css_pos);
                  break;
        case '?': mp_add_cs_buf (&p1, 1, css + css_pos);
                  break;
        default:  log_error ("ERROR: syntax error: %s\n", mask_buf);
                  exit (-1);
      }
    }
    else
    {
      if (status_info.engine_parameter->hex_charset)
      {
        mask_pos++;

        if (mask_pos == mask_len)
        {
          log_error ("ERROR: the hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

          exit (-1);
        }

        char p1 = mask_buf[mask_pos];

        if ((is_valid_hex_char (p0) == 0) || (is_valid_hex_char (p1) == 0))
        {
          log_error ("ERROR: invalid hex character detected in mask: %s", mask_buf);

          exit (-1);
        }

        char c = 0;

        c |= hex_convert (p1) << 0;
        c |= hex_convert (p0) << 4;

        mp_add_cs_buf (&c, 1, css + css_pos);
      }
      else
      {
        mp_add_cs_buf (&p0, 1, css + css_pos);
      }
    }
  }

  *css_cnt = css_pos;

  return (css);
}

static void mp_cut_at (char *mask, uint32_t max)
{
  uint32_t mask_len = strlen (mask);

  if (status_info.engine_parameter->hex_charset)
  {
    max *= 2;
  }

  uint32_t i;
  uint32_t j;

  for (i = 0, j = 0; i < mask_len && j < max; i++, j++)
  {
    if (mask[i] == '?') i++;
  }

  mask[i] = 0;
}

uint64_t per_sec (const uint64_t cnt, uint64_t diff)
{
  if (diff == 0) diff = 1;

  long double v = (1000 * 1000) / (double) diff;

  return cnt * v;
}

char *size_display (const uint64_t val)
{
  char units[7] = { ' ', 'k', 'M', 'G', 'T', 'P', 'E' };

  /* make sure that bigint fits into double */

  uint32_t level = 0;

  uint64_t tmp1 = val;

  while (tmp1 > (1000 * 1000))
  {
    tmp1 /= 1000;

    level++;
  }

  /* now we can do the final double value */

  double tmp2 = (double) tmp1;

  if (tmp2 > 1000)
  {
    tmp2 /= 1000;

    level++;
  }

  /* generate output */

  char *display = mymalloc (16);

  if (level == 0)
  {
    snprintf (display, 16, "%llu", (long long unsigned int) val);
  }
  else
  {
    snprintf (display, 16, "%04.02f%c", tmp2, units[level]);
  }

  return (display);
}

void wait_finish ()
{
  hashcat_running = 0;

#ifdef WINDOWS
  THREAD i_threads[1];

  i_threads[0] = thr_keypress;

  WaitForMultipleObjects (1, i_threads, TRUE, INFINITE);

  CloseHandle (i_threads[0]);

  if (thr_removehash)
  {
    i_threads[0] = thr_removehash;

    WaitForMultipleObjects (1, i_threads, TRUE, INFINITE);

    CloseHandle (i_threads[0]);
  }

  if (thr_runtime)
  {
    i_threads[0] = thr_runtime;

    WaitForMultipleObjects (1, i_threads, TRUE, INFINITE);

    CloseHandle (i_threads[0]);
  }

  if (thr_status)
  {
    i_threads[0] = thr_status;

    WaitForMultipleObjects (1, i_threads, TRUE, INFINITE);

    CloseHandle (i_threads[0]);
  }
#endif

#if defined LINUX || defined OSX || defined FREEBSD
  pthread_join (thr_keypress, NULL);

  if (thr_removehash)
  {
    pthread_join (thr_removehash, NULL);
  }

  if (thr_runtime)
  {
    pthread_join (thr_runtime, NULL);
  }

  if (thr_status)
  {
    pthread_join (thr_status, NULL);
  }
#endif
}

void status_display ();
void status_benchmark ();
void save_hash ();

static void clear_prompt ();

time_t proc_start;

time_t proc_stop;

void show_restore_options ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  if (engine_parameter->maskcnt > 1) return;

  /* ensure no output to stdout */

  fclose (stdout);

  /* get words from active threads */

  uint64_t thread_words_total = get_thread_words_total (engine_parameter->num_threads);

  /* print wordskip */

  log_warning ("\nTo restore Session use Parameter -s %llu\n", (status_info.proc_words + engine_parameter->words_skip + thread_words_total));
}

void finalize ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;
  db_t *db = status_info.db;

  wait_finish ();

  uint32_t all_recovered = db->salts_found == db->salts_cnt;

  if (engine_parameter->quiet == 0)
  {
    if (engine_parameter->quiet == 0) clear_prompt ();

    if (all_recovered == 1)
    {
      log_info ("");

      log_info ("All hashes have been recovered");

      status_display ();

      log_info ("");
    }
    else if (engine_parameter->hashcat_status == STATUS_QUIT)
    {
      if (engine_parameter->benchmark == 0) show_restore_options ();

      log_info ("");
    }

    time (&proc_stop);

    printf ("Started: %s", ctime (&proc_start));
    printf ("Stopped: %s", ctime (&proc_stop));
  }

  if (plains_iteration != NULL)
  {
    uint64_t i;

    for (i = 0; i < 1024; i++) free (plains_iteration[i]);

    plains_iteration = NULL;
  }

  // make sure that we always remove the hashes at the end at least once

  if (engine_parameter->remove == 1)
  {
    if (status_info.proc_saved != status_info.proc_recovered)
    {
      status_info.proc_saved = status_info.proc_recovered;

      save_hash ();
    }
  }
}

void myquit ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  engine_parameter->hashcat_status = STATUS_QUIT;
}

void myabort ()
{
  finalize ();

  exit (0);
}

static void show_prompt ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  if (engine_parameter->status_automat == 1) return;

  fprintf (stdout, "\n%s", PROMPT);

  fflush (stdout);
}

static void show_prompt_no_nl ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  if (engine_parameter->status_automat == 1) return;

  fprintf (stdout, "%s", PROMPT);

  fflush (stdout);
}

static void clear_prompt ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  if (engine_parameter->status_automat == 1) return;

  fputc ('\r', stdout);

  uint i;

  for (i = 0; i < strlen (PROMPT); i++)
  {
    fputc (' ', stdout);
  }

  fputc ('\r', stdout);

  fflush (stdout);
}

void status_display_automat ()
{
  db_t *db = status_info.db;

  words_t *words = db->words;

  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  if (status_info.cache_start.tv_sec == 0) return;

  FILE *out = stdout;

  // hashcat status

  fprintf (out, "STATUS\t%u\t", engine_parameter->hashcat_status);

  // index

  fprintf (out, "INDEX\t%llu\t%llu\t", (unsigned long long int) status_info.segment_pos, (unsigned long long int) status_info.segment_cnt);

  // speed

  uint64_t thread_words_total = get_thread_words_total (engine_parameter->num_threads);

  uint64_t thread_plains_total = get_thread_plains_total (engine_parameter->num_threads);

  thread_plains_total *= (db->salts_cnt - db->salts_found);

  gettimeofday (&status_info.cache_current, NULL);

  uint64_t usec_run = TIMESPEC_SUBTRACT (status_info.cache_current, status_info.cache_start);

  usec_run -= engine_parameter->ms_paused;  // pause time

  uint speed_init = 1;

  if (usec_run > (1000 * 30))
  {
    if ((thread_plains_total > 100) && (thread_words_total > 100))
    {
      fprintf (out, "SPEED\t%llu\t%llu\t%llu\t", (unsigned long long int) thread_plains_total, (unsigned long long int) thread_words_total, (unsigned long long int) usec_run);

      speed_init = 0;
    }
    else if (thread_words_total > 100)
    {
      fprintf (out, "SPEED\t0\t%llu\t%llu\t", (unsigned long long int) thread_words_total, (unsigned long long int) usec_run);

      speed_init = 0;
    }
  }

  if (speed_init == 1)
  {
    fprintf (out, "SPEED\t0\t0\t%llu\t", (unsigned long long int) usec_run);
  }

  // words completed + words total (progress)

  if (words->words_cnt)
  {
    fprintf (out, "PROGRESS\t%llu\t%llu\t", (unsigned long long int) (thread_words_total + engine_parameter->words_skip), (unsigned long long int) words->words_cnt);
  }
  else
  {
    fprintf (out, "PROGRESS\t0\t0\t");
  }

  // recovered hashes

  fprintf (out, "RECHASH\t%llu\t%llu\t", (unsigned long long int) status_info.proc_recovered, (unsigned long long int) status_info.proc_hashes);

  // recovered salts

  fprintf (out, "RECSALT\t%llu\t%llu", (unsigned long long int) db->salts_found, (unsigned long long int) db->salts_cnt);

  #ifdef WINDOWS
  fputc ('\r', out);
  fputc ('\n', out);
  #endif

  #if defined LINUX || defined OSX || defined FREEBSD
  fputc ('\n', out);
  #endif

  fflush (out);
}

void status_display ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  // special case (--status-automat)

  if (engine_parameter->status_automat)
  {
    status_display_automat ();

    return;
  }

  uint32_t benchmark = engine_parameter->benchmark;

  db_t *db = status_info.db;

  words_t *words = db->words;

  if (status_info.cache_start.tv_sec == 0)
  {
    if (benchmark == 0) log_info ("Caching segment, please wait...");
  }
  else
  {
    uint64_t thread_words_total = get_thread_words_total (engine_parameter->num_threads);

    uint64_t thread_plains_total = get_thread_plains_total (engine_parameter->num_threads);

    thread_plains_total *= (db->salts_cnt - db->salts_found);

    gettimeofday (&status_info.cache_current, NULL);

    time_t sec_run = status_info.cache_current.tv_sec - status_info.cache_start.tv_sec;

    #ifdef WIN
    __time64_t sec_eta = 0;
    #else
    time_t sec_eta = 0;
    #endif

    uint64_t usec_run = TIMESPEC_SUBTRACT (status_info.cache_current, status_info.cache_start);

    // substract the pause time

    usec_run -= engine_parameter->ms_paused;

    char *words_per_sec_display = "-";

    char *plains_per_sec_display = "-";

    if (usec_run > (1000 * 50))
    {
      if (thread_words_total > 100)
      {
        uint64_t words_per_sec = per_sec (thread_words_total, usec_run);

        if (words_per_sec)
        {
          words_per_sec_display = size_display (words_per_sec);

          sec_eta = (words->words_cnt - engine_parameter->words_skip - thread_words_total) / words_per_sec;
        }
      }

      if (thread_plains_total > 100)
      {
        uint64_t plains_per_sec = per_sec (thread_plains_total, usec_run);

        if (plains_per_sec) plains_per_sec_display = size_display (plains_per_sec);
      }
    }

    log_info ("");

    if (engine_parameter->file_words)
    {
      log_info ("Input.Mode: Dict (%s)", engine_parameter->file_words);
    }
    else
    {
      char *mask = mystrdup (engine_parameter->mask);

      mp_cut_at (mask, engine_parameter->pw_len);

      if (engine_parameter->maskcnt > 1)
      {
        float mask_percentage = (float) engine_parameter->maskpos / (float) engine_parameter->maskcnt;

        log_info ("Input.Mode: Mask (%s) [%i] (%.02f%%)", mask, engine_parameter->pw_len, mask_percentage * 100);
      }
      else
      {
        log_info ("Input.Mode: Mask (%s) [%i]", mask, engine_parameter->pw_len);
      }
    }

    log_info ("Index.....: %llu/%llu (segment), %llu (words), %llu (bytes)", status_info.segment_pos, status_info.segment_cnt, words->words_cnt, words->cache_cnt);
    log_info ("Recovered.: %llu/%llu hashes, %llu/%llu salts", status_info.proc_recovered, status_info.proc_hashes, db->salts_found, db->salts_cnt);
    log_info ("Speed/sec.: %s plains, %s words", plains_per_sec_display, words_per_sec_display);

    if (words->words_cnt)
    {
      log_info ("Progress..: %llu/%llu (%.02f%%)", thread_words_total + engine_parameter->words_skip, words->words_cnt, (double) ((double) ((double) (thread_words_total + engine_parameter->words_skip) / (double) words->words_cnt) * 100));
    }
    else
    {
      log_info ("Progress..: 0/0 (100%)");
    }

    if ((uint64_t) sec_run > ETC_MAX)
    {
      log_info ("Running...: > 10 Years\n");
    }
    else if (sec_run != 0)
    {
      struct tm *tm_run;

      #ifdef WIN

      tm_run = _gmtime64 (&sec_run);

      #else

      tm_run = gmtime (&sec_run);

      #endif

      log_info ("Running...: %02d:%02d:%02d:%02d", tm_run->tm_yday, tm_run->tm_hour, tm_run->tm_min, tm_run->tm_sec);
    }
    else
    {
      log_info ("Running...: --:--:--:--");
    }

    if ((uint64_t) sec_eta > ETC_MAX)
    {
      log_info ("Estimated.: > 10 Years\n");
    }
    else if (sec_eta != 0)
    {
      struct tm *tm_eta;

      #ifdef WIN

      tm_eta = _gmtime64 (&sec_eta);

      #else

      tm_eta = gmtime (&sec_eta);

      #endif

      log_info ("Estimated.: %02d:%02d:%02d:%02d\n", tm_eta->tm_yday, tm_eta->tm_hour, tm_eta->tm_min, tm_eta->tm_sec);
    }
    else
    {
      log_info ("Estimated.: --:--:--:--\n");
    }
  }
}

void status_benchmark ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  db_t *db = status_info.db;

  if (status_info.cache_start.tv_sec != 0)
  {
    uint64_t thread_words_total = get_thread_words_total (engine_parameter->num_threads);

    uint64_t thread_plains_total = get_thread_plains_total (engine_parameter->num_threads);

    thread_plains_total *= (db->salts_cnt - db->salts_found);

    gettimeofday (&status_info.cache_current, NULL);

    uint64_t usec_run = TIMESPEC_SUBTRACT (status_info.cache_current, status_info.cache_start);

    char *words_per_sec_display = "-";

    if (usec_run > (1000 * 50))
    {
      if (thread_words_total > 100)
      {
        uint64_t words_per_sec = per_sec (thread_words_total, usec_run);

        if (words_per_sec)
        {
          words_per_sec_display = size_display (words_per_sec);
        }
      }
    }

    log_info ("Hash type: %s", strhashtype (engine_parameter->hash_mode));
    log_info ("Speed/sec: %s words", words_per_sec_display);
    log_info ("");
  }
}

char int_to_base64 (const char c);
char base64b_int2char (int i);
char base64_to_int (const char c);

void write_digest (FILE *fp, digest_t *digest, salt_t *salt)
{
  uint out_buf_plain[256];
  uint out_buf_salt[256];

  char tmp_buf[1024];
  char tmp_buf2[1024];

  uint *uint_tmp_buf_ptr  = (uint *) tmp_buf;
  uint *uint_tmp_buf_ptr2 = (uint *) tmp_buf2;

  memset (out_buf_plain, 0, sizeof (out_buf_plain));
  memset (out_buf_salt,  0, sizeof (out_buf_salt));

  memset (tmp_buf,  0, sizeof (tmp_buf));
  memset (tmp_buf2, 0, sizeof (tmp_buf2));

  char *ptr_plain = (char *) out_buf_plain;
  char *ptr_salt  = (char *) out_buf_salt;

  char buf[100];

  uint32_t *uintptr     = (uint32_t *) salt->salt_plain_buf;
  uint32_t *uintptr_pre = (uint32_t *) salt->salt_prehashed_buf;

  uint32_t tmp;

  uint32_t tmp_len;

  memset (buf, 0, sizeof (buf));

  uint32_t swap[8];
  uint64_t swap64[8];

  switch (status_info.engine_parameter->hash_type)
  {
    case HASH_TYPE_MD5:

      swap[0] = __builtin_bswap32 (digest->buf.md5[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md5[1]);

      if (status_info.engine_parameter->hash_mode == 5100)
      {
        fprintf (fp, "%08x%08x", swap[0], swap[1]);
      }
      else
      {
        swap[2] = __builtin_bswap32 (digest->buf.md5[2]);
        swap[3] = __builtin_bswap32 (digest->buf.md5[3]);

        fprintf (fp, "%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);
      }

      break;

    case HASH_TYPE_SHA1:

      fprintf (fp, "%08x%08x%08x%08x%08x", digest->buf.sha1[0], digest->buf.sha1[1], digest->buf.sha1[2], digest->buf.sha1[3], digest->buf.sha1[4]);

      break;

    case HASH_TYPE_OSX1:

      fprintf (fp, "%s%08x%08x%08x%08x%08x", salt->salt_plain_buf, digest->buf.sha1[0], digest->buf.sha1[1], digest->buf.sha1[2], digest->buf.sha1[3], digest->buf.sha1[4]);

      break;

    case HASH_TYPE_OSX512:

      fprintf (fp, "%s%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx",
        salt->salt_plain_buf,
        (long long unsigned int) digest->buf.sha512[0],
        (long long unsigned int) digest->buf.sha512[1],
        (long long unsigned int) digest->buf.sha512[2],
        (long long unsigned int) digest->buf.sha512[3],
        (long long unsigned int) digest->buf.sha512[4],
        (long long unsigned int) digest->buf.sha512[5],
        (long long unsigned int) digest->buf.sha512[6],
        (long long unsigned int) digest->buf.sha512[7]);

      break;

    case HASH_TYPE_MYSQL:

      fprintf (fp, "%08x%08x", digest->buf.mysql[0], digest->buf.mysql[1]);

      break;

    case HASH_TYPE_PHPASS:

      phpass_encode ((unsigned char *) &digest->buf.md5, (unsigned char *) buf);

      buf[HASH_SIZE_PHPASS] = 0;

      fprintf (fp, "%s", salt->signature);
      fprintf (fp, "%c", base64b_int2char ((uint32_t) log2 (salt->iterations)));
      fprintf (fp, "%s", salt->salt_plain_buf);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_MD5UNIX:

      md5unix_encode ((unsigned char *) &digest->buf.md5, (unsigned char *) buf);

      buf[HASH_SIZE_MD5UNIX] = 0;

      fprintf (fp, "%s", MD5UNIX_MAGIC);

      if (salt->iterations != MD5UNIX_ROUNDS) fprintf (fp, "rounds=%i$", salt->iterations);

      fprintf (fp, "%s", salt->salt_plain_buf);
      fprintf (fp, "%s", "$");
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_MD5SUN:

      md5sun_encode ((unsigned char *) &digest->buf.md5, (unsigned char *) buf);

      buf[PLAIN_SIZE_MD5SUN] = 0;

      fprintf (fp, "%s$", salt->salt_plain_buf);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SHA1B64:

      swap[0] = __builtin_bswap32 (digest->buf.sha1[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha1[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha1[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha1[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha1[4]);

      sha1b64_encode ((unsigned char *) swap, (unsigned char *) buf);

      buf[HASH_SIZE_SHA1B64] = 0;

      fprintf (fp, "%s", SHA1B64_MAGIC);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SHA1B64S:

      swap[0] = __builtin_bswap32 (digest->buf.sha1[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha1[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha1[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha1[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha1[4]);

      sha1b64s_encode ((unsigned char *) swap, (unsigned char *) salt->salt_plain_buf, salt->salt_plain_len, buf);

      fprintf (fp, "%s", SHA1B64S_MAGIC);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SHA256B64:

      swap[0] = __builtin_bswap32 (digest->buf.sha256[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha256[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha256[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha256[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha256[4]);
      swap[5] = __builtin_bswap32 (digest->buf.sha256[5]);
      swap[6] = __builtin_bswap32 (digest->buf.sha256[6]);
      swap[7] = __builtin_bswap32 (digest->buf.sha256[7]);

      sha256b64_encode ((unsigned char *) swap, (unsigned char *) buf);

      buf[HASH_SIZE_SHA256B64] = 0;

      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_MD4:

      swap[0] = __builtin_bswap32 (digest->buf.md4[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md4[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md4[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md4[3]);

      fprintf (fp, "%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);

      break;

    case HASH_TYPE_DCC:

      swap[0] = __builtin_bswap32 (digest->buf.md4[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md4[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md4[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md4[3]);

      fprintf (fp, "%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);
      fprintf (fp, "%c", status_info.engine_parameter->separator);
      fprintf (fp, "%s", salt->salt_plain_buf);

      break;

    case HASH_TYPE_MD5CHAP:

      swap[0] = __builtin_bswap32 (digest->buf.md5[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md5[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md5[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md5[3]);

      fprintf (fp, "%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);
      fprintf (fp, "%c", status_info.engine_parameter->separator);

      swap[0] = __builtin_bswap32 (uintptr[0]);
      swap[1] = __builtin_bswap32 (uintptr[1]);
      swap[2] = __builtin_bswap32 (uintptr[2]);
      swap[3] = __builtin_bswap32 (uintptr[3]);

      fprintf (fp, "%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);
      fprintf (fp, "%c", status_info.engine_parameter->separator);
      fprintf (fp, "%02x", (unsigned char) salt->md5chap_idbyte);

      break;

    case HASH_TYPE_MSSQL2000:

      memcpy (&tmp, salt->salt_plain_buf, 4);

      BYTESWAP (tmp);

      fprintf (fp, "%s", MSSQL_MAGIC);
      fprintf (fp, "%08x", tmp);

      fprintf (fp, "%08x%08x%08x%08x%08x", uintptr_pre[0], uintptr_pre[1], uintptr_pre[2], uintptr_pre[3], uintptr_pre[4]);

      fprintf (fp, "%08x%08x%08x%08x%08x", digest->buf.sha1[0], digest->buf.sha1[1], digest->buf.sha1[2], digest->buf.sha1[3], digest->buf.sha1[4]);

      break;

    case HASH_TYPE_MSSQL2005:

      memcpy (&tmp, salt->salt_plain_buf, 4);

      BYTESWAP (tmp);

      fprintf (fp, "%s", MSSQL_MAGIC);
      fprintf (fp, "%08x", tmp);

      fprintf (fp, "%08x%08x%08x%08x%08x", digest->buf.sha1[0], digest->buf.sha1[1], digest->buf.sha1[2], digest->buf.sha1[3], digest->buf.sha1[4]);

      break;

    case HASH_TYPE_EPIV6:

      memcpy (tmp_buf, salt->salt_plain_buf, salt->salt_plain_len);

      base64_encode (int_to_base64, tmp_buf, salt->salt_plain_len, ptr_salt);

      memset (tmp_buf, 0, sizeof (tmp_buf));
      memcpy (tmp_buf, digest->buf.sha1, 20);

      BYTESWAP (uint_tmp_buf_ptr[0]);
      BYTESWAP (uint_tmp_buf_ptr[1]);
      BYTESWAP (uint_tmp_buf_ptr[2]);
      BYTESWAP (uint_tmp_buf_ptr[3]);
      BYTESWAP (uint_tmp_buf_ptr[4]);

      base64_encode (int_to_base64, tmp_buf, 20, ptr_plain);

      ptr_plain[HASH_SIZE_EPIV6_MAX] = 0;

      fprintf (fp, "%s%s*%s", EPISERVERV6_MAGIC, ptr_salt, ptr_plain);

      break;

    case HASH_TYPE_SHA256:

      fprintf (fp, "%08x%08x%08x%08x%08x%08x%08x%08x", digest->buf.sha256[0], digest->buf.sha256[1], digest->buf.sha256[2], digest->buf.sha256[3], digest->buf.sha256[4], digest->buf.sha256[5], digest->buf.sha256[6], digest->buf.sha256[7]);

      break;

    case HASH_TYPE_MD5APR:

      md5apr_encode ((unsigned char *) &digest->buf.md5, (unsigned char *) buf);

      buf[HASH_SIZE_MD5APR] = 0;

      fprintf (fp, "%s", MD5APR_MAGIC);

      if (salt->iterations != MD5APR_ROUNDS) fprintf (fp, "rounds=%i$", salt->iterations);

      fprintf (fp, "%s", salt->salt_plain_buf);
      fprintf (fp, "%s", "$");
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SHA512:

      fprintf (fp, "%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx",
        (long long unsigned int) digest->buf.sha512[0],
        (long long unsigned int) digest->buf.sha512[1],
        (long long unsigned int) digest->buf.sha512[2],
        (long long unsigned int) digest->buf.sha512[3],
        (long long unsigned int) digest->buf.sha512[4],
        (long long unsigned int) digest->buf.sha512[5],
        (long long unsigned int) digest->buf.sha512[6],
        (long long unsigned int) digest->buf.sha512[7]);

      break;

    case HASH_TYPE_SHA512UNIX:

      sha512unix_encode ((unsigned char *) &digest->buf.sha512, (unsigned char *) buf);

      buf[HASH_SIZE_SHA512UNIX] = 0;

      fprintf (fp, "%s", SHA512UNIX_MAGIC);

      if (salt->iterations != SHA512UNIX_ROUNDS) fprintf (fp, "rounds=%i$", salt->iterations);

      fprintf (fp, "%s", salt->salt_plain_buf);
      fprintf (fp, "%s", "$");
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_MSSQL2012:

      memcpy (&tmp, salt->salt_plain_buf, 4);

      BYTESWAP (tmp);

      fprintf (fp, "%s", MSSQL2012_MAGIC);
      fprintf (fp, "%08x", tmp);

      fprintf (fp, "%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx",
        (long long unsigned int) digest->buf.sha512[0],
        (long long unsigned int) digest->buf.sha512[1],
        (long long unsigned int) digest->buf.sha512[2],
        (long long unsigned int) digest->buf.sha512[3],
        (long long unsigned int) digest->buf.sha512[4],
        (long long unsigned int) digest->buf.sha512[5],
        (long long unsigned int) digest->buf.sha512[6],
        (long long unsigned int) digest->buf.sha512[7]);

      break;

    case HASH_TYPE_DESCRYPT:
      descrypt_encode ((unsigned char *) &digest->buf.descrypt, (unsigned char *) buf);

      buf[HASH_SIZE_DESCRYPT] = 0;

      fprintf (fp, "%s", salt->salt_plain_buf);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_KECCAK:

      for (tmp = 0; tmp < salt->keccak_mdlen / 8; tmp++)
      {
        uint64_t v = digest->buf.keccak[tmp];

        BYTESWAP64 (v);

        fprintf (fp, "%.16llx", (long long unsigned int) v);
      }

      break;

    case HASH_TYPE_WPA:
      fprintf (fp, "%s", status_info.engine_parameter->file_hashes);
      break;

    case HASH_TYPE_PSAFE3:
      fprintf (fp, "%s", status_info.engine_parameter->file_hashes);
      break;

    case HASH_TYPE_IKEPSK_MD5:
      fprintf (fp, "%s", status_info.engine_parameter->file_hashes);
      break;

    case HASH_TYPE_IKEPSK_SHA1:
      fprintf (fp, "%s", status_info.engine_parameter->file_hashes);
      break;

    case HASH_TYPE_NETNTLMv1:

      for (tmp = 0; tmp < salt->netntlm->user_len; tmp += 2)
      {
        char *ptr = (char *) salt->netntlm->userdomain_buf;

        fprintf (fp, "%c", ptr[tmp]);
      }

      fprintf (fp, "::");

      for (tmp = 0; tmp < salt->netntlm->domain_len; tmp += 2)
      {
        char *ptr = (char *) salt->netntlm->userdomain_buf;

        fprintf (fp, "%c", ptr[salt->netntlm->user_len + tmp]);
      }

      fprintf (fp, ":");

      for (tmp = 0; tmp < salt->netntlm->srvchall_len; tmp++)
      {
        char *ptr = (char *) salt->netntlm->chall_buf;

        fprintf (fp, "%02x", (uint8_t) ptr[tmp]);
      }

      fprintf (fp, ":");

      fprintf (fp, "%08x%08x%08x%08x%08x%08x",
        (unsigned int) __builtin_bswap32 (digest->buf.md4[0]),
        (unsigned int) __builtin_bswap32 (digest->buf.md4[1]),
        (unsigned int) __builtin_bswap32 (digest->buf.md4[2]),
        (unsigned int) __builtin_bswap32 (digest->buf.md4[3]),
        (unsigned int) __builtin_bswap32 (digest->buf.md4[4]),
        (unsigned int) __builtin_bswap32 (digest->buf.md4[5]));

      fprintf (fp, ":");

      for (tmp = 0; tmp < salt->netntlm->clichall_len; tmp++)
      {
        char *ptr = (char *) salt->netntlm->chall_buf;

        fprintf (fp, "%02x", (uint8_t) ptr[salt->netntlm->srvchall_len + tmp]);
      }

      break;

    case HASH_TYPE_NETNTLMv2:

      for (tmp = 0; tmp < salt->netntlm->user_len; tmp += 2)
      {
        char *ptr = (char *) salt->netntlm->userdomain_buf;

        fprintf (fp, "%c", ptr[tmp]);
      }

      fprintf (fp, "::");

      for (tmp = 0; tmp < salt->netntlm->domain_len; tmp += 2)
      {
        char *ptr = (char *) salt->netntlm->userdomain_buf;

        fprintf (fp, "%c", ptr[salt->netntlm->user_len + tmp]);
      }

      fprintf (fp, ":");

      for (tmp = 0; tmp < salt->netntlm->srvchall_len; tmp++)
      {
        char *ptr = (char *) salt->netntlm->chall_buf;

        fprintf (fp, "%02x", (uint8_t) ptr[tmp]);
      }

      fprintf (fp, ":");

      fprintf (fp, "%08x%08x%08x%08x",
        (unsigned int) __builtin_bswap32 (digest->buf.md5[0]),
        (unsigned int) __builtin_bswap32 (digest->buf.md5[1]),
        (unsigned int) __builtin_bswap32 (digest->buf.md5[2]),
        (unsigned int) __builtin_bswap32 (digest->buf.md5[3]));

      fprintf (fp, ":");

      for (tmp = 0; tmp < salt->netntlm->clichall_len; tmp++)
      {
        char *ptr = (char *) salt->netntlm->chall_buf;

        fprintf (fp, "%02x", (uint8_t) ptr[salt->netntlm->srvchall_len + tmp]);
      }

      break;

    case HASH_TYPE_CISCO_SECRET4:

      memcpy (tmp_buf, digest->buf.sha256, 32);

      BYTESWAP (uint_tmp_buf_ptr[0]);
      BYTESWAP (uint_tmp_buf_ptr[1]);
      BYTESWAP (uint_tmp_buf_ptr[2]);
      BYTESWAP (uint_tmp_buf_ptr[3]);
      BYTESWAP (uint_tmp_buf_ptr[4]);
      BYTESWAP (uint_tmp_buf_ptr[5]);
      BYTESWAP (uint_tmp_buf_ptr[6]);
      BYTESWAP (uint_tmp_buf_ptr[7]);

      base64_encode (int_to_itoa64, tmp_buf, 32, ptr_plain);

      ptr_plain[43] = 0;

      fprintf (fp, "%s", ptr_plain);

      break;

    case HASH_TYPE_MD5AIX:

      md5unix_encode ((unsigned char *) &digest->buf.md5, (unsigned char *) buf);

      buf[HASH_SIZE_MD5UNIX] = 0;

      fprintf (fp, "%s", MD5AIX_MAGIC);

      if (salt->iterations != MD5AIX_ROUNDS) fprintf (fp, "rounds=%i$", salt->iterations);

      fprintf (fp, "%s", salt->salt_plain_buf);
      fprintf (fp, "%s", "$");
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SHA1AIX:

      swap[0] = __builtin_bswap32 (digest->buf.sha1[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha1[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha1[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha1[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha1[4]);

      sha1aix_encode ((unsigned char *) swap, (unsigned char *) buf);

      buf[HASH_SIZE_SHA1AIX] = 0;

      fprintf (fp, "%s", SHA1AIX_MAGIC);
      fprintf (fp, "%02d$", (uint32_t) log2 (salt->iterations));
      fprintf (fp, "%s$", (unsigned char *) salt->salt_plain_buf);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SHA256AIX:

      swap[0] = __builtin_bswap32 (digest->buf.sha256[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha256[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha256[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha256[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha256[4]);
      swap[5] = __builtin_bswap32 (digest->buf.sha256[5]);
      swap[6] = __builtin_bswap32 (digest->buf.sha256[6]);
      swap[7] = __builtin_bswap32 (digest->buf.sha256[7]);

      sha256aix_encode ((unsigned char *) swap, (unsigned char *) buf);

      buf[HASH_SIZE_SHA256AIX] = 0;

      fprintf (fp, "%s", SHA256AIX_MAGIC);
      fprintf (fp, "%02d$", (uint32_t) log2 (salt->iterations));
      fprintf (fp, "%s$", (unsigned char *) salt->salt_plain_buf);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SHA512AIX:

      swap64[0] = __builtin_bswap64 (digest->buf.sha512[0]);
      swap64[1] = __builtin_bswap64 (digest->buf.sha512[1]);
      swap64[2] = __builtin_bswap64 (digest->buf.sha512[2]);
      swap64[3] = __builtin_bswap64 (digest->buf.sha512[3]);
      swap64[4] = __builtin_bswap64 (digest->buf.sha512[4]);
      swap64[5] = __builtin_bswap64 (digest->buf.sha512[5]);
      swap64[6] = __builtin_bswap64 (digest->buf.sha512[6]);
      swap64[7] = __builtin_bswap64 (digest->buf.sha512[7]);

      sha512aix_encode ((unsigned char *) swap64, (unsigned char *) buf);

      buf[HASH_SIZE_SHA512AIX] = 0;

      fprintf (fp, "%s", SHA512AIX_MAGIC);
      fprintf (fp, "%02d$", (uint32_t) log2 (salt->iterations));
      fprintf (fp, "%s$", (unsigned char *) salt->salt_plain_buf);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_GOST:

      fprintf (fp, "%08x%08x%08x%08x%08x%08x%08x%08x",
        digest->buf.gost[0],
        digest->buf.gost[1],
        digest->buf.gost[2],
        digest->buf.gost[3],
        digest->buf.gost[4],
        digest->buf.gost[5],
        digest->buf.gost[6],
        digest->buf.gost[7]);

      break;

    case HASH_TYPE_SHA1FORTIGATE:
      swap[0] = __builtin_bswap32 (digest->buf.sha1[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha1[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha1[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha1[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha1[4]);

      sha1fortigate_encode ((unsigned char *) swap, (unsigned char *) salt->salt_plain_buf, buf);

      buf[44] = 0;

      fprintf (fp, "%s%s", FORTIGATE_MAGIC, buf);
      break;

    case HASH_TYPE_PBKDF2OSX:
    {
      fprintf (fp, "%s%d$", PBKDF2OSX_MAGIC, salt->iterations);

      uint32_t iter;

      for (iter = 0; iter < salt->salt_plain_len; iter += 1) fprintf (fp, "%02x", (unsigned char) salt->salt_plain_buf[iter]);

      fprintf (fp, "$%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx",
        (long long unsigned int) digest->buf.sha512[0],
        (long long unsigned int) digest->buf.sha512[1],
        (long long unsigned int) digest->buf.sha512[2],
        (long long unsigned int) digest->buf.sha512[3],
        (long long unsigned int) digest->buf.sha512[4],
        (long long unsigned int) digest->buf.sha512[5],
        (long long unsigned int) digest->buf.sha512[6],
        (long long unsigned int) digest->buf.sha512[7]);

      break;
    }
    case HASH_TYPE_PBKDF2GRUB:
    {
      fprintf (fp, "%s%d.", PBKDF2GRUB_MAGIC, salt->iterations);

      uint32_t iter;

      for (iter = 0; iter < salt->salt_plain_len; iter += 1) fprintf (fp, "%02x", (unsigned char) salt->salt_plain_buf[iter]);

      fprintf (fp, ".%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx%.16llx",
        (long long unsigned int) digest->buf.sha512[0],
        (long long unsigned int) digest->buf.sha512[1],
        (long long unsigned int) digest->buf.sha512[2],
        (long long unsigned int) digest->buf.sha512[3],
        (long long unsigned int) digest->buf.sha512[4],
        (long long unsigned int) digest->buf.sha512[5],
        (long long unsigned int) digest->buf.sha512[6],
        (long long unsigned int) digest->buf.sha512[7]);

      break;
    }
    case HASH_TYPE_MD5CISCO_PIX:

      md5cisco_encode (digest->buf.md5, (unsigned char *) buf);

      buf[HASH_SIZE_MD5CISCO] = 0;

      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SHA1ORACLE:

      fprintf (fp, "%08x%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
        digest->buf.sha1[0],
        digest->buf.sha1[1],
        digest->buf.sha1[2],
        digest->buf.sha1[3],
        digest->buf.sha1[4],
        (unsigned char) salt->salt_plain_buf[0],
        (unsigned char) salt->salt_plain_buf[1],
        (unsigned char) salt->salt_plain_buf[2],
        (unsigned char) salt->salt_plain_buf[3],
        (unsigned char) salt->salt_plain_buf[4],
        (unsigned char) salt->salt_plain_buf[5],
        (unsigned char) salt->salt_plain_buf[6],
        (unsigned char) salt->salt_plain_buf[7],
        (unsigned char) salt->salt_plain_buf[8],
        (unsigned char) salt->salt_plain_buf[9]);

      break;

    case HASH_TYPE_HMACRAKP:
    {
      uint32_t iter;

      for (iter = 0; iter < salt->salt_plain_len; iter += 1) fprintf (fp, "%02x", (unsigned char) salt->salt_plain_buf[iter]);

      fprintf (fp, ":%08x%08x%08x%08x%08x",
        digest->buf.sha1[0],
        digest->buf.sha1[1],
        digest->buf.sha1[2],
        digest->buf.sha1[3],
        digest->buf.sha1[4]);

      break;
    }

    case HASH_TYPE_BCRYPT:

      memcpy (tmp_buf, digest->buf.bcrypt, 24);

      BYTESWAP (uint_tmp_buf_ptr[0]);
      BYTESWAP (uint_tmp_buf_ptr[1]);
      BYTESWAP (uint_tmp_buf_ptr[2]);
      BYTESWAP (uint_tmp_buf_ptr[3]);
      BYTESWAP (uint_tmp_buf_ptr[4]);
      BYTESWAP (uint_tmp_buf_ptr[5]);

      memcpy (tmp_buf2, salt->salt_plain_buf, 16);

      BYTESWAP (uint_tmp_buf_ptr2[0]);
      BYTESWAP (uint_tmp_buf_ptr2[1]);
      BYTESWAP (uint_tmp_buf_ptr2[2]);
      BYTESWAP (uint_tmp_buf_ptr2[3]);

      bcrypt_encode ((char *) uint_tmp_buf_ptr, (char *) uint_tmp_buf_ptr2, buf);

      fprintf (fp, "%s%02d$%s", salt->signature, (uint32_t) log2 (salt->iterations), buf);

      break;

    case HASH_TYPE_SHA256UNIX:

      sha256unix_encode ((unsigned char *) &digest->buf.sha256, (unsigned char *) buf);

      buf[HASH_SIZE_SHA256UNIX] = 0;

      fprintf (fp, "%s",        SHA256UNIX_MAGIC);

      if (salt->iterations != SHA256UNIX_ROUNDS) fprintf (fp, "rounds=%i$", salt->iterations);

      fprintf (fp, "%s",        salt->salt_plain_buf);
      fprintf (fp, "%s",        "$");
      fprintf (fp, "%s",        buf);

      break;

    case HASH_TYPE_EPIV6_4:

      memcpy (tmp_buf, salt->salt_plain_buf, salt->salt_plain_len);

      base64_encode (int_to_base64, tmp_buf, salt->salt_plain_len, ptr_salt);

      swap[0] = __builtin_bswap32 (digest->buf.sha256[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha256[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha256[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha256[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha256[4]);
      swap[5] = __builtin_bswap32 (digest->buf.sha256[5]);
      swap[6] = __builtin_bswap32 (digest->buf.sha256[6]);
      swap[7] = __builtin_bswap32 (digest->buf.sha256[7]);

      memset (tmp_buf, 0, sizeof (tmp_buf));

      memcpy (tmp_buf, swap, 32);

      base64_encode (int_to_base64, tmp_buf, 32, ptr_plain);

      ptr_plain[HASH_SIZE_EPIV6_4_MAX] = 0;

      fprintf (fp, "%s%s*%s", EPISERVERV6_4_MAGIC, ptr_salt, ptr_plain);

      break;

    case HASH_TYPE_SHA512B64S:

      swap64[0] = __builtin_bswap64 (digest->buf.sha512[0]);
      swap64[1] = __builtin_bswap64 (digest->buf.sha512[1]);
      swap64[2] = __builtin_bswap64 (digest->buf.sha512[2]);
      swap64[3] = __builtin_bswap64 (digest->buf.sha512[3]);
      swap64[4] = __builtin_bswap64 (digest->buf.sha512[4]);
      swap64[5] = __builtin_bswap64 (digest->buf.sha512[5]);
      swap64[6] = __builtin_bswap64 (digest->buf.sha512[6]);
      swap64[7] = __builtin_bswap64 (digest->buf.sha512[7]);

      sha512b64s_encode ((unsigned char *) swap64, (unsigned char *) salt->salt_plain_buf, salt->salt_plain_len, buf);

      fprintf (fp, "%s", SHA512B64S_MAGIC);
      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_EPIV4:

      fprintf (fp, "%s", EPISERVERV4_MAGIC);

      uint32_t iter;

      for (iter = 0; iter < salt->salt_plain_len + 1; iter += 1) fprintf (fp, "%02X", (unsigned char) salt->salt_plain_buf[iter]);

      fprintf (fp, " %s%08X%08X%08X%08X%08X",
        EPISERVERV4_MAGIC,
        digest->buf.sha1[0],
        digest->buf.sha1[1],
        digest->buf.sha1[2],
        digest->buf.sha1[3],
        digest->buf.sha1[4]);

      break;

    case HASH_TYPE_SCRYPT:

      memcpy (tmp_buf, salt->salt_plain_buf, salt->salt_plain_len);

      base64_encode (int_to_base64, tmp_buf, salt->salt_plain_len, ptr_salt);

      memset (tmp_buf, 0, sizeof (tmp_buf));

      swap[0] = __builtin_bswap32 (digest->buf.sha256[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha256[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha256[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha256[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha256[4]);
      swap[5] = __builtin_bswap32 (digest->buf.sha256[5]);
      swap[6] = __builtin_bswap32 (digest->buf.sha256[6]);
      swap[7] = __builtin_bswap32 (digest->buf.sha256[7]);

      memcpy (tmp_buf, swap, 32);

      base64_encode (int_to_base64, tmp_buf, 32, ptr_plain);

      ptr_plain[HASH_SIZE_SCRYPT_MAX] = 0;

      fprintf (fp, "%s:%i:%i:%i:%s:%s", SCRYPT_MAGIC, salt->scrypt_N, salt->scrypt_r, salt->scrypt_p, ptr_salt, ptr_plain);

      break;

    case HASH_TYPE_CISCO_SECRET9:

      memset (tmp_buf, 0, sizeof (tmp_buf));

      swap[0] = __builtin_bswap32 (digest->buf.sha256[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha256[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha256[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha256[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha256[4]);
      swap[5] = __builtin_bswap32 (digest->buf.sha256[5]);
      swap[6] = __builtin_bswap32 (digest->buf.sha256[6]);
      swap[7] = __builtin_bswap32 (digest->buf.sha256[7]);

      memcpy (tmp_buf, swap, 32);

      base64_encode (int_to_itoa64, tmp_buf, 32, ptr_plain);
      ptr_plain[HASH_SIZE_CISCO_SECRET9] = 0;

      fprintf (fp, "%s%s$%s", CISCO_SECRET9_MAGIC, salt->salt_plain_buf, ptr_plain);

      break;

    case HASH_TYPE_PHPS:

      swap[0] = __builtin_bswap32 (digest->buf.md5[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md5[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md5[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md5[3]);

      fprintf (fp, "%s", PHPS_MAGIC);

      uint32_t i;

      for (i = 0; i < salt->salt_plain_len; i++) fprintf (fp, "%02x", (unsigned char) salt->salt_plain_buf[i]);

      fprintf (fp, "$%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);

      break;

    case HASH_TYPE_DJANGOSHA1:

      fprintf (fp, "%s%s$%08x%08x%08x%08x%08x",
        DJANGOSHA1_MAGIC,
        salt->salt_plain_buf,
        digest->buf.sha1[0],
        digest->buf.sha1[1],
        digest->buf.sha1[2],
        digest->buf.sha1[3],
        digest->buf.sha1[4]);

      break;

    case HASH_TYPE_HMAIL:

      fprintf (fp, "%s%08x%08x%08x%08x%08x%08x%08x%08x",
        salt->salt_plain_buf,
        digest->buf.sha256[0],
        digest->buf.sha256[1],
        digest->buf.sha256[2],
        digest->buf.sha256[3],
        digest->buf.sha256[4],
        digest->buf.sha256[5],
        digest->buf.sha256[6],
        digest->buf.sha256[7]);

      break;

    case HASH_TYPE_MEDIAWIKI_B:

      swap[0] = __builtin_bswap32 (digest->buf.md5[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md5[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md5[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md5[3]);

      fprintf (fp, "%s", MEDIAWIKI_B_MAGIC);

      for (i = 0; i < salt->salt_plain_len - 1; i++) fprintf (fp, "%c", (unsigned char) salt->salt_plain_buf[i]);

      fprintf (fp, "$%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);

      break;

    case HASH_TYPE_CISCO_SECRET8:

      memset (tmp_buf, 0, sizeof (tmp_buf));

      swap[0] = __builtin_bswap32 (digest->buf.sha256[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha256[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha256[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha256[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha256[4]);
      swap[5] = __builtin_bswap32 (digest->buf.sha256[5]);
      swap[6] = __builtin_bswap32 (digest->buf.sha256[6]);
      swap[7] = __builtin_bswap32 (digest->buf.sha256[7]);

      memcpy (tmp_buf, swap, 32);

      base64_encode (int_to_itoa64, tmp_buf, 32, ptr_plain);
      ptr_plain[HASH_SIZE_CISCO_SECRET8] = 0;

      fprintf (fp, "%s%s$%s",
        CISCO_SECRET8_MAGIC,
        (unsigned char *) salt->salt_plain_buf,
        ptr_plain);

      break;

    case HASH_TYPE_DJANGO_SHA256:

      memset (tmp_buf, 0, sizeof (tmp_buf));

      swap[0] = __builtin_bswap32 (digest->buf.sha256[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha256[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha256[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha256[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha256[4]);
      swap[5] = __builtin_bswap32 (digest->buf.sha256[5]);
      swap[6] = __builtin_bswap32 (digest->buf.sha256[6]);
      swap[7] = __builtin_bswap32 (digest->buf.sha256[7]);

      memcpy (tmp_buf, swap, 32);

      base64_encode (int_to_base64, tmp_buf, 32, ptr_plain);
      ptr_plain[HASH_SIZE_DJANGO_SHA256] = 0;

      fprintf (fp, "%s%i$%s$%s",
        DJANGO_SHA256_MAGIC,
        salt->iterations,
        (unsigned char *) salt->salt_plain_buf,
        ptr_plain);

      break;

    case HASH_TYPE_PEOPLESOFT:

      memset (tmp_buf, 0, sizeof (tmp_buf));

      swap[0] = __builtin_bswap32 (digest->buf.sha1[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha1[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha1[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha1[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha1[4]);

      memcpy (tmp_buf, swap, 20);

      base64_encode (int_to_base64, tmp_buf, 20, ptr_plain);

      ptr_plain[HASH_SIZE_PEOPLESOFT] = 0;

      fprintf (fp, "%s", ptr_plain);

      break;

    case HASH_TYPE_CRAM_MD5:

      swap[0] = __builtin_bswap32 (digest->buf.md5[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md5[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md5[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md5[3]);

      // magic + salt

      tmp_len = base64_encode (int_to_base64, salt->salt_plain_buf, salt->salt_plain_len, ptr_plain);

      ptr_plain[tmp_len + 1] = 0;

      fprintf (fp, "%s%s", CRAM_MD5_MAGIC, ptr_plain);

      // digest

      memset (tmp_buf, 0, sizeof (tmp_buf));

      memcpy (tmp_buf, salt->salt_prehashed_buf, salt->salt_prehashed_len);

      uint used_len = salt->salt_prehashed_len;

      uint remaining_len = sizeof (tmp_buf) - used_len;

      snprintf (tmp_buf + used_len , remaining_len, "%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);

      used_len += 32;

      // encode it (username . " " . hex_hash)

      tmp_len = base64_encode (int_to_base64, tmp_buf, used_len, ptr_plain);

      ptr_plain[tmp_len + 1] = 0;

      fprintf (fp, "$%s", ptr_plain);

      break;

    case HASH_TYPE_DRUPAL7:

      swap64[0] = __builtin_bswap64 (digest->buf.sha512[0]);
      swap64[1] = __builtin_bswap64 (digest->buf.sha512[1]);
      swap64[2] = __builtin_bswap64 (digest->buf.sha512[2]);
      swap64[3] = __builtin_bswap64 (digest->buf.sha512[3]);
      swap64[4] = __builtin_bswap64 (digest->buf.sha512[4]);

      drupal7_encode ((unsigned char *) &swap64, (unsigned char *) buf);

      buf[HASH_SIZE_DRUPAL7] = 0;

      fprintf (fp, "%s%c%s%s", DRUPAL7_MAGIC,  base64b_int2char ((uint32_t) log2 (salt->iterations)), salt->salt_plain_buf, buf);

      break;

    case HASH_TYPE_MD5CISCO_ASA:

      md5cisco_encode (digest->buf.md5, (unsigned char *) buf);

      buf[HASH_SIZE_MD5CISCO] = 0;

      fprintf (fp, "%s", buf);

      break;

    case HASH_TYPE_SAP_H_SHA1:

      swap[0] = __builtin_bswap32 (digest->buf.sha1[0]);
      swap[1] = __builtin_bswap32 (digest->buf.sha1[1]);
      swap[2] = __builtin_bswap32 (digest->buf.sha1[2]);
      swap[3] = __builtin_bswap32 (digest->buf.sha1[3]);
      swap[4] = __builtin_bswap32 (digest->buf.sha1[4]);

      memcpy (buf, swap, 20);
      memcpy (buf + 20, salt->salt_plain_buf, salt->salt_plain_len);

      uint tmp_len = base64_encode (int_to_base64, buf, 20 + salt->salt_plain_len, ptr_plain);

      ptr_plain[tmp_len + 1] = 0;

      fprintf (fp, "%s%i}%s", SAP_H_SHA1_MAGIC, salt->iterations, ptr_plain);

      break;

    case HASH_TYPE_PRESTASHOP:

      swap[0] = __builtin_bswap32 (digest->buf.md5[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md5[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md5[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md5[3]);

      fprintf (fp, "%08x%08x%08x%08x", swap[0], swap[1], swap[2], swap[3]);

      break;

    case HASH_TYPE_POSTGRESQL_AUTH:

      swap[0] = __builtin_bswap32 (digest->buf.md5[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md5[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md5[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md5[3]);

      // user name

      plain_t *user_name_plain = salt->additional_plain_struct;

      unsigned char *user_name = (unsigned char *) user_name_plain->buf;

      // 4 byte salt

      uint32_t *salt_buf_ptr = (uint32_t *) salt->salt_plain_buf;

      uint32_t salt_uint = salt_buf_ptr[0];

      salt_uint = __builtin_bswap32 (salt_uint);

      // print

      fprintf (fp, "%s%s*%08x*%08x%08x%08x%08x", POSTGRESQL_AUTH_MAGIC, user_name, salt_uint, swap[0], swap[1], swap[2], swap[3]);

      break;

    case HASH_TYPE_MYSQL_AUTH:
    {
      uint32_t *salt_ptr = (uint32_t *) salt->salt_plain_buf;

      swap[0] = __builtin_bswap32 (salt_ptr[0]);
      swap[1] = __builtin_bswap32 (salt_ptr[1]);
      swap[2] = __builtin_bswap32 (salt_ptr[2]);
      swap[3] = __builtin_bswap32 (salt_ptr[3]);
      swap[4] = __builtin_bswap32 (salt_ptr[4]);

      fprintf (fp, "%s%08x%08x%08x%08x%08x*%08x%08x%08x%08x%08x",
        MYSQL_AUTH_MAGIC,
        swap[0],
        swap[1],
        swap[2],
        swap[3],
        swap[4],
        digest->buf.sha1[0],
        digest->buf.sha1[1],
        digest->buf.sha1[2],
        digest->buf.sha1[3],
        digest->buf.sha1[4]);

      break;
    }
    case HASH_TYPE_SIP_AUTH:
    {
      sip_t *sip = salt->sip;

      swap[0] = __builtin_bswap32 (digest->buf.md5[0]);
      swap[1] = __builtin_bswap32 (digest->buf.md5[1]);
      swap[2] = __builtin_bswap32 (digest->buf.md5[2]);
      swap[3] = __builtin_bswap32 (digest->buf.md5[3]);

      fprintf (fp, "%s%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%s*%08x%08x%08x%08x",
        SIP_AUTH_MAGIC,
        sip->URI_server,
        sip->URI_client,
        sip->user,
        sip->realm,
        sip->method,
        sip->URI_prefix,
        sip->URI_resource,
        sip->URI_suffix,
        sip->nonce,
        sip->nonce_client,
        sip->nonce_count,
        sip->qop,
        sip->directive,
        swap[0],
        swap[1],
        swap[2],
        swap[3]);

      break;
    }

    case HASH_TYPE_PLAIN:
      fprintf (fp, "%s", digest->buf.plain);
      break;
  }

  if (status_info.engine_parameter->salt_type == SALT_TYPE_INCLUDED ||
     (status_info.engine_parameter->salt_type == SALT_TYPE_EXTERNAL && salt->salt_plain_len > 0))
  {
    fputc (status_info.engine_parameter->separator, fp);

    uint32_t i;
    uint64_t len;

    len = salt->salt_plain_len;

    if (status_info.engine_parameter->hash_mode == 23)
    {
      len -= 8;
    }

    for (i = 0; i < len; i++)
    {
      if (status_info.engine_parameter->hex_salt == 1)
      {
        fprintf (fp, "%02x", (unsigned char) salt->salt_plain_buf[i]);
      }
      else
      {
        fputc (salt->salt_plain_buf[i], fp);
      }
    }
  }
}

void save_hash ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  db_t *db = status_info.db;

  char *input_file = engine_parameter->file_hashes;

  char new_input_file[256];
  char old_input_file[256];

  snprintf (new_input_file, 256, "%s.new", input_file);
  snprintf (old_input_file, 256, "%s.old", input_file);

  FILE *fp = fopen (new_input_file, "wb");

  if (fp == NULL)
  {
    log_error ("ERROR: %s: %s\n", new_input_file, strerror (errno));

    exit (-1);
  }

  uint64_t salts_pos;
  uint64_t salts_cnt = (engine_parameter->salt_type == SALT_TYPE_EXTERNAL) ? 1 : db->salts_cnt;

  for (salts_pos = 0; salts_pos < salts_cnt; salts_pos++)
  {
    salt_t *salt_buf = db->salts_buf[salts_pos];

    if (salt_buf == NULL) continue;

    uint64_t indexes_pos;
    uint64_t indexes_cnt = ((engine_parameter->salt_type == SALT_TYPE_INCLUDED) || (engine_parameter->salt_type == SALT_TYPE_EMBEDDED)) ? 1 : INDEX_SIZE[INDEX_BITS];

    for (indexes_pos = 0; indexes_pos < indexes_cnt; indexes_pos++)
    {
      index_t *index_buf = salt_buf->indexes_buf[indexes_pos];

      if (index_buf == NULL) continue;

      uint64_t digests_pos;
      uint64_t digests_cnt = index_buf->digests_cnt;

      for (digests_pos = 0; digests_pos < digests_cnt; digests_pos++)
      {
        digest_t *digest_buf = index_buf->digests_buf[digests_pos];

        if (digest_buf == NULL) continue;

        if (digest_buf->found == 1) continue;

        // first output the username

        if (engine_parameter->username)
        {
          user_t *user = digest_buf->user;

          if (user)
          {
            uint i;

            for (i = 0; i < user->user_len; i++) fputc (user->user_name[i], fp);

            fputc (engine_parameter->separator, fp);
          }
        }

        // digest

        digest_t digest_tmp;

        salt_t salt_tmp;

        memcpy (&digest_tmp, digest_buf, sizeof (digest_t));

        memcpy (&salt_tmp, salt_buf, sizeof (salt_t));

        // don't output the salts when external salt (-e) option is used
        if (engine_parameter->salt_type == SALT_TYPE_EXTERNAL) salt_tmp.salt_plain_len = 0;

        write_digest (fp, &digest_tmp, &salt_tmp);

        fputc ('\n', fp);
      }
    }
  }

  fclose (fp);

  unlink (old_input_file);

  if (rename (input_file, old_input_file) != 0)
  {
    log_error ("ERROR: rename file '%s' to '%s': %s\n", input_file, old_input_file, strerror (errno));

    exit (-1);
  }

  unlink (input_file);

  if (rename (new_input_file, input_file) != 0)
  {
    log_error ("ERROR: rename file '%s' to '%s': %s\n", new_input_file, input_file, strerror (errno));

    exit (-1);
  }

  unlink (old_input_file);
}

#if defined OSX  || defined FREEBSD

static struct termios savemodes;
static int havemodes = 0;

int tty_break ()
{
  struct termios modmodes;

  if (ioctl (fileno (stdin), TIOCGETA, &savemodes) < 0) return -1;

  havemodes = 1;

  modmodes = savemodes;
  modmodes.c_lflag &= ~ICANON;
  modmodes.c_cc[VMIN] = 1;
  modmodes.c_cc[VTIME] = 0;

  return ioctl (fileno (stdin), TIOCSETAW, &modmodes);
}

int tty_getchar ()
{
  fd_set rfds;

  FD_ZERO (&rfds);

  FD_SET (fileno (stdin), &rfds);

  struct timeval tv;

  tv.tv_sec  = 1;
  tv.tv_usec = 0;

  int retval = select (1, &rfds, NULL, NULL, &tv);

  if (retval ==  0) return  0;
  if (retval == -1) return -1;

  return getchar ();
}

int tty_fix ()
{
  if (!havemodes) return 0;

  return ioctl (fileno (stdin), TIOCSETAW, &savemodes);
}
#endif

#if defined LINUX
static struct termio savemodes;
static int havemodes = 0;

int tty_break ()
{
  struct termio modmodes;

  if (ioctl (fileno (stdin), TCGETA, &savemodes) < 0) return -1;

  havemodes = 1;

  modmodes = savemodes;
  modmodes.c_lflag &= ~ICANON;
  modmodes.c_cc[VMIN] = 1;
  modmodes.c_cc[VTIME] = 0;

  return ioctl (fileno (stdin), TCSETAW, &modmodes);
}

int tty_getchar ()
{
  fd_set rfds;

  FD_ZERO (&rfds);

  FD_SET (fileno (stdin), &rfds);

  struct timeval tv;

  tv.tv_sec  = 1;
  tv.tv_usec = 0;

  int retval = select (1, &rfds, NULL, NULL, &tv);

  if (retval ==  0) return  0;
  if (retval == -1) return -1;

  return getchar ();
}

int tty_fix ()
{
  if (!havemodes) return 0;

  return ioctl (fileno (stdin), TCSETAW, &savemodes);
}
#endif

#ifdef WINDOWS
static DWORD saveMode = 0;

int tty_break_win ()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  GetConsoleMode (stdinHandle, &saveMode);
  SetConsoleMode (stdinHandle, ENABLE_PROCESSED_INPUT);

  return 0;
}

int tty_getchar_win ()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  DWORD rc = WaitForSingleObject (stdinHandle, 1000);

  if (rc == WAIT_TIMEOUT)   return  0;
  if (rc == WAIT_ABANDONED) return -1;
  if (rc == WAIT_FAILED)    return -1;

  // The whole ReadConsoleInput () part is a workaround.
  // For some unknown reason, maybe a mingw bug, a random signal
  // is sent to stdin which unblocks WaitForSingleObject () and sets rc 0.
  // Then it wants to read with getche () a keyboard input
  // which has never been made.

  INPUT_RECORD buf[100];

  DWORD num = 0;

  ReadConsoleInput (stdinHandle, buf, 100, &num);

  FlushConsoleInputBuffer (stdinHandle);

  uint i;

  for (i = 0; i < num; i++)
  {
    if (buf[i].EventType != KEY_EVENT) continue;

    KEY_EVENT_RECORD KeyEvent = buf[i].Event.KeyEvent;

    if (KeyEvent.bKeyDown != TRUE) continue;

    return KeyEvent.uChar.AsciiChar;
  }

  return 0;
}

int tty_fix_win ()
{
  HANDLE stdinHandle = GetStdHandle (STD_INPUT_HANDLE);

  SetConsoleMode (stdinHandle, saveMode);

  return 0;
}

/*
 * Cygwin
 */

int is_running_in_cygwin ()
{
  int ret = 0;

  char *home = getenv ("HOME");

  if (home)
  {
    char *original_path = getenv ("ORIGINAL_PATH");

    if (original_path)
    {
      char *ps1 = getenv ("PS1");

      if (ps1)
      {
        ret = 1;
      }
    }
  }

  return ret;
}

/*
// the code below is indeed working under cygwin, but it needs to configure the terminal with system/exec/popen
// it seems that there is no better way to do it currently, so cygwin support is disabled

char saved_stty_cygwin[200];

uint exec_stty_cmd_cygwin (char *cmd, char *output, int max_output_len)
{
  FILE *fp;

  fp = popen (cmd, "r");

  if (fp == NULL)
  {
    return 0;
  }

  if (fgets (output, max_output_len - 1, fp) != NULL)
  {
    fclose (fp);

    int output_len = strlen (output);

    if (output_len < 1)
    {
      return 0;
    }

    output[output_len - 1] = 0;

    return 1;
  }

  return 0;
}

uint get_stty_path_cygwin (char *path, int max_path_len)
{
  // "which" command

  uint max_cmd_len = 150;

  char cmd[max_cmd_len];

  snprintf (cmd, max_cmd_len, "which stty.exe");

  // get the resulting path

  if (! exec_stty_cmd_cygwin (cmd, path, max_path_len))
  {
    return 0;
  }

  // we need to use cygpath to get the dos compatible path (which we can use with system ())

  snprintf (cmd, max_cmd_len, "cygpath -d %s", path);

  if (! exec_stty_cmd_cygwin (cmd, path, max_path_len))
  {
    return 0;
  }

  return 1;
}

uint stty_get_cygwin (char *saved_stty, uint max_len)
{
  memset (saved_stty, 0, max_len);

  int max_path_len = 120;

  char stty_path[max_path_len];

  if (! get_stty_path_cygwin (stty_path, max_path_len))
  {
    return 0;
  }

  int max_cmd_len = 150;

  char cmd[max_cmd_len];

  snprintf (cmd, max_cmd_len, "%s -g", stty_path);

  if (! exec_stty_cmd_cygwin (cmd, saved_stty_cygwin, max_path_len))
  {
    return 0;
  }

  return 1;
}

void stty_cmd_cygwin (char *mode)
{
  int max_path_len = 120;

  char stty_path[max_path_len];

  if (get_stty_path_cygwin (stty_path, max_path_len))
  {
    int max_cmd_len = 150;

    char cmd[max_cmd_len];

    snprintf (cmd, max_cmd_len, "%s %s", stty_path, mode);

    system (cmd);
  }
}

int tty_break_cygwin ()
{
  if (stty_get_cygwin (saved_stty_cygwin, sizeof (saved_stty_cygwin)))
  {
    stty_cmd_cygwin ("raw");
  }

  return 0;
}

int tty_getchar_cygwin ()
{
  char c;

  c = getchar ();

  return c;
}

int tty_fix_cygwin ()
{
  if (saved_stty_cygwin != NULL)
  {
    if (saved_stty_cygwin[0] != 0)
    {
      stty_cmd_cygwin (saved_stty_cygwin);
    }
  }

  return 0;
}
*/

/*
 * Wrappers
 */

int tty_break ()
{
  if (is_running_in_cygwin ())
  {
    log_error ("using hashcat with the cygwin terminal is not supported");

    exit (-1);

    //return tty_break_cygwin ();
  }
  else
  {
    return tty_break_win ();
  }
}

int tty_getchar ()
{
  if (is_running_in_cygwin ())
  {
    log_error ("using hashcat with the cygwin terminal is not supported");

    exit (-1);

    //return tty_getchar_cygwin ();
  }
  else
  {
    return tty_getchar_win ();
  }
}

int tty_fix ()
{
  if (is_running_in_cygwin ())
  {
    log_error ("using hashcat with the cygwin terminal is not supported");

    exit (-1);

    //return tty_fix_cygwin ();
  }
  else
  {
    return tty_fix_win ();
  }
}
#endif

void SuspendThreads ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  if (engine_parameter->hashcat_status == STATUS_RUNNING)
  {
    gettimeofday (&engine_parameter->timer_paused, NULL);

    engine_parameter->hashcat_status = STATUS_PAUSED;

    if (engine_parameter->quiet == 0) log_info ("\nPaused");
  }
}

void ResumeThreads ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  if (engine_parameter->hashcat_status == STATUS_PAUSED)
  {
    struct timeval now;

    gettimeofday (&now, NULL);

    #ifdef WINDOWS
    __time64_t  sec_paused =  now.tv_sec - engine_parameter->timer_paused.tv_sec;
    __time64_t usec_paused = now.tv_usec - engine_parameter->timer_paused.tv_usec;
    #else
    time_t  sec_paused =  now.tv_sec - engine_parameter->timer_paused.tv_sec;
    time_t usec_paused = now.tv_usec - engine_parameter->timer_paused.tv_usec;
    #endif

    float ms_paused = sec_paused * 1000 + usec_paused / 1000;

    engine_parameter->ms_paused += ms_paused;

    engine_parameter->hashcat_status = STATUS_RUNNING;

    if (engine_parameter->quiet == 0) log_info ("\nResumed");
  }
}

void *keypress ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  uint32_t benchmark = engine_parameter->benchmark;

  uint check_keypress = 1;

  while ((hashcat_running == 1) && (check_keypress == 1))
  {
    tty_break ();

    int ch = tty_getchar ();

    tty_fix ();

    if (ch == -1) break;

    if (ch ==  0) continue;

    if (ch != '\n') log_info ("");

    switch (ch)
    {
      case 's':
      case '\n':
      {
        status_display ();

        if (engine_parameter->quiet== 0) show_prompt ();

        break;
      }
      case 'b':
      {
        if (engine_parameter->hashcat_status != STATUS_RUNNING) continue;

        engine_parameter->hashcat_status = STATUS_BYPASS;

        if (engine_parameter->quiet == 0) log_info ("\nBypassed");

        break;
      }
      case 'q':
      {
        if (engine_parameter->hashcat_status != STATUS_RUNNING) continue;

        if (benchmark == 0) myquit ();
        if (benchmark == 1) myabort ();

        check_keypress = 0;

        break;
      }
      case 'p':
      {
        if (engine_parameter->hashcat_status != STATUS_RUNNING) continue;

        if (benchmark == 1) continue; // ignore

        SuspendThreads ();

        if (engine_parameter->quiet== 0) show_prompt ();

        break;
      }
      case 'r':
      {
        if (engine_parameter->hashcat_status != STATUS_PAUSED) continue;

        if (benchmark == 1) continue; // ignore

        ResumeThreads ();

        if (engine_parameter->quiet== 0) show_prompt ();

        break;
      }
    }
  }

  tty_fix ();

  return (NULL);
}

void *removehash ()
{
  //status_info.proc_saved = status_info.proc_recovered;

  while (hashcat_running == 1)
  {
    hc_sleep (1);

    if (status_info.proc_saved == status_info.proc_recovered) continue;

    status_info.proc_saved = status_info.proc_recovered;

    save_hash ();
  }

  return (NULL);
}

void *check_runtime ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  int runtime_left = engine_parameter->runtime;

  uint32_t benchmark = engine_parameter->benchmark;
  uint32_t quiet     = engine_parameter->quiet;

  while (hashcat_running == 1)
  {
    hc_sleep (1);

    runtime_left--;

    if (engine_parameter->hashcat_status == STATUS_QUIT) continue;

    if (runtime_left <= 0)
    {
      if (benchmark == 0)
      {
        if (quiet == 0)
        {
          log_info ("\nNOTE: Runtime limit reached, aborting...\n");

          status_display ();
        }
      }
      else
      {
        status_benchmark ();
      }

      myquit ();
    }
  }

  return (NULL);
}

void *periodic_status_display ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  uint32_t status_timer = engine_parameter->status_timer;

  uint32_t time_left = status_timer;

  while (hashcat_running == 1)
  {
    hc_sleep (1);

    time_left--;

    if (time_left == 0)
    {
      if (engine_parameter->quiet== 0) log_info ("");

      status_display ();

      if (engine_parameter->quiet== 0) show_prompt ();

      // reset timer

      time_left = status_timer;
    }
  }

  return (NULL);
}

void store_debug (char *debug_buf, int debug_len)
{
  FILE *fp = stderr;

  if (status_info.engine_parameter->file_debug)
  {
    fp = fopen (status_info.engine_parameter->file_debug, "ab");

    if (fp == NULL)
    {
      fp = stderr;

      log_error ("%s: %s", status_info.engine_parameter->file_debug, strerror (errno));
    }
  }

  int i;

  for (i = 0; i < debug_len; i++) fputc (debug_buf[i], fp);

  fputc ('\n', fp);

  if (status_info.engine_parameter->file_debug)
  {
    fclose (fp);
  }
}

void store_out (plain_t *plain, digest_t *digest, salt_t *salt)
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  uint output_format = engine_parameter->output_format;
  char separator = engine_parameter->separator;

  status_info.proc_recovered++;

  FILE *fp = stdout;
  FILE *pot = NULL;

  if (engine_parameter->file_output)
  {
    fp = fopen (engine_parameter->file_output, "ab");

    if (fp == NULL)
    {
      fp = stdout;

      log_error ("%s: %s", engine_parameter->file_output, strerror (errno));
    }
  }

  if (engine_parameter->file_pot)
  {
    pot = fopen (engine_parameter->file_pot, "ab");

    if (pot == NULL)
    {
      log_error ("%s: %s", engine_parameter->file_pot, strerror (errno));
    }
  }

  char *ptr = NULL;

  if (engine_parameter->hash_type == HASH_TYPE_SHA512
   || engine_parameter->hash_type == HASH_TYPE_SHA512UNIX
   || engine_parameter->hash_type == HASH_TYPE_MSSQL2012
   || engine_parameter->hash_type == HASH_TYPE_KECCAK
   || engine_parameter->hash_type == HASH_TYPE_SHA512AIX
   || engine_parameter->hash_type == HASH_TYPE_PBKDF2OSX
   || engine_parameter->hash_type == HASH_TYPE_PBKDF2GRUB
   || engine_parameter->hash_type == HASH_TYPE_DRUPAL7)
  {
    ptr = (char *) &plain->buf64;
  }
  else
  {
    ptr = (char *) &plain->buf;
  }

  digest_t digest_tmp;

  salt_t salt_tmp;

  memcpy (&digest_tmp, digest, sizeof (digest_t));

  memcpy (&salt_tmp, salt, sizeof (salt_t));

  if (pot)
  {
    write_digest (pot, &digest_tmp, &salt_tmp);

    fputc (separator, pot);
  }

  if (engine_parameter->quiet == 0)
  {
    if (engine_parameter->file_output == NULL)
    {
      clear_prompt ();
    }
  }

  if (output_format % 2)
  {
    write_digest (fp, &digest_tmp, &salt_tmp);
  }

  uint plain_len = plain->len;

  // hack: for -m 123 = EPi, we need to reduce the plain_len by one, +1 was used for optimization

  if (engine_parameter->hash_type == HASH_TYPE_EPIV4)
  {
    plain_len--; // no worries, it is guaranteed to be at least 1 -> 0 at most
  }

  format_output (fp, engine_parameter, NULL, ptr, plain_len, plain->pos);

  if (engine_parameter->quiet == 0)
  {
    if (engine_parameter->file_output == NULL)
    {
      show_prompt_no_nl ();
    }
  }

  if (fp != stdout) fclose (fp);

  if (pot)
  {
    format_plain (pot, ptr, plain_len, 1);

    fputc ('\n', pot);

    fclose (pot);
  }

  if (engine_parameter->debug_mode != DEBUG_MODE) store_debug (plain->debug_buf, plain->debug_len);
}

void catch_int ()
{
  engine_parameter_t *engine_parameter = status_info.engine_parameter;

  if ((engine_parameter->quiet == 0) && (engine_parameter->benchmark == 0))
  {
    log_info ("");

    show_restore_options ();
  }

  exit (0);
}

void usage_mini_print (const char *progname)
{
  uint32_t i;

  for (i = 0; USAGE_MINI[i] != NULL; i++) log_info (USAGE_MINI[i], progname);
}

void usage_big_print (const char *progname)
{
  uint32_t i;

  for (i = 0; USAGE_BIG[i] != NULL; i++) log_info (USAGE_BIG[i], progname);
}

uint32_t get_num_cores ()
{
  long nprocs = 0;

  #ifdef _WIN32
    #ifndef _SC_NPROCESSORS_ONLN

      SYSTEM_INFO info;
      GetSystemInfo (&info);

      #define sysconf(a) info.dwNumberOfProcessors
      #define _SC_NPROCESSORS_ONLN

    #endif
  #endif

  #ifndef OSX
    #ifdef _SC_NPROCESSORS_ONLN

    nprocs = sysconf (_SC_NPROCESSORS_ONLN);

    if (nprocs < 1)
    {
      log_warning ("Unable to determine number of online CPUs"),

      nprocs = 0;
    }

    #endif

  #else

  int num_procs;

  size_t proc_len = sizeof (int);

  sysctlbyname ("hw.logicalcpu", &num_procs, &proc_len, NULL, 0);

  nprocs = (long) num_procs;

  #endif

  return (uint32_t) nprocs;
}

int fgetl (FILE *fp, char *line_buf)
{
  if (fgets (line_buf, BUFSIZ, fp) == NULL) return (-1);

  int line_len = strlen (line_buf);

  if (line_buf[line_len - 1] == '\n')
  {
    line_len--;

    line_buf[line_len] = '\0';
  }

  if (line_buf[line_len - 1] == '\r')
  {
    line_len--;

    line_buf[line_len] = '\0';
  }

  return (line_len);
}

int get_cpu_model (char **name)
{
  #ifdef OSX

  size_t buflen = BUFSIZ;

  *name = mycalloc (BUFSIZ, 1);

  sysctlbyname ("machdep.cpu.brand_string", *name, &buflen, NULL, 0);

  if (buflen < 1)
  {
    return 1;
  }

  return 0;

  #endif

  #if defined LINUX || defined FREEBSD

  FILE *fp = fopen ("/proc/cpuinfo", "rb");

  if (fp == NULL)
  {
    return 1;
  }

  char line_buf[BUFSIZ];
  int line_len = 0;

  char *query = "model name";
  int query_len = strlen (query);

  while ((line_len = fgetl (fp, line_buf)) != -1)
  {
    if (line_len > query_len)
    {
      if (memcmp (line_buf, query, query_len) == 0)
      {
        char *line_ptr = (char *) line_buf;
        line_ptr += query_len;
        int max_skip = BUFSIZ - query_len;

        while (max_skip--)
        {
          char c = line_ptr[0];

          if ((c != ':') && (c != ' ') && (c != '\t'))
          {
            break;
          }

          line_ptr++;
        }

        int name_len = strlen (line_ptr);

        if (name_len > 0)
        {
          *name = mycalloc (BUFSIZ, 1);
          memcpy (*name, line_ptr, name_len);

          fclose (fp);

          return 0;
        }
      }
    }
  }

  fclose (fp);

  #endif

  #ifdef WINDOWS

  char *szPath = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";

  HKEY hKey = NULL;

  // first open the key

  if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, szPath, 0, KEY_READ, &hKey) != 0)
  {
    return 1;
  }

  // query the value

  *name = mycalloc (BUFSIZ, 1);

  DWORD dwSize = BUFSIZ;

  if (RegQueryValueEx (hKey, "ProcessorNameString", 0, NULL, (unsigned char*) *name, &dwSize) != 0)
  {
    return 1;
  }

  // cleanup

  RegCloseKey (hKey);

  return 0;

  #endif

  return 1;
}

/*
int compare_salt (const void *p1, const void *p2)
{
  const salt_t *s1 = (const salt_t *) p1;
  const salt_t *s2 = (const salt_t *) p2;

  return strcmp (s1->salt_plain_buf, s2->salt_plain_buf);
}
*/

int compare_salt (const void *p1, const void *p2)
{
  const salt_t *s1 = (const salt_t *) p1;
  const salt_t *s2 = (const salt_t *) p2;

  if (s1->salt_plain_len != s2->salt_plain_len) return (s1->salt_plain_len - s2->salt_plain_len);

  return memcmp (s1->salt_plain_buf, s2->salt_plain_buf, s1->salt_plain_len);
}

int compare_salt_pre (const void *p1, const void *p2)
{
  const salt_t *s1 = (const salt_t *) p1;
  const salt_t *s2 = (const salt_t *) p2;

  if (s1->salt_prehashed_len != s2->salt_prehashed_len) return (s1->salt_prehashed_len - s2->salt_prehashed_len);

  return memcmp (s1->salt_prehashed_buf, s2->salt_prehashed_buf, s1->salt_prehashed_len);
}

int compare_string (const void *p1, const void *p2)
{
  const char *s1 = (const char *) p1;
  const char *s2 = (const char *) p2;

  return strcmp (s1, s2);
}

int compare_stringptr (const void *p1, const void *p2)
{
  const char **s1 = (const char **) p1;
  const char **s2 = (const char **) p2;

  return strcmp (*s1, *s2);
}

int compare_salt_ikepsk (const void *p1, const void *p2)
{
  const salt_t *s1 = (const salt_t *) p1;
  const salt_t *s2 = (const salt_t *) p2;

  return memcmp (s1->ikepsk, s2->ikepsk, sizeof (ikepsk_t));
}

int compare_salt_netntlm (const void *p1, const void *p2)
{
  const salt_t *s1 = (const salt_t *) p1;
  const salt_t *s2 = (const salt_t *) p2;

  return memcmp (s1->netntlm, s2->netntlm, sizeof (netntlm_t));
}

char **scan_directory (const char *path)
{
  char *tmp_path = mystrdup (path);

  size_t tmp_path_len = strlen (tmp_path);

  while (tmp_path[tmp_path_len - 1] == '/' || tmp_path[tmp_path_len - 1] == '\\')
  {
    tmp_path[tmp_path_len - 1] = '\0';

    tmp_path_len = strlen (tmp_path);
  }

  char **files = NULL;

  int num_files = 0;

  DIR *d;

  if ((d = opendir (tmp_path)) != NULL)
  {
    struct dirent *de;

    while ((de = readdir (d)) != NULL)
    {
      if ((strcmp (de->d_name, ".") == 0) || (strcmp (de->d_name, "..") == 0)) continue;

      int path_file_len = strlen (tmp_path) + 1 + strlen (de->d_name) + 1;

      char *path_file = malloc ( path_file_len );

      snprintf (path_file, path_file_len , "%s/%s", tmp_path, de->d_name);

      DIR *d_test;

      if ((d_test = opendir (path_file)) != NULL)
      {
        closedir (d_test);

        myfree (path_file);
      }
      else
      {
        files = myrealloc (files, (num_files + 1) * sizeof (char *));

        files[num_files] = path_file;

        num_files++;
      }
    }

    closedir (d);

    qsort (files, num_files, sizeof (char *), compare_stringptr);
  }
  else if (errno == ENOTDIR)
  {
    files = myrealloc (files, (num_files + 1) * sizeof (char *));

    files[num_files] = mystrdup (path);

    num_files++;
  }
  else
  {
    log_error ("%s: %s", path, strerror (errno));

    exit (-1);
  }

  files = myrealloc (files, (num_files + 1) * sizeof (char *));

  files[num_files] = NULL;

  myfree (tmp_path);

  return (files);
}

void incr_rules_buf (rules_t *rules)
{
  if (rules->rules_cnt == rules->rules_avail)
  {
    rules->rules_avail += INCR_RULES_PTR;

    rules->rules_buf = myrealloc (rules->rules_buf, rules->rules_avail * sizeof (char *));

    rules->rules_len = myrealloc (rules->rules_len, rules->rules_avail * sizeof (uint32_t));
  }
}

void incr_words_buf (words_t *words)
{
  if (words->words_cnt == words->words_avail)
  {
    words->words_avail += INCR_WORDS_PTR;

    words->words_buf = myrealloc (words->words_buf, words->words_avail * sizeof (char *));

    words->words_len = myrealloc (words->words_len, words->words_avail * sizeof (uint32_t));
  }
}

void incr_salt_ptrs (db_t *db)
{
  if (db->salts_cnt == db->salts_avail)
  {
    db->salts_avail += INCR_SALT_PTR;

    db->salts_buf = myrealloc (db->salts_buf, db->salts_avail * sizeof (salt_t *));
  }
}

void incr_digest_ptrs (index_t *index)
{
  if (index->digests_cnt == index->digests_avail)
  {
    index->digests_avail += INCR_DIGEST_PTR;

    index->digests_buf = myrealloc (index->digests_buf, index->digests_avail * sizeof (digest_t *));
  }
}

words_t *init_new_words (void)
{
  words_t *words = mymalloc (sizeof (words_t));

  memset (words, 0, sizeof (words_t));

  return words;
}

rules_t *init_new_rules (void)
{
  rules_t *rules = mymalloc (sizeof (rules_t));

  memset (rules, 0, sizeof (rules_t));

  return rules;
}

digest_t *init_new_digest (void)
{
  digest_t *digest = mymalloc (sizeof (digest_t));

  memset (digest, 0, sizeof (digest_t));

  return digest;
}

index_t *init_new_index (void)
{
  index_t *index = mymalloc (sizeof (index_t));

  memset (index, 0, sizeof (index_t));

  return index;
}

salt_t *init_new_salt (void)
{
  salt_t *salt = mymalloc (sizeof (salt_t));

  memset (salt, 0, sizeof (salt_t));

  return salt;
}

db_t *init_new_db (void)
{
  db_t *db = mymalloc (sizeof (db_t));

  memset (db, 0, sizeof (db_t));

  return db;
}

engine_parameter_t *init_new_engine_parameter (void)
{
  engine_parameter_t *engine_parameter = mymalloc (sizeof (engine_parameter_t));

  memset (engine_parameter, 0, sizeof (engine_parameter_t));

  return engine_parameter;
}

#define SPACE 256

uint32_t getCharsetFromWord (char *word_buf, uint32_t word_len, char *cs_buf)
{
  char done[SPACE + 1];

  memset (done, 0, SPACE + 1);

  uint32_t i;

  for (i = 0; i < word_len; i++)
  {
    int c = word_buf[i];

    done[c]++;
  }

  uint32_t cs_len = 0;

  for (i = 0; i < SPACE; i++)
  {
    if (done[i] == 0) continue;

    int j;

    for (j = 0; j < done[i]; j++)
    {
      cs_buf[cs_len] = i;

      cs_len++;
    }
  }

  return (cs_len);
}

uint32_t convert_from_hex (char *plain_buf, uint32_t plain_len)
{
  uint32_t new_len = 0;

  if ((plain_len % 2) == 0)
  {
    uint32_t i;
    uint32_t j;

    new_len = plain_len / 2;

    for (i = 0, j = 0; i < new_len; i += 1, j += 2)
    {
      char p0 = plain_buf[j + 0];
      char p1 = plain_buf[j + 1];

      plain_buf[i]  = hex_convert (p1) << 0;
      plain_buf[i] |= hex_convert (p0) << 4;
    }

    plain_len = new_len;
  }
  else
  {
    log_error ("ERROR: invalid hex len\n");

    exit (-1);
  }

  return new_len;
}

int cnt = 0;

void *root_cs = NULL;

void add_word (char *word_pos, uint32_t word_len, words_t *words, engine_parameter_t *engine_parameter)
{
  if (word_len > 0) if (word_pos[word_len - 1] == '\r') word_len--;

  // this conversion must be done before the length check

  if (word_len > 6)
  {
    if (strncmp (word_pos, "$HEX[", 5) == 0)
    {
      if (word_pos[word_len - 1] == ']')
      {
        word_pos += 5;
        word_len  = convert_from_hex (word_pos, word_len - 6);
      }
    }
  }

  if (word_len > engine_parameter->plain_size_max) return;

  if (engine_parameter->attack_mode == 4)
  {
    if (word_len < engine_parameter->perm_min || word_len > engine_parameter->perm_max) return;

    char cs_buf[SPACE];

    uint32_t cs_len = getCharsetFromWord (word_pos, word_len, cs_buf);

    cs_buf[cs_len] = 0;

    if (__hc_tfind (cs_buf, &root_cs, compare_string) != NULL) return;

    char *next = mystrdup (cs_buf);

    __hc_tsearch (next, &root_cs, compare_string);
  }
  else if (engine_parameter->attack_mode == 5)
  {
    if (word_len < engine_parameter->table_min || word_len > engine_parameter->table_max) return;
  }

  incr_words_buf (words);

  words->words_buf[words->words_cnt] = word_pos;
  words->words_len[words->words_cnt] = word_len;

  words->words_cnt++;

  return;

  /* disabled, confuses users */

  /* add trimmed variant */

  if (word_pos[word_len - 1] == ' ' || word_pos[word_len - 1] == '\t')
  {
    if (word_len == 1) return;

    word_len--;

    while (word_pos[word_len - 1] == ' ' || word_pos[word_len - 1] == '\t')
    {
      if (word_len == 1) return;

      word_len--;
    }

    add_word (word_pos, word_len, words, engine_parameter);
  }

  if (word_pos[0] == ' ' || word_pos[0] == '\t')
  {
    if (word_len == 1) return;

    word_pos++;
    word_len--;

    while (word_pos[0] == ' ' || word_pos[0] == '\t')
    {
      if (word_len == 1) return;

      word_pos++;
      word_len--;
    }

    add_word (word_pos, word_len, words, engine_parameter);
  }
}

static int out_push (words_t *words, const char *pw_buf, const int pw_len)
{
  char *word_pos = words->cache_buf + words->cache_cnt;
  int   word_len = pw_len;

  memcpy (word_pos, pw_buf, pw_len);

  words->cache_cnt += pw_len;

  incr_words_buf (words);

  words->words_buf[words->words_cnt] = word_pos;
  words->words_len[words->words_cnt] = word_len;

  words->words_cnt++;

  if (words->cache_cnt >= words->cache_avail - 1000)
  {
    return 1;
  }

  return 0;
}

int add_rule (char *rule_buf, uint32_t rule_len, rules_t *rules)
{
  if (__hc_tfind (rule_buf, &rules->root_rule, compare_string) != NULL) return (-3);

  char in[BLOCK_SIZE];
  char out[BLOCK_SIZE];

  memset (in,  0, BLOCK_SIZE);
  memset (out, 0, BLOCK_SIZE);

  int result = apply_rule (rule_buf, rule_len, in, 1, out);

  if (result == -1) return (-1);

  char *next_rule = mystrdup (rule_buf);

  __hc_tsearch (next_rule, &rules->root_rule, compare_string);

  incr_rules_buf (rules);

  rules->rules_buf[rules->rules_cnt] = next_rule;

  rules->rules_len[rules->rules_cnt] = rule_len;

  rules->rules_cnt++;

  return (0);
}

inline static void add_user (engine_parameter_t *engine_parameter, digest_t *digest, char *start, char *end)
{
  if (engine_parameter->username)
  {
    if (engine_parameter->remove == 1)
    {
      user_t **user_ptr = &digest->user;

      user_t *user = (user_t *) mymalloc (sizeof (user_t));

      *user_ptr = user;

      uint user_len = end - start - 1;

      user->user_len = user_len;

      if (user_len < 1)
      {
        user->user_name = mystrdup ("");
      }
      else
      {
        user->user_name = mycalloc (user_len, 1); // sizeof (char) == 1

        memcpy (user->user_name, start, user_len);
      }
    }
  }
}

void *root_salts = NULL;

#define LINE_OK                   0
#define LINE_COMMENT             -1
#define LINE_GLOBAL_ZERO         -2
#define LINE_GLOBAL_LENGTH       -3
#define LINE_HASH_LENGTH         -4
#define LINE_SALT_LENGTH         -5
#define LINE_SEPARATOR_UNMATCHED -6
#define LINE_SIGNATURE_UNMATCHED -7
#define LINE_HASH_VALUE          -8
#define LINE_UNKNOWN_ERROR       -255

plain_t **plains_iteration = NULL;

#include "md5.h"

int parse_hash_line (char *line_buf, int line_len, int hash_type, int hash_mode, char **hash_buf, int *hash_len, int salt_type, char **salt_buf, int *salt_len, char separator, int hex_salt)
{
  if (line_len == 0) return (LINE_GLOBAL_ZERO);

  if (line_buf[0] == '#') return (LINE_COMMENT);

  if ((hash_type == HASH_TYPE_MD5) && (salt_type == SALT_TYPE_NONE))
  {
    int expected_line_len;

    // allow half MD5 here
    if (hash_mode == 5100) expected_line_len = HASH_SIZE_MD5 / 2;
    else                   expected_line_len = HASH_SIZE_MD5;

    if (line_len != expected_line_len) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_MD5;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_MD5) && (salt_type == SALT_TYPE_EXTERNAL))
  {
    int min_line_len = HASH_SIZE_MD5;
    int max_line_len = HASH_SIZE_MD5 + 1 + SALT_SIZE_MAX_MD5;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_MD5;

    if (line_len == min_line_len) return (LINE_OK);

    if (line_buf[HASH_SIZE_MD5] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = line_buf + HASH_SIZE_MD5 + 1;
    *salt_len = line_len - HASH_SIZE_MD5 - 1;

    if ((*salt_len < SALT_SIZE_MIN_MD5) || (*salt_len > SALT_SIZE_MAX_MD5)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_MD5) && (salt_type == SALT_TYPE_INCLUDED))
  {
    int min_line_len = HASH_SIZE_MD5 + 1 + SALT_SIZE_MIN_MD5;
    int max_line_len = HASH_SIZE_MD5 + 1 + SALT_SIZE_MAX_MD5;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (line_buf[HASH_SIZE_MD5] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_MD5;

    *salt_buf = line_buf + HASH_SIZE_MD5 + 1;
    *salt_len = line_len - HASH_SIZE_MD5 - 1;

    if (hex_salt == 1)
    {
      *salt_len = convert_from_hex (*salt_buf, *salt_len);
    }

    if (hash_mode == 2611)
    {
      if (*salt_len <  1) return (LINE_SALT_LENGTH);
      if (*salt_len > 23) return (LINE_SALT_LENGTH);
    }
    else if (hash_mode == 2711)
    {
      if (*salt_len < 24) return (LINE_SALT_LENGTH);
      if (*salt_len > 31) return (LINE_SALT_LENGTH);
    }

    if ((*salt_len < SALT_SIZE_MIN_MD5) || (*salt_len > SALT_SIZE_MAX_MD5)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA1) && (salt_type == SALT_TYPE_NONE))
  {
    int min_line_len = HASH_SIZE_SHA1;
    int max_line_len = HASH_SIZE_SHA1;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA1;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA1) && (salt_type == SALT_TYPE_EXTERNAL))
  {
    int min_line_len = HASH_SIZE_SHA1;
    int max_line_len = HASH_SIZE_SHA1 + 1 + SALT_SIZE_MAX_SHA1;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA1;

    if (line_len == min_line_len) return (LINE_OK);

    if (line_buf[HASH_SIZE_SHA1] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = line_buf + HASH_SIZE_SHA1 + 1;
    *salt_len = line_len - HASH_SIZE_SHA1 - 1;

    if ((*salt_len < SALT_SIZE_MIN_SHA1) || (*salt_len > SALT_SIZE_MAX_SHA1)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA1) && (salt_type == SALT_TYPE_INCLUDED))
  {
    int min_line_len = HASH_SIZE_SHA1 + 1 + SALT_SIZE_MIN_SHA1;
    int max_line_len = HASH_SIZE_SHA1 + 1 + SALT_SIZE_MAX_SHA1;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (line_buf[HASH_SIZE_SHA1] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA1;

    *salt_buf = line_buf + HASH_SIZE_SHA1 + 1;
    *salt_len = line_len - HASH_SIZE_SHA1 - 1;

    if (hex_salt == 1)
    {
      *salt_len = convert_from_hex (*salt_buf, *salt_len);
    }

    if ((*salt_len < SALT_SIZE_MIN_SHA1) || (*salt_len > SALT_SIZE_MAX_SHA1)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MYSQL)
  {
    int min_line_len = HASH_SIZE_MYSQL;
    int max_line_len = HASH_SIZE_MYSQL;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = line_len;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_PHPASS)
  {
    int min_line_len = PHPASS_SIGN + PHPASS_ITER + SALT_SIZE_MIN_PHPASS + HASH_SIZE_PHPASS;
    int max_line_len = PHPASS_SIGN + PHPASS_ITER + SALT_SIZE_MAX_PHPASS + HASH_SIZE_PHPASS;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if ((memcmp (line_buf, PHPASS_MAGIC_P, PHPASS_SIGN) != 0) &&
        (memcmp (line_buf, PHPASS_MAGIC_H, PHPASS_SIGN) != 0)) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + PHPASS_SIGN + PHPASS_ITER;
    *salt_len = line_len - PHPASS_SIGN - PHPASS_ITER - HASH_SIZE_PHPASS;

    if ((*salt_len < SALT_SIZE_MIN_PHPASS) || (*salt_len > SALT_SIZE_MAX_PHPASS)) return (LINE_SALT_LENGTH);

    *hash_buf = line_buf + PHPASS_SIGN + PHPASS_ITER + *salt_len;
    *hash_len = HASH_SIZE_PHPASS;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MD5UNIX)
  {
    int min_line_len = MD5UNIX_SIGN + SALT_SIZE_MIN_MD5UNIX + 1 + HASH_SIZE_MD5UNIX;
    int max_line_len = MD5UNIX_SIGN + SALT_SIZE_MAX_MD5UNIX + 1 + HASH_SIZE_MD5UNIX;

    if (memcmp (line_buf, MD5UNIX_MAGIC, MD5UNIX_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + MD5UNIX_SIGN;

    if (memcmp (*salt_buf, "rounds=", 7) == 0)
    {
      int rounds_len = 0;

      *salt_buf += 7;

      for (rounds_len = 0; *salt_buf[0] >= '0' && *salt_buf[0] <= '9' && rounds_len < 7; rounds_len++, *salt_buf += 1) continue;

      if (rounds_len   ==  0 ) return (LINE_SIGNATURE_UNMATCHED);
      if (*salt_buf[0] != '$') return (LINE_SIGNATURE_UNMATCHED);

      *salt_buf += 1;

      max_line_len = max_line_len + 7 + rounds_len + 1;
    }

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *salt_ptr = *salt_buf;

    for (*salt_len = 0; *salt_ptr != '$' && *salt_len < SALT_SIZE_MAX_MD5UNIX; *salt_len += 1, salt_ptr += 1) continue;

    if ((*salt_len < SALT_SIZE_MIN_MD5UNIX) || (*salt_len > SALT_SIZE_MAX_MD5UNIX)) return (LINE_SALT_LENGTH);

    *hash_buf = *salt_buf + *salt_len + 1;
    *hash_len = HASH_SIZE_MD5UNIX;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MD5SUN)
  {
    int min_line_len = MD5SUN_SIGN + SALT_SIZE_MIN_MD5SUN + 1 + HASH_SIZE_MD5SUN;
    int max_line_len = MD5SUN_SIGN + SALT_SIZE_MAX_MD5SUN + 1 + HASH_SIZE_MD5SUN;

    if (memcmp (line_buf, MD5SUN_MAGIC, MD5SUN_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    if (line_buf[MD5SUN_SIGN] != '$' &&
        line_buf[MD5SUN_SIGN] != ',') return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + MD5SUN_SIGN + 1;

    if (memcmp (*salt_buf, "rounds=", 7) != 0) return (LINE_SIGNATURE_UNMATCHED);

    int rounds_len = 0;

    *salt_buf += 7;

    for (rounds_len = 0; *salt_buf[0] >= '0' && *salt_buf[0] <= '9' && rounds_len < 7; rounds_len++, *salt_buf += 1) continue;

    if (rounds_len   ==  0 ) return (LINE_SIGNATURE_UNMATCHED);
    if (*salt_buf[0] != '$') return (LINE_SIGNATURE_UNMATCHED);

    max_line_len = max_line_len + 7 + rounds_len + 1;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = strrchr (line_buf, '$') + 1;
    *hash_len = HASH_SIZE_MD5SUN;

    *salt_buf = line_buf;
    *salt_len = *hash_buf - line_buf - 1;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_OSX1) && (salt_type == SALT_TYPE_EMBEDDED))
  {
    int min_line_len = HASH_SIZE_OSX1 + SALT_SIZE_MIN_OSX1;
    int max_line_len = HASH_SIZE_OSX1 + SALT_SIZE_MAX_OSX1;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *salt_buf = line_buf;
    *salt_len = 8;

    *hash_buf = *salt_len + line_buf;
    *hash_len = HASH_SIZE_OSX1;

    if ((*salt_len < SALT_SIZE_MIN_OSX1) || (*salt_len > SALT_SIZE_MAX_OSX1)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_OSX512) && (salt_type == SALT_TYPE_EMBEDDED))
  {
    int min_line_len = HASH_SIZE_OSX512 + SALT_SIZE_MIN_OSX512;
    int max_line_len = HASH_SIZE_OSX512 + SALT_SIZE_MAX_OSX512;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *salt_buf = line_buf;
    *salt_len = 8;

    *hash_buf = *salt_len + line_buf;
    *hash_len = HASH_SIZE_OSX512;

    if ((*salt_len < SALT_SIZE_MIN_OSX512) || (*salt_len > SALT_SIZE_MAX_OSX512)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA1B64)
  {
    int min_line_len = SHA1B64_SIGN + HASH_SIZE_SHA1B64;
    int max_line_len = SHA1B64_SIGN + HASH_SIZE_SHA1B64;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SHA1B64_MAGIC, SHA1B64_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *hash_buf = line_buf + SHA1B64_SIGN;
    *hash_len = line_len - SHA1B64_SIGN;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA1B64S)
  {
    int min_line_len = SHA1B64S_SIGN + HASH_SIZE_SHA1B64 + SALT_SIZE_MIN_SHA1B64S;
    int max_line_len = SHA1B64S_SIGN + HASH_SIZE_SHA1B64 + SALT_SIZE_MAX_SHA1B64S;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SHA1B64S_MAGIC, SHA1B64S_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *hash_buf = line_buf + SHA1B64S_SIGN;
    *hash_len = line_len - SHA1B64S_SIGN;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA256B64)
  {
    int min_line_len = HASH_SIZE_SHA256B64;
    int max_line_len = HASH_SIZE_SHA256B64;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA256B64;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MD4)
  {
    int min_line_len = HASH_SIZE_MD4;
    int max_line_len = HASH_SIZE_MD4;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_MD4;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_DCC)
  {
    int min_line_len = HASH_SIZE_MD4 + 1 + SALT_SIZE_MIN_DCC;
    int max_line_len = HASH_SIZE_MD4 + 1 + SALT_SIZE_MAX_DCC;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (line_buf[HASH_SIZE_MD4] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_MD4;

    *salt_buf = line_buf + HASH_SIZE_MD4 + 1;
    *salt_len = line_len - HASH_SIZE_MD4 - 1;

    if ((*salt_len < SALT_SIZE_MIN_DCC) || (*salt_len > SALT_SIZE_MAX_DCC)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MD5CHAP)
  {
    int min_line_len = HASH_SIZE_MD5CHAP + 1 + SALT_SIZE_MIN_MD5CHAP + 1 + MD5CHAP_IDBYTE;
    int max_line_len = HASH_SIZE_MD5CHAP + 1 + SALT_SIZE_MAX_MD5CHAP + 1 + MD5CHAP_IDBYTE;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (line_buf[HASH_SIZE_MD5CHAP] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = line_buf + HASH_SIZE_MD5CHAP + 1;
    *salt_len = line_len - HASH_SIZE_MD5CHAP - 1 - 1 - MD5CHAP_IDBYTE;

    if ((*salt_len < SALT_SIZE_MIN_MD5CHAP) || (*salt_len > SALT_SIZE_MAX_MD5CHAP)) return (LINE_SALT_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_MD5CHAP;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MSSQL2000)
  {
    int expected_line_len = MSSQL_SIGN + SALT_SIZE_MIN_MSSQL2000 + HASH_SIZE_MSSQL2000;

    if (line_len != expected_line_len) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, MSSQL_MAGIC, MSSQL_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + MSSQL_SIGN;
    *salt_len = 8;

    *hash_buf = line_buf + MSSQL_SIGN + *salt_len;
    *hash_len = HASH_SIZE_MSSQL2000;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MSSQL2005)
  {
    int expected_line_len = MSSQL_SIGN + SALT_SIZE_MIN_MSSQL2005 + HASH_SIZE_MSSQL2005;

    if (line_len != expected_line_len) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, MSSQL_MAGIC, MSSQL_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + MSSQL_SIGN;
    *salt_len = 8;

    *hash_buf = line_buf + MSSQL_SIGN + *salt_len;
    *hash_len = line_len - MSSQL_SIGN - *salt_len;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_EPIV6)
  {
    int line_len1 = EPISERVERV6_SIGN + SALT_SIZE_MIN_EPIV6 + 1 + HASH_SIZE_EPIV6_MIN;
    int line_len2 = EPISERVERV6_SIGN + SALT_SIZE_MAX_EPIV6 + 1 + HASH_SIZE_EPIV6_MAX;

    if ((line_len < line_len1) || (line_len > line_len2)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, EPISERVERV6_MAGIC, EPISERVERV6_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + EPISERVERV6_SIGN;

    char *hash_pos = strchr (salt_pos, '*');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    hash_pos++;

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos - 1;

    if (*salt_len < SALT_SIZE_MIN_EPIV6 || *salt_len > SALT_SIZE_MAX_EPIV6) return (LINE_SALT_LENGTH);

    *hash_buf = hash_pos;
    *hash_len = HASH_SIZE_EPIV6_MIN;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA256) && (salt_type == SALT_TYPE_NONE))
  {
    int min_line_len = HASH_SIZE_SHA256;
    int max_line_len = HASH_SIZE_SHA256;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA256;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA256) && (salt_type == SALT_TYPE_EXTERNAL))
  {
    int min_line_len = HASH_SIZE_SHA256;
    int max_line_len = HASH_SIZE_SHA256 + 1 + SALT_SIZE_MAX_SHA256;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA256;

    if (line_len == min_line_len) return (LINE_OK);

    if (line_buf[HASH_SIZE_SHA256] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = line_buf + HASH_SIZE_SHA256 + 1;
    *salt_len = line_len - HASH_SIZE_SHA256 - 1;

    if ((*salt_len < SALT_SIZE_MIN_SHA256) || (*salt_len > SALT_SIZE_MAX_SHA256)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA256) && (salt_type == SALT_TYPE_INCLUDED))
  {
    int min_line_len = HASH_SIZE_SHA256 + 1 + SALT_SIZE_MIN_SHA256;
    int max_line_len = HASH_SIZE_SHA256 + 1 + SALT_SIZE_MAX_SHA256;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (line_buf[HASH_SIZE_SHA256] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA256;

    *salt_buf = line_buf + HASH_SIZE_SHA256 + 1;
    *salt_len = line_len - HASH_SIZE_SHA256 - 1;

    if (hex_salt == 1)
    {
      *salt_len = convert_from_hex (*salt_buf, *salt_len);
    }

    if ((*salt_len < SALT_SIZE_MIN_SHA256) || (*salt_len > SALT_SIZE_MAX_SHA256)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MD5APR)
  {
    int min_line_len = MD5APR_SIGN + SALT_SIZE_MIN_MD5APR + 1 + HASH_SIZE_MD5APR;
    int max_line_len = MD5APR_SIGN + SALT_SIZE_MAX_MD5APR + 1 + HASH_SIZE_MD5APR;

    if (memcmp (line_buf, MD5APR_MAGIC, MD5APR_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + MD5APR_SIGN;

    if (memcmp (*salt_buf, "rounds=", 7) == 0)
    {
      int rounds_len = 0;

      *salt_buf += 7;

      for (rounds_len = 0; *salt_buf[0] >= '0' && *salt_buf[0] <= '9' && rounds_len < 7; rounds_len++, *salt_buf += 1) continue;

      if (rounds_len   ==  0 ) return (LINE_SIGNATURE_UNMATCHED);
      if (*salt_buf[0] != '$') return (LINE_SIGNATURE_UNMATCHED);

      *salt_buf += 1;

      max_line_len = max_line_len + 7 + rounds_len + 1;
    }

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *salt_ptr = *salt_buf;

    for (*salt_len = 0; *salt_ptr != '$' && *salt_len < SALT_SIZE_MAX_MD5APR; *salt_len += 1, salt_ptr += 1) continue;

    if ((*salt_len < SALT_SIZE_MIN_MD5APR) || (*salt_len > SALT_SIZE_MAX_MD5APR)) return (LINE_SALT_LENGTH);

    *hash_buf = *salt_buf + *salt_len + 1;
    *hash_len = HASH_SIZE_MD5APR;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA512) && (salt_type == SALT_TYPE_NONE))
  {
    int min_line_len = HASH_SIZE_SHA512;
    int max_line_len = HASH_SIZE_SHA512;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA512;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA512) && (salt_type == SALT_TYPE_EXTERNAL))
  {
    int min_line_len = HASH_SIZE_SHA512;
    int max_line_len = HASH_SIZE_SHA512 + 1 + SALT_SIZE_MAX_SHA512;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA512;

    if (line_len == min_line_len) return (LINE_OK);

    if (line_buf[HASH_SIZE_SHA512] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = line_buf + HASH_SIZE_SHA512 + 1;
    *salt_len = line_len - HASH_SIZE_SHA512 - 1;

    if ((*salt_len < SALT_SIZE_MIN_SHA512) || (*salt_len > SALT_SIZE_MAX_SHA512)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_SHA512) && (salt_type == SALT_TYPE_INCLUDED))
  {
    int min_line_len = HASH_SIZE_SHA512 + 1 + SALT_SIZE_MIN_SHA512;
    int max_line_len = HASH_SIZE_SHA512 + 1 + SALT_SIZE_MAX_SHA512;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (line_buf[HASH_SIZE_SHA512] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA512;

    *salt_buf = line_buf + HASH_SIZE_SHA512 + 1;
    *salt_len = line_len - HASH_SIZE_SHA512 - 1;

    if (hex_salt == 1)
    {
      *salt_len = convert_from_hex (*salt_buf, *salt_len);
    }

    if ((*salt_len < SALT_SIZE_MIN_SHA512) || (*salt_len > SALT_SIZE_MAX_SHA512)) return (LINE_SALT_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA512UNIX)
  {
    int min_line_len = SHA512UNIX_SIGN + SALT_SIZE_MIN_SHA512UNIX + 1 + HASH_SIZE_SHA512UNIX;
    int max_line_len = SHA512UNIX_SIGN + SALT_SIZE_MAX_SHA512UNIX + 1 + HASH_SIZE_SHA512UNIX;

    if (memcmp (line_buf, SHA512UNIX_MAGIC, SHA512UNIX_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + SHA512UNIX_SIGN;

    if (memcmp (*salt_buf, "rounds=", 7) == 0)
    {
      int rounds_len = 0;

      *salt_buf += 7;

      for (rounds_len = 0; *salt_buf[0] >= '0' && *salt_buf[0] <= '9' && rounds_len < 7; rounds_len++, *salt_buf += 1) continue;

      if (rounds_len   ==  0 ) return (LINE_SIGNATURE_UNMATCHED);
      if (*salt_buf[0] != '$') return (LINE_SIGNATURE_UNMATCHED);

      *salt_buf += 1;

      max_line_len = max_line_len + 7 + rounds_len + 1;
    }

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *salt_ptr = *salt_buf;

    for (*salt_len = 0; *salt_ptr != '$' && *salt_len < SALT_SIZE_MAX_SHA512UNIX; *salt_len += 1, salt_ptr += 1) continue;

    if ((*salt_len < SALT_SIZE_MIN_SHA512UNIX) || (*salt_len > SALT_SIZE_MAX_SHA512UNIX)) return (LINE_SALT_LENGTH);

    *hash_buf = *salt_buf + *salt_len + 1;
    *hash_len = HASH_SIZE_SHA512UNIX;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MSSQL2012)
  {
    int line_len1 = MSSQL2012_SIGN + SALT_SIZE_MIN_MSSQL2012 + HASH_SIZE_MSSQL2012;

    if (line_len != line_len1) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, MSSQL2012_MAGIC, MSSQL2012_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + MSSQL2012_SIGN;
    *salt_len = 8;

    *hash_buf = line_buf + MSSQL2012_SIGN + *salt_len;
    *hash_len = line_len - MSSQL2012_SIGN - *salt_len;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_DESCRYPT)
  {
    int line_len1 = SALT_SIZE_MIN_DESCRYPT + HASH_SIZE_DESCRYPT;

    if (line_len != line_len1) return (LINE_GLOBAL_LENGTH);

    unsigned char c12 = itoa64_to_int (line_buf[12]);
    if (c12 & 3) return (LINE_HASH_VALUE);

    *salt_buf = line_buf;
    *salt_len = 2;

    *hash_buf = line_buf + *salt_len;
    *hash_len = line_len - *salt_len;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_KECCAK) && (salt_type == SALT_TYPE_EMBEDDED))
  {
    int min_line_len = HASH_SIZE_KECCAK_MIN;
    int max_line_len = HASH_SIZE_KECCAK_MAX;

    if (line_len % 16) return (LINE_GLOBAL_LENGTH); // not sure if this is true

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = line_len;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_IKEPSK_MD5)
  {
    int min_line_len = HASH_SIZE_IKEPSK_MD5_MIN;
    int max_line_len = HASH_SIZE_IKEPSK_MD5_MAX;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *in_off[9];

    size_t in_len[9];

    in_off[0] = strtok (line_buf, ":");

    in_len[0] = strlen (in_off[0]);

    size_t i;

    for (i = 1; i < 9; i++)
    {
      in_off[i] = strtok (NULL, ":");

      if (in_off[i] == NULL) return (LINE_SEPARATOR_UNMATCHED);

      in_len[i] = strlen (in_off[i]);
    }

    static ikepsk_t ikepsk;

    memset (&ikepsk, 0, sizeof (ikepsk_t));

    char *ptr;

    ptr = (char *) ikepsk.msg_buf;

    for (i = 0; i < in_len[0]; i += 2) *ptr++ = hex_to_char (in_off[0] + i);
    for (i = 0; i < in_len[1]; i += 2) *ptr++ = hex_to_char (in_off[1] + i);
    for (i = 0; i < in_len[2]; i += 2) *ptr++ = hex_to_char (in_off[2] + i);
    for (i = 0; i < in_len[3]; i += 2) *ptr++ = hex_to_char (in_off[3] + i);
    for (i = 0; i < in_len[4]; i += 2) *ptr++ = hex_to_char (in_off[4] + i);
    for (i = 0; i < in_len[5]; i += 2) *ptr++ = hex_to_char (in_off[5] + i);

    *ptr = 0x80;

    ikepsk.msg_len = (in_len[0] + in_len[1] + in_len[2] + in_len[3] + in_len[4] + in_len[5]) / 2;

    ptr = (char *) ikepsk.nr_buf;

    for (i = 0; i < in_len[6]; i += 2) *ptr++ = hex_to_char (in_off[6] + i);
    for (i = 0; i < in_len[7]; i += 2) *ptr++ = hex_to_char (in_off[7] + i);

    *ptr = 0x80;

    ikepsk.nr_len = (in_len[6] + in_len[7]) / 2;

    *salt_buf = (char *) &ikepsk;
    *salt_len = sizeof (ikepsk_t);

    *hash_buf = in_off[8];
    *hash_len = in_len[8];

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_IKEPSK_SHA1)
  {
    int min_line_len = HASH_SIZE_IKEPSK_SHA1_MIN;
    int max_line_len = HASH_SIZE_IKEPSK_SHA1_MAX;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *in_off[9];

    size_t in_len[9];

    in_off[0] = strtok (line_buf, ":");

    in_len[0] = strlen (in_off[0]);

    size_t i;

    for (i = 1; i < 9; i++)
    {
      in_off[i] = strtok (NULL, ":");

      if (in_off[i] == NULL) return (LINE_SEPARATOR_UNMATCHED);

      in_len[i] = strlen (in_off[i]);
    }

    static ikepsk_t ikepsk;

    char *ptr;

    ptr = (char *) ikepsk.msg_buf;

    for (i = 0; i < in_len[0]; i += 2) *ptr++ = hex_to_char (in_off[0] + i);
    for (i = 0; i < in_len[1]; i += 2) *ptr++ = hex_to_char (in_off[1] + i);
    for (i = 0; i < in_len[2]; i += 2) *ptr++ = hex_to_char (in_off[2] + i);
    for (i = 0; i < in_len[3]; i += 2) *ptr++ = hex_to_char (in_off[3] + i);
    for (i = 0; i < in_len[4]; i += 2) *ptr++ = hex_to_char (in_off[4] + i);
    for (i = 0; i < in_len[5]; i += 2) *ptr++ = hex_to_char (in_off[5] + i);

    *ptr = 0x80;

    ikepsk.msg_len = (in_len[0] + in_len[1] + in_len[2] + in_len[3] + in_len[4] + in_len[5]) / 2;

    ptr = (char *) ikepsk.nr_buf;

    for (i = 0; i < in_len[6]; i += 2) *ptr++ = hex_to_char (in_off[6] + i);
    for (i = 0; i < in_len[7]; i += 2) *ptr++ = hex_to_char (in_off[7] + i);

    *ptr = 0x80;

    ikepsk.nr_len = (in_len[6] + in_len[7]) / 2;

    *salt_buf = (char *) &ikepsk;
    *salt_len = sizeof (ikepsk_t);

    *hash_buf = in_off[8];
    *hash_len = in_len[8];

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_NETNTLMv1) && (salt_type == SALT_TYPE_EMBEDDED))
  {
    int min_line_len =  1 + 1 + 0 +  1 +  1 +  1 +  0 +  1 + 48 + 1 + 16;
    int max_line_len = 60 + 1 + 0 +  1 + 45 +  1 + 48 +  1 + 48 + 1 + 16;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *pos = line_buf;

    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);
    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);
    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);
    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);
    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_NETNTLMv2) && (salt_type == SALT_TYPE_EMBEDDED))
  {
    int min_line_len =  1 + 1 + 0 +  1 +  1 +  1 + 16 +  1 + 32 + 1 +    1;
    int max_line_len = 60 + 1 + 0 +  1 + 45 +  1 + 16 +  1 + 32 + 1 + 1024;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *pos = line_buf;

    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);
    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);
    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);
    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);
    if ((pos = strchr (pos, ':')) == NULL) return (LINE_SEPARATOR_UNMATCHED);

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_CISCO_SECRET4) && (salt_type == SALT_TYPE_NONE))
  {
    int min_line_len = HASH_SIZE_CISCO_SECRET4;
    int max_line_len = HASH_SIZE_CISCO_SECRET4;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA256;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MD5AIX)
  {
    int min_line_len = MD5AIX_SIGN + SALT_SIZE_MIN_MD5AIX + 1 + HASH_SIZE_MD5AIX;
    int max_line_len = MD5AIX_SIGN + SALT_SIZE_MAX_MD5AIX + 1 + HASH_SIZE_MD5AIX;

    if (memcmp (line_buf, MD5AIX_MAGIC, MD5AIX_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + MD5AIX_SIGN;

    if (memcmp (*salt_buf, "rounds=", 7) == 0)
    {
      int rounds_len = 0;

      *salt_buf += 7;

      for (rounds_len = 0; *salt_buf[0] >= '0' && *salt_buf[0] <= '9' && rounds_len < 7; rounds_len++, *salt_buf += 1) continue;

      if (rounds_len   ==  0 ) return (LINE_SIGNATURE_UNMATCHED);
      if (*salt_buf[0] != '$') return (LINE_SIGNATURE_UNMATCHED);

      *salt_buf += 1;

      max_line_len = max_line_len + 7 + rounds_len + 1;
    }

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *salt_ptr = *salt_buf;

    for (*salt_len = 0; *salt_ptr != '$' && *salt_len < SALT_SIZE_MAX_MD5AIX; *salt_len += 1, salt_ptr += 1) continue;

    if ((*salt_len < SALT_SIZE_MIN_MD5AIX) || (*salt_len > SALT_SIZE_MAX_MD5AIX)) return (LINE_SALT_LENGTH);

    *hash_buf = *salt_buf + *salt_len + 1;
    *hash_len = HASH_SIZE_MD5AIX;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA1AIX)
  {
    int min_line_len = SHA1AIX_SIGN + 2 + 1 + SALT_SIZE_MIN_SHA1AIX + 1 + HASH_SIZE_SHA1AIX;
    int max_line_len = SHA1AIX_SIGN + 2 + 1 + SALT_SIZE_MAX_SHA1AIX + 1 + HASH_SIZE_SHA1AIX;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SHA1AIX_MAGIC, SHA1AIX_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + SHA1AIX_SIGN + 2 + 1;
    for (*salt_len = 0; line_buf[SHA1AIX_SIGN + 2 + 1 + *salt_len] != '$' && *salt_len < SALT_SIZE_MAX_SHA1AIX; *salt_len += 1) continue;

    if ((*salt_len < SALT_SIZE_MIN_SHA1AIX) || (*salt_len > SALT_SIZE_MAX_SHA1AIX)) return (LINE_SALT_LENGTH);

    *hash_buf = line_buf + SHA1AIX_SIGN + 2 + 1 + *salt_len + 1;
    *hash_len = HASH_TYPE_SHA1AIX;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA256AIX)
  {
    int min_line_len = SHA256AIX_SIGN + 2 + 1 + SALT_SIZE_MIN_SHA256AIX + 1 + HASH_SIZE_SHA256AIX;
    int max_line_len = SHA256AIX_SIGN + 2 + 1 + SALT_SIZE_MAX_SHA256AIX + 1 + HASH_SIZE_SHA256AIX;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SHA256AIX_MAGIC, SHA256AIX_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + SHA256AIX_SIGN + 2 + 1;
    for (*salt_len = 0; line_buf[SHA256AIX_SIGN + 2 + 1 + *salt_len] != '$' && *salt_len < SALT_SIZE_MAX_SHA256AIX; *salt_len += 1) continue;

    if ((*salt_len < SALT_SIZE_MIN_SHA256AIX) || (*salt_len > SALT_SIZE_MAX_SHA256AIX)) return (LINE_SALT_LENGTH);

    *hash_buf = line_buf + SHA256AIX_SIGN + 2 + 1 + *salt_len + 1;
    *hash_len = HASH_TYPE_SHA256AIX;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA512AIX)
  {
    int min_line_len = SHA512AIX_SIGN + 2 + 1 + SALT_SIZE_MIN_SHA512AIX + 1 + HASH_SIZE_SHA512AIX;
    int max_line_len = SHA512AIX_SIGN + 2 + 1 + SALT_SIZE_MAX_SHA512AIX + 1 + HASH_SIZE_SHA512AIX;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SHA512AIX_MAGIC, SHA512AIX_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + SHA512AIX_SIGN + 2 + 1;
    for (*salt_len = 0; line_buf[SHA512AIX_SIGN + 2 + 1 + *salt_len] != '$' && *salt_len < SALT_SIZE_MAX_SHA512AIX; *salt_len += 1) continue;

    if ((*salt_len < SALT_SIZE_MIN_SHA512AIX) || (*salt_len > SALT_SIZE_MAX_SHA512AIX)) return (LINE_SALT_LENGTH);

    *hash_buf = line_buf + SHA512AIX_SIGN + 2 + 1 + *salt_len + 1;
    *hash_len = HASH_TYPE_SHA512AIX;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_GOST) && (salt_type == SALT_TYPE_NONE))
  {
    int min_line_len = HASH_SIZE_GOST;
    int max_line_len = HASH_SIZE_GOST;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_GOST;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA1FORTIGATE)
  {
    int fortigate_line_len = FORTIGATE_SIGN + 44;  // 3 + 44 (44 == base64 encoded SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1)

    if (line_len != fortigate_line_len) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, FORTIGATE_MAGIC, FORTIGATE_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *hash_buf = line_buf + FORTIGATE_SIGN;
    *hash_len = line_len - FORTIGATE_SIGN;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_PBKDF2OSX)
  {
    int min_line_len = PBKDF2OSX_SIGN + 1 + SALT_SIZE_MIN_PBKDF2OSX + 1 + HASH_SIZE_PBKDF2OSX;
    int max_line_len = PBKDF2OSX_SIGN + 7 + SALT_SIZE_MAX_PBKDF2OSX + 1 + (HASH_SIZE_PBKDF2OSX * 3); // * 3 because of keysize variations

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, PBKDF2OSX_MAGIC, PBKDF2OSX_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    int iter_len;

    for (iter_len = 0; line_buf[PBKDF2OSX_SIGN + iter_len] >= '0' && line_buf[PBKDF2OSX_SIGN + iter_len] <= '9' && iter_len < 7; iter_len += 1) continue;

    if (iter_len < 1 || iter_len > 7) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + PBKDF2OSX_SIGN + iter_len + 1;

    for (*salt_len = 0; line_buf[PBKDF2OSX_SIGN + iter_len + 1 + *salt_len] != '$' && *salt_len < SALT_SIZE_MAX_PBKDF2OSX; *salt_len += 1) continue;

    if (*salt_len != SALT_SIZE_MIN_PBKDF2OSX) return (LINE_SALT_LENGTH);

    *hash_buf = line_buf + PBKDF2OSX_SIGN + iter_len + 1 + *salt_len + 1;
    *hash_len = line_len - PBKDF2OSX_SIGN - iter_len - 1 - *salt_len - 1;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_PBKDF2GRUB)
  {
    int min_line_len = PBKDF2GRUB_SIGN + 1 + SALT_SIZE_MIN_PBKDF2GRUB + 1 + HASH_SIZE_PBKDF2GRUB;
    int max_line_len = PBKDF2GRUB_SIGN + 7 + SALT_SIZE_MAX_PBKDF2GRUB + 1 + (HASH_SIZE_PBKDF2GRUB * 10); // * 10 accounts for keysize variations

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, PBKDF2GRUB_MAGIC, PBKDF2GRUB_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    int iter_len;

    for (iter_len = 0; line_buf[PBKDF2GRUB_SIGN + iter_len] >= '0' && line_buf[PBKDF2GRUB_SIGN + iter_len] <= '9' && iter_len < 7; iter_len += 1) continue;

    if (iter_len < 1 || iter_len > 7) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + PBKDF2GRUB_SIGN + iter_len + 1;

    for (*salt_len = 0; line_buf[PBKDF2GRUB_SIGN + iter_len + 1 + *salt_len] != '.' && *salt_len < SALT_SIZE_MAX_PBKDF2GRUB; *salt_len += 1) continue;

    if (*salt_len < SALT_SIZE_MIN_PBKDF2GRUB || *salt_len > SALT_SIZE_MAX_PBKDF2GRUB) return (LINE_SALT_LENGTH);

    *hash_buf = line_buf + PBKDF2GRUB_SIGN + iter_len + 1 + *salt_len + 1;
    *hash_len = line_len - PBKDF2GRUB_SIGN - iter_len - 1 - *salt_len - 1;

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_MD5CISCO_PIX) && (salt_type == SALT_TYPE_NONE))
  {
    int min_line_len = HASH_SIZE_MD5CISCO;

    if (line_len != min_line_len) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = line_len;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA1ORACLE)
  {
    int min_line_len = HASH_SIZE_SHA1ORACLE + 1 + SALT_SIZE_MIN_SHA1ORACLE;

    if (line_len != min_line_len) return (LINE_GLOBAL_LENGTH);

    if (line_buf[HASH_SIZE_SHA1ORACLE] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_SHA1ORACLE;

    *salt_buf = line_buf + HASH_SIZE_SHA1FORTIGATE + 1;
    *salt_len = SALT_SIZE_MIN_SHA1ORACLE;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_HMACRAKP)
  {
    int min_line_len = SALT_SIZE_MIN_HMACRAKP + 1 + HASH_SIZE_HMACRAKP;
    int max_line_len = SALT_SIZE_MAX_HMACRAKP + 1 + HASH_SIZE_HMACRAKP;

    if (line_len < min_line_len || line_len > max_line_len) return (LINE_GLOBAL_LENGTH);

    *salt_buf = line_buf;

    for (*salt_len = 0; line_buf[*salt_len] != separator && *salt_len < SALT_SIZE_MAX_HMACRAKP; *salt_len += 1) continue;

    if (*salt_len < SALT_SIZE_MIN_HMACRAKP || *salt_len > SALT_SIZE_MAX_HMACRAKP || *salt_len % 2 != 0) return (LINE_SALT_LENGTH);

    *hash_len = line_len - *salt_len - 1;

    if (*hash_len != HASH_SIZE_HMACRAKP) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf + *salt_len + 1;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_BCRYPT)
  {
    int min_line_len = BCRYPT_SIGN + 3 + SALT_SIZE_MIN_BCRYPT + HASH_SIZE_BCRYPT;

    if (line_len != min_line_len) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, BCRYPT_MAGIC, BCRYPT_SIGN) != 0)
    {
      unsigned char alternative_sign[BCRYPT_SIGN];

      memcpy (&alternative_sign, BCRYPT_MAGIC, BCRYPT_SIGN);

      alternative_sign[2] = 'x';

      if (memcmp (line_buf, alternative_sign, BCRYPT_SIGN) != 0)
      {
        alternative_sign[2] = 'y';

        if (memcmp (line_buf, alternative_sign, BCRYPT_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);
      }
    }

    if (line_buf[BCRYPT_SIGN + 2] != '$') return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = line_buf + BCRYPT_SIGN + 3;
    *salt_len = SALT_SIZE_MIN_BCRYPT;

    *hash_buf = *salt_buf + SALT_SIZE_MIN_BCRYPT;
    *hash_len = HASH_SIZE_BCRYPT;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA256UNIX)
  {
    int min_line_len = SHA256UNIX_SIGN + SALT_SIZE_MIN_SHA256UNIX + 1 + HASH_SIZE_SHA256UNIX;
    int max_line_len = SHA256UNIX_SIGN + SALT_SIZE_MAX_SHA256UNIX + 1 + HASH_SIZE_SHA256UNIX;

    if (memcmp (line_buf, SHA256UNIX_MAGIC, SHA256UNIX_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *salt_buf = line_buf + SHA256UNIX_SIGN;

    if (memcmp (*salt_buf, "rounds=", 7) == 0)
    {
      int rounds_len = 0;

      *salt_buf += 7;

      for (rounds_len = 0; *salt_buf[0] >= '0' && *salt_buf[0] <= '9' && rounds_len < 7; rounds_len++, *salt_buf += 1) continue;

      if (rounds_len   ==  0 ) return (LINE_SIGNATURE_UNMATCHED);
      if (*salt_buf[0] != '$') return (LINE_SIGNATURE_UNMATCHED);

      *salt_buf += 1;

      max_line_len = max_line_len + 7 + rounds_len + 1;
    }

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    char *salt_ptr = *salt_buf;

    for (*salt_len = 0; *salt_ptr != '$' && *salt_len < SALT_SIZE_MAX_SHA256UNIX; *salt_len += 1, salt_ptr += 1) continue;

    if ((*salt_len < SALT_SIZE_MIN_SHA256UNIX) || (*salt_len > SALT_SIZE_MAX_SHA256UNIX)) return (LINE_SALT_LENGTH);

    *hash_buf = *salt_buf + *salt_len + 1;
    *hash_len = HASH_SIZE_SHA256UNIX;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_EPIV6_4)
  {
    int line_len1 = EPISERVERV6_4_SIGN + SALT_SIZE_MIN_EPIV6_4 + 1 + HASH_SIZE_EPIV6_4_MIN;
    int line_len2 = EPISERVERV6_4_SIGN + SALT_SIZE_MAX_EPIV6_4 + 1 + HASH_SIZE_EPIV6_4_MAX;

    if ((line_len < line_len1) || (line_len > line_len2)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, EPISERVERV6_4_MAGIC, EPISERVERV6_4_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + EPISERVERV6_4_SIGN;

    char *hash_pos = strchr (salt_pos, '*');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    hash_pos++;

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos - 1;

    if (*salt_len < SALT_SIZE_MIN_EPIV6_4 || *salt_len > SALT_SIZE_MAX_EPIV6_4) return (LINE_SALT_LENGTH);

    *hash_buf = hash_pos;
    *hash_len = HASH_SIZE_EPIV6_4_MIN;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SHA512B64S)
  {
    int min_line_len = SHA512B64S_SIGN + HASH_SIZE_SHA512B64 + SALT_SIZE_MIN_SHA512B64S;
    int max_line_len = SHA512B64S_SIGN + HASH_SIZE_SHA512B64 + SALT_SIZE_MAX_SHA512B64S;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SHA512B64S_MAGIC, SHA512B64S_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *hash_buf = line_buf + SHA512B64S_SIGN;
    *hash_len = line_len - SHA512B64S_SIGN;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_EPIV4)
  {
    int line_len1 = EPISERVERV4_SIGN + SALT_SIZE_MIN_EPIV4 + 1 + EPISERVERV4_SIGN + HASH_SIZE_EPIV4_MIN;
    int line_len2 = EPISERVERV4_SIGN + SALT_SIZE_MAX_EPIV4 + 1 + EPISERVERV4_SIGN + HASH_SIZE_EPIV4_MAX;

    if ((line_len < line_len1) || (line_len > line_len2)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, EPISERVERV4_MAGIC, EPISERVERV4_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + EPISERVERV4_SIGN;

    char *hash_pos = strchr (salt_pos, ' ');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos;

    hash_pos = hash_pos + 1 + EPISERVERV4_SIGN;

    if (*salt_len < SALT_SIZE_MIN_EPIV4 || *salt_len > SALT_SIZE_MAX_EPIV4) return (LINE_SALT_LENGTH);

    *hash_buf = hash_pos;
    *hash_len = HASH_SIZE_EPIV4_MIN;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SCRYPT)
  {
    int line_len1 = SCRYPT_SIGN + 1 + 1 + 1 + 1 + 1 + 1 + 1 + SALT_SIZE_MIN_SCRYPT + 1 + HASH_SIZE_SCRYPT_MIN;
    int line_len2 = SCRYPT_SIGN + 1 + 7 + 1 + 2 + 1 + 2 + 1 + SALT_SIZE_MAX_SCRYPT + 1 + HASH_SIZE_SCRYPT_MAX;

    if ((line_len < line_len1) || (line_len > line_len2)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SCRYPT_MAGIC, SCRYPT_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *N_pos = line_buf + SCRYPT_SIGN;

    if (N_pos[0] != ':') return (LINE_SEPARATOR_UNMATCHED);

    N_pos++;

    char *r_pos = strchr (N_pos, ':');

    if (r_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    r_pos++;

    char *p_pos = strchr (r_pos, ':');

    if (p_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    p_pos++;

    char *salt_pos = strchr (p_pos, ':');

    if (salt_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    salt_pos++;

    char *hash_pos = strchr (salt_pos, ':');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    *salt_len = hash_pos - salt_pos;

    if (*salt_len < SALT_SIZE_MIN_SCRYPT || *salt_len > SALT_SIZE_MAX_SCRYPT) return (LINE_SALT_LENGTH);

    hash_pos++;

    *hash_len = HASH_SIZE_SCRYPT_MIN;

    *hash_buf = hash_pos;
    *salt_buf = salt_pos;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_CISCO_SECRET9)
  {
    int line_len1 = CISCO_SECRET9_SIGN + SALT_SIZE_CISCO_SECRET9 + 1 + HASH_SIZE_CISCO_SECRET9;

    if (line_len != line_len1) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, CISCO_SECRET9_MAGIC, CISCO_SECRET9_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + CISCO_SECRET9_SIGN;

    char *hash_pos = strchr (salt_pos, '$');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    *salt_len = hash_pos - salt_pos;

    if (*salt_len < SALT_SIZE_CISCO_SECRET9) return (LINE_SALT_LENGTH);

    hash_pos++;

    *hash_len = HASH_SIZE_CISCO_SECRET9;

    *hash_buf = hash_pos;
    *salt_buf = salt_pos;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_PHPS)
  {
    int min_line_len = 6 + SALT_SIZE_MIN_MD5 + 1 + HASH_SIZE_MD5;
    int max_line_len = 6 + SALT_SIZE_MAX_MD5 + 1 + HASH_SIZE_MD5;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, PHPS_MAGIC, PHPS_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + PHPS_SIGN;

    char *hash_pos = strchr (salt_pos, '$');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    hash_pos++;

    int salt_len_hex = line_len - HASH_SIZE_MD5 - 1 - 6;

    if ((salt_len_hex % 2) != 0) return (LINE_SALT_LENGTH);

    if (salt_len_hex > 46) return (LINE_SALT_LENGTH);

    *hash_buf = hash_pos;
    *hash_len = HASH_SIZE_MD5;

    *salt_buf = salt_pos;
    *salt_len = salt_len_hex / 2;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_DJANGOSHA1)
  {
    int line_len1 = DJANGOSHA1_SIGN + SALT_SIZE_MIN_DJANGOSHA1 + 1 + HASH_SIZE_DJANGOSHA1_MIN;
    int line_len2 = DJANGOSHA1_SIGN + SALT_SIZE_MAX_DJANGOSHA1 + 1 + HASH_SIZE_DJANGOSHA1_MAX;

    if ((line_len < line_len1) || (line_len > line_len2)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, DJANGOSHA1_MAGIC, DJANGOSHA1_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + DJANGOSHA1_SIGN;

    char *hash_pos = strchr (salt_pos, '$');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos;

    hash_pos++;

    if (*salt_len < SALT_SIZE_MIN_DJANGOSHA1 || *salt_len > SALT_SIZE_MAX_DJANGOSHA1) return (LINE_SALT_LENGTH);

    *hash_buf = hash_pos;
    *hash_len = HASH_SIZE_DJANGOSHA1_MIN;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_HMAIL)
  {
    int line_len_expected = SALT_SIZE_HMAIL + HASH_SIZE_HMAIL;

    if (line_len != line_len_expected) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf + SALT_SIZE_HMAIL;
    *hash_len = HASH_SIZE_SHA256;

    *salt_buf = line_buf;
    *salt_len = SALT_SIZE_HMAIL;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MEDIAWIKI_B)
  {
    int min_line_len = MEDIAWIKI_B_SIGN + SALT_SIZE_MIN_MEDIAWIKI_B + 1 + HASH_SIZE_MEDIAWIKI_B_MIN;
    int max_line_len = MEDIAWIKI_B_SIGN + SALT_SIZE_MAX_MEDIAWIKI_B + 1 + HASH_SIZE_MEDIAWIKI_B_MAX;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, MEDIAWIKI_B_MAGIC, MEDIAWIKI_B_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + MEDIAWIKI_B_SIGN;

    char *hash_pos = strchr (salt_pos, '$');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos;

    hash_pos++; // skip the $

    *hash_buf = hash_pos;
    *hash_len = line_len - MEDIAWIKI_B_SIGN - *salt_len - 1;

    if (*hash_len != HASH_SIZE_MEDIAWIKI_B_MIN) return (LINE_HASH_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_CISCO_SECRET8)
  {
    int min_line_len = CISCO_SECRET8_SIGN + SALT_SIZE_MIN_CISCO_SECRET8 + 1 + HASH_SIZE_CISCO_SECRET8;
    int max_line_len = CISCO_SECRET8_SIGN + SALT_SIZE_MAX_CISCO_SECRET8 + 1 + HASH_SIZE_CISCO_SECRET8;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, CISCO_SECRET8_MAGIC, CISCO_SECRET8_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + CISCO_SECRET8_SIGN;

    char *hash_pos = strchr (salt_pos, '$');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos;

    hash_pos++;

    *hash_buf = hash_pos;
    *hash_len = line_len - CISCO_SECRET8_SIGN - *salt_len - 1;

    if (*hash_len != HASH_SIZE_CISCO_SECRET8) return (LINE_HASH_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_DJANGO_SHA256)
  {
    int min_line_len = DJANGO_SHA256_SIGN + 1 + 1 + SALT_SIZE_MIN_DJANGO_SHA256 + 1 + HASH_SIZE_DJANGO_SHA256;
    int max_line_len = DJANGO_SHA256_SIGN + 6 + 1 + SALT_SIZE_MAX_DJANGO_SHA256 + 1 + HASH_SIZE_DJANGO_SHA256;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, DJANGO_SHA256_MAGIC, DJANGO_SHA256_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *iter_pos = line_buf + DJANGO_SHA256_SIGN;

    char *salt_pos = strchr (iter_pos, '$');

    if (salt_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    uint iter_len = salt_pos - line_buf - DJANGO_SHA256_SIGN;

    salt_pos++;

    char *hash_pos = strchr (salt_pos, '$');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos;

    hash_pos++;

    *hash_buf = hash_pos;
    *hash_len = line_len - DJANGO_SHA256_SIGN - iter_len - 1 - *salt_len - 1;

    if (*hash_len != HASH_SIZE_DJANGO_SHA256) return (LINE_HASH_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_PEOPLESOFT)
  {
    int min_line_len = HASH_SIZE_PEOPLESOFT;
    int max_line_len = HASH_SIZE_PEOPLESOFT;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_PEOPLESOFT;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_CRAM_MD5)
  {
    int min_line_len = CRAM_MD5_SIGN + SALT_SIZE_MIN_CRAM_MD5 + 1 + HASH_SIZE_CRAM_MD5_MIN;
    int max_line_len = CRAM_MD5_SIGN + SALT_SIZE_MAX_CRAM_MD5 + 1 + HASH_SIZE_CRAM_MD5_MAX;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, CRAM_MD5_MAGIC, CRAM_MD5_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *salt_pos = line_buf + CRAM_MD5_SIGN;

    char *hash_pos = strchr (salt_pos, '$');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos;

    hash_pos++;

    *hash_buf = hash_pos;
    *hash_len = line_len - CRAM_MD5_SIGN - *salt_len - 1;

    if ((*hash_len < HASH_SIZE_CRAM_MD5_MIN) || (*hash_len > HASH_SIZE_CRAM_MD5_MAX)) return (LINE_HASH_LENGTH);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_DRUPAL7)
  {
    int line_len_expected = DRUPAL7_SIGN + 1 + SALT_SIZE_DRUPAL7 + HASH_SIZE_DRUPAL7;

    if (line_len != line_len_expected) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, DRUPAL7_MAGIC, DRUPAL7_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    *hash_buf = line_buf + DRUPAL7_SIGN + 1 + SALT_SIZE_DRUPAL7;
    *hash_len = HASH_SIZE_DRUPAL7;

    *salt_buf = line_buf + DRUPAL7_SIGN + 1;
    *salt_len = SALT_SIZE_DRUPAL7;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MD5CISCO_ASA)
  {
    int min_line_len = HASH_SIZE_MD5CISCO + 1 + SALT_SIZE_MIN_MD5CISCO_ASA;
    int max_line_len = HASH_SIZE_MD5CISCO + 1 + SALT_SIZE_MAX_MD5CISCO_ASA;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_MD5CISCO;

    *salt_buf = line_buf + HASH_SIZE_MD5CISCO + 1;
    *salt_len = line_len - HASH_SIZE_MD5CISCO - 1;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SAP_H_SHA1)
  {
    int min_line_len = SAP_H_SHA1_SIGN + 1 + 1 + HASH_SIZE_SAP_H_MIN;
    int max_line_len = SAP_H_SHA1_SIGN + 5 + 1 + HASH_SIZE_SAP_H_MAX;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SAP_H_SHA1_MAGIC, SAP_H_SHA1_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *hash_pos = strchr (line_buf, '}');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    hash_pos++;

    *hash_buf = hash_pos;
    *hash_len = line_len - (hash_pos - line_buf);

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_PRESTASHOP)
  {
    int expected_line_len = HASH_SIZE_MD5 + 1 + SALT_SIZE_MIN_PRESTASHOP;

    if (line_len != expected_line_len) return (LINE_GLOBAL_LENGTH);

    if (line_buf[HASH_SIZE_MD5] != separator) return (LINE_SEPARATOR_UNMATCHED);

    *hash_buf = line_buf;
    *hash_len = HASH_SIZE_MD5;

    *salt_buf = line_buf + HASH_SIZE_MD5 + 1;
    *salt_len = SALT_SIZE_MIN_PRESTASHOP;

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_POSTGRESQL_AUTH)
  {
    int min_line_len = POSTGRESQL_AUTH_SIGN +              0 + 1 + SALT_SIZE_POSTGRESQL_AUTH + 1 + HASH_SIZE_MD5;
    int max_line_len = POSTGRESQL_AUTH_SIGN + PLAIN_SIZE_MD5 + 1 + SALT_SIZE_POSTGRESQL_AUTH + 1 + HASH_SIZE_MD5;

    if (line_len < min_line_len) return (LINE_GLOBAL_LENGTH);
    if (line_len > max_line_len) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, POSTGRESQL_AUTH_MAGIC, POSTGRESQL_AUTH_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    char *user_pos = line_buf + POSTGRESQL_AUTH_SIGN;

    char *salt_pos = strchr (user_pos, '*');

    if (salt_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    salt_pos++;

    char *hash_pos = strchr (salt_pos, '*');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    hash_pos++;

    *hash_buf = hash_pos;
    *hash_len = HASH_SIZE_MD5;

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos - 1;

    if (*salt_len != SALT_SIZE_POSTGRESQL_AUTH) return (LINE_SALT_LENGTH);

    *salt_len /= 2; // salt is in exactly 4 hex bytes

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_MYSQL_AUTH)
  {
    int expected_line_len = MYSQL_AUTH_SIGN + SALT_SIZE_MYSQL_AUTH + 1 + HASH_SIZE_SHA1;

    if (memcmp (line_buf, MYSQL_AUTH_MAGIC, MYSQL_AUTH_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    if (line_len != expected_line_len) return (LINE_GLOBAL_LENGTH);

    char *salt_pos = line_buf + MYSQL_AUTH_SIGN;

    char *hash_pos = strchr (salt_pos, '*');

    if (hash_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    hash_pos++;

    *salt_buf = salt_pos;
    *salt_len = hash_pos - salt_pos - 1;

    *hash_buf = hash_pos;
    *hash_len = line_len - (hash_pos - line_buf);

    if (*salt_len != SALT_SIZE_MYSQL_AUTH) return (LINE_SALT_LENGTH);
    if (*hash_len != HASH_SIZE_SHA1)       return (LINE_HASH_LENGTH);

    *salt_len /= 2; // 20 bytes (convert from hex)

    return (LINE_OK);
  }
  else if (hash_type == HASH_TYPE_SIP_AUTH)
  {
    int min_line_len = SIP_AUTH_SIGN +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   0 + 1 +   1 + 1 +   0 + 1 +  1 + 1 +  0 + 1 +  0 + 1 +  0 + 1 + 3 + 1 + HASH_SIZE_MD5;
    int max_line_len = SIP_AUTH_SIGN + 512 + 1 + 512 + 1 + 116 + 1 + 116 + 1 + 246 + 1 + 245 + 1 + 246 + 1 + 245 + 1 + 50 + 1 + 50 + 1 + 50 + 1 + 50 + 1 + 3 + 1 + HASH_SIZE_MD5;

    if (line_len < min_line_len) return (LINE_GLOBAL_LENGTH);
    if (line_len > max_line_len) return (LINE_GLOBAL_LENGTH);

    if (memcmp (line_buf, SIP_AUTH_MAGIC, SIP_AUTH_SIGN) != 0) return (LINE_SIGNATURE_UNMATCHED);

    // use a temporary buffer such that we can manipulate it

    char temp_buf[max_line_len + 1];

    memset (temp_buf, 0, sizeof (temp_buf));
    memcpy (temp_buf, line_buf, max_line_len);

    // URI_server:

    char *URI_server_pos = temp_buf + SIP_AUTH_SIGN;

    char *URI_client_pos = strchr (URI_server_pos, '*');

    if (URI_client_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    URI_client_pos[0] = '\0';
    URI_client_pos++;

    uint URI_server_len = strlen (URI_server_pos);

    if (URI_server_len > 512) return (LINE_SALT_LENGTH);

    // URI_client:

    char *user_pos = strchr (URI_client_pos, '*');

    if (user_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    user_pos[0] = '\0';
    user_pos++;

    uint URI_client_len = strlen (URI_client_pos);

    if (URI_client_len > 512) return (LINE_SALT_LENGTH);

    // user:

    char *realm_pos = strchr (user_pos, '*');

    if (realm_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    realm_pos[0] = '\0';
    realm_pos++;

    uint user_len = strlen (user_pos);

    if (user_len > 116) return (LINE_SALT_LENGTH);

    // realm:

    char *method_pos = strchr (realm_pos, '*');

    if (method_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    method_pos[0] = '\0';
    method_pos++;

    uint realm_len = strlen (realm_pos);

    if (realm_len > 116) return (LINE_SALT_LENGTH);

    // method:

    char *URI_prefix_pos = strchr (method_pos, '*');

    if (URI_prefix_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    URI_prefix_pos[0] = '\0';
    URI_prefix_pos++;

    uint method_len = strlen (method_pos);

    if (method_len > 246) return (LINE_SALT_LENGTH);

    // URI_prefix:

    char *URI_resource_pos = strchr (URI_prefix_pos, '*');

    if (URI_resource_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    URI_resource_pos[0] = '\0';
    URI_resource_pos++;

    uint URI_prefix_len = strlen (URI_prefix_pos);

    if (URI_prefix_len > 245) return (LINE_SALT_LENGTH);

    // URI_resource:

    char *URI_suffix_pos = strchr (URI_resource_pos, '*');

    if (URI_suffix_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    URI_suffix_pos[0] = '\0';
    URI_suffix_pos++;

    uint URI_resource_len = strlen (URI_resource_pos);

    if (URI_resource_len <   1) return (LINE_SALT_LENGTH);
    if (URI_resource_len > 246) return (LINE_SALT_LENGTH);

    // URI_suffix:

    char *nonce_pos = strchr (URI_suffix_pos, '*');

    if (nonce_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    nonce_pos[0] = '\0';
    nonce_pos++;

    uint URI_suffix_len = strlen (URI_suffix_pos);

    if (URI_suffix_len > 245) return (LINE_SALT_LENGTH);

    // nonce:

    char *nonce_client_pos = strchr (nonce_pos, '*');

    if (nonce_client_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    nonce_client_pos[0] = '\0';
    nonce_client_pos++;

    uint nonce_len = strlen (nonce_pos);

    if (nonce_len <  1) return (LINE_SALT_LENGTH);
    if (nonce_len > 50) return (LINE_SALT_LENGTH);

    // nonce_client:

    char *nonce_count_pos = strchr (nonce_client_pos, '*');

    if (nonce_count_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    nonce_count_pos[0] = '\0';
    nonce_count_pos++;

    uint nonce_client_len = strlen (nonce_client_pos);

    if (nonce_client_len > 50) return (LINE_SALT_LENGTH);

    // nonce_count:

    char *qop_pos = strchr (nonce_count_pos, '*');

    if (qop_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    qop_pos[0] = '\0';
    qop_pos++;

    uint nonce_count_len = strlen (nonce_count_pos);

    if (nonce_count_len > 50) return (LINE_SALT_LENGTH);

    // qop:

    char *directive_pos = strchr (qop_pos, '*');

    if (directive_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    directive_pos[0] = '\0';
    directive_pos++;

    uint qop_len = strlen (qop_pos);

    if (qop_len > 50) return (LINE_SALT_LENGTH);

    // directive

    char *digest_pos = strchr (directive_pos, '*');

    if (digest_pos == NULL) return (LINE_SEPARATOR_UNMATCHED);

    digest_pos[0] = '\0';
    digest_pos++;

    uint directive_len = strlen (directive_pos);

    if (directive_len != 3) return (LINE_SALT_LENGTH);

    if (memcmp (directive_pos, "MD5", 3))
    {
      log_error ("ERROR: only the MD5 directive is currently supported\n");

      return (LINE_SALT_LENGTH);
    }

    return (LINE_OK);
  }
  else if ((hash_type == HASH_TYPE_PLAIN) && (salt_type == SALT_TYPE_NONE))
  {
    int min_line_len = 0;
    int max_line_len = HASH_SIZE_PLAIN;

    if ((line_len < min_line_len) || (line_len > max_line_len)) return (LINE_GLOBAL_LENGTH);

    *hash_buf = line_buf;
    *hash_len = line_len;

    return (LINE_OK);
  }

  return (LINE_UNKNOWN_ERROR);
}

void plain_init (plain_t *in);

void md5_init_sse2 (digest_md5_sse2_t *digests);

void md5_update_sse2 (plain_t *plains_dst, digest_md5_sse2_t *digests, plain_t *plains_src);

void md5_final_sse2_max55 (plain_t *plains, digest_md5_sse2_t *digests);

void md5_final_sse2 (plain_t *plains, digest_md5_sse2_t *digests);

void transpose_md5_digest (digest_md5_sse2_t *in, digest_t *out);

void load_salts (FILE *fp, db_t *db, engine_parameter_t *engine_parameter)
{
  char line_buf[BUFSIZ];

  int line_len;

  while ((line_len = fgetl (fp, line_buf)) != -1)
  {
    if (line_len == 0) continue;

    /* do not skip lines beginning with # because this is valid salt char */

    if ((line_len < SALT_SIZE_MIN_MD5) || (line_len > SALT_SIZE_MAX_MD5))
    {
      log_warning ("Skipping salt: %s (salt length)", line_buf);

      continue;
    }

    salt_t *salt_search = init_new_salt ();

    salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
    salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

    memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
    memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

    memcpy (salt_search->salt_plain_buf, line_buf, line_len);

    salt_search->salt_plain_len = line_len;

    if (engine_parameter->hash_mode == 2811 || engine_parameter->hash_mode == 3610 || engine_parameter->hash_mode == 3910)
    {
      digest_md5_sse2_t digests;

      digest_t dgst[4];

      plain_t plains[4];

      uint32_t i;

      for (i = 0; i < 4; i += 1)
      {
        memcpy (&plains[i].buf, salt_search->salt_plain_buf, salt_search->salt_plain_len);

        plains[i].len = salt_search->salt_plain_len;
      }

      md5_init_sse2 (&digests);

      md5_final_sse2_max55 (plains, &digests);

      transpose_md5_digest (&digests, dgst);

      BYTESWAP (dgst[0].buf.md5[0]);
      BYTESWAP (dgst[0].buf.md5[1]);
      BYTESWAP (dgst[0].buf.md5[2]);
      BYTESWAP (dgst[0].buf.md5[3]);

      char hex_tmp[4][8];

      uint_to_hex_lower (dgst[0].buf.md5[0], hex_tmp[0]);
      uint_to_hex_lower (dgst[0].buf.md5[1], hex_tmp[1]);
      uint_to_hex_lower (dgst[0].buf.md5[2], hex_tmp[2]);
      uint_to_hex_lower (dgst[0].buf.md5[3], hex_tmp[3]);

      for (i = 0; i < 4; i += 1)
      {
         memcpy (&salt_search->salt_plain_struct[i], hex_tmp[0], 32);

         salt_search->salt_plain_struct[i].len = 32;
      }
    }

    void *ptr = NULL;

    if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
    {
      incr_salt_ptrs (db);

      db->salts_buf[db->salts_cnt] = salt_search;

      db->salts_cnt++;

      __hc_tsearch (salt_search, &root_salts, compare_salt);
    }
    else
    {
      myfree (salt_search->salt_prehashed_buf);

      myfree (salt_search->salt_plain_buf);

      myfree (salt_search);
    }
  }
}

int base64b_char2int (char c);

void load_hashes (FILE *fp, db_t *db, engine_parameter_t *engine_parameter)
{
  uint32_t separator_warnings = 0;

  char entire_line_buf[BUFSIZ];

  int entire_line_len;

  FILE *out_fp = NULL;

  pot_t *pot = engine_parameter->pot;

  if (engine_parameter->file_output != NULL)
  {
    out_fp = fopen (engine_parameter->file_output, "ab");

    if (out_fp == NULL)
    {
      log_error ("ERROR: cannot open output file '%s' (%d) : %s", engine_parameter->file_output, errno, strerror (errno));

      exit (-1);
    }
  }
  else
  {
    out_fp = stdout;
  }

  if (engine_parameter->hash_type == HASH_TYPE_PSAFE3)
  {
    char tmp[4];

    if (fread (tmp, sizeof (char), PSAFE3_SIGN, fp) != PSAFE3_SIGN)
    {
      log_warning ("Skipping file: %s (signature unmatched)", engine_parameter->file_hashes);

      return;
    }

    uint32_t salt_buf[8];
    uint32_t psafe3_iter[1];
    uint32_t hash_buf[8];

    if (fread (salt_buf, sizeof (uint32_t), 8, fp) != 8)
    {
      log_warning ("Skipping file: %s (salt length exception)", engine_parameter->file_hashes);

      if (out_fp != stdin) fclose (out_fp);

      return;
    }

    if (fread (psafe3_iter, sizeof (uint32_t), 1, fp) != 1)
    {
      log_warning ("Skipping file: %s (iterator length exception)", engine_parameter->file_hashes);

      if (out_fp != stdin) fclose (out_fp);

      return;
    }

    if (fread (hash_buf, sizeof (uint32_t), 8, fp) != 8)
    {
      log_warning ("Skipping file: %s (hash length exception)", engine_parameter->file_hashes);

      if (out_fp != stdin) fclose (out_fp);

      return;
    }

    /* digest */

    digest_t *digest = init_new_digest ();

    digest->buf.sha256[0] = hash_buf[0];
    digest->buf.sha256[1] = hash_buf[1];
    digest->buf.sha256[2] = hash_buf[2];
    digest->buf.sha256[3] = hash_buf[3];
    digest->buf.sha256[4] = hash_buf[4];
    digest->buf.sha256[5] = hash_buf[5];
    digest->buf.sha256[6] = hash_buf[6];
    digest->buf.sha256[7] = hash_buf[7];

    /* salt */

    salt_t *salt = init_new_salt ();

    salt->salt_plain_buf = mymalloc (32);

    memcpy (salt->salt_plain_buf, salt_buf, 32);

    salt->salt_plain_len = 32;

    salt->iterations = psafe3_iter[0];

    incr_salt_ptrs (db);

    db->salts_buf[db->salts_cnt] = salt;

    db->salts_cnt++;

    /* index */

    if (salt->indexes_buf == NULL)
    {
      salt->indexes_buf = mymalloc (sizeof (index_t *));

      salt->indexes_buf[0] = init_new_index ();

      salt->indexes_cnt++;
    }

    index_t *index = salt->indexes_buf[0];

    incr_digest_ptrs (index);

    index->digests_buf[index->digests_cnt] = digest;

    index->digests_cnt++;

    status_info.proc_hashes++;
  }
  else if (engine_parameter->hash_type == HASH_TYPE_WPA)
  {
    hccap_t in;

    int n = fread (&in, sizeof (hccap_t), 1, fp);

    if (n != 1)
    {
      log_warning ("Skipping file: %s (file too small)", engine_parameter->file_hashes);

      return;
    }

    if (in.eapol_size < 1 || in.eapol_size > 255)
    {
      log_warning ("Skipping file: %s (invalid eapol size)", engine_parameter->file_hashes);

      if (out_fp != stdin) fclose (out_fp);

      return;
    }

    /* digest */

    digest_t *digest = init_new_digest ();

    memcpy (digest->buf.md5, in.keymic, 16);

    /* salt */

    salt_t *salt = init_new_salt ();

    salt->salt_plain_buf = mymalloc (36);

    uint salt_plain_len = strlen (in.essid);

    memcpy (salt->salt_plain_buf, in.essid, salt_plain_len);

    salt->salt_plain_len = salt_plain_len;

    salt->wpa = (wpa_t *) mycalloc (1, sizeof (wpa_t));

    wpa_t *wpa = salt->wpa;

    unsigned char *pke_ptr = (unsigned char *) wpa->pke;

    memcpy (pke_ptr, "Pairwise key expansion", 23);

    if (memcmp (in.mac1, in.mac2, 6) < 0)
    {
      memcpy (pke_ptr + 23, in.mac1, 6);
      memcpy (pke_ptr + 29, in.mac2, 6);
    }
    else
    {
      memcpy (pke_ptr + 23, in.mac2, 6);
      memcpy (pke_ptr + 29, in.mac1, 6);
    }

    if (memcmp (in.nonce1, in.nonce2, 32) < 0)
    {
      memcpy (pke_ptr + 35, in.nonce1, 32);
      memcpy (pke_ptr + 67, in.nonce2, 32);
    }
    else
    {
      memcpy (pke_ptr + 35, in.nonce2, 32);
      memcpy (pke_ptr + 67, in.nonce1, 32);
    }

    int i;

    for (i = 0; i < 25; i++)
    {
      BYTESWAP (wpa->pke[i]);
    }

    wpa->keyver = in.keyver;

    if (wpa->keyver > 255)
    {
      log_info ("ATTENTION!");
      log_info ("  The WPA/WPA2 key version in your .hccap file is invalid!");
      log_info ("  This could be due to a recent aircrack-ng bug.");
      log_info ("  The key version was automatically reset to a reasonable value.");
      log_info ("");

      wpa->keyver &= 0xff;
    }

    wpa->eapol_size = in.eapol_size;

    unsigned char *eapol_ptr = (unsigned char *) wpa->eapol;

    memcpy (eapol_ptr, in.eapol, wpa->eapol_size);

    memset (eapol_ptr + wpa->eapol_size, 0, 256 - wpa->eapol_size);

    eapol_ptr[wpa->eapol_size] = (unsigned char) 0x80;

    if (wpa->keyver == 1)
    {
      // nothing to do
    }
    else
    {
      BYTESWAP (digest->buf.md5[0]);
      BYTESWAP (digest->buf.md5[1]);
      BYTESWAP (digest->buf.md5[2]);
      BYTESWAP (digest->buf.md5[3]);

      for (i = 0; i < 64; i++)
      {
        BYTESWAP (wpa->eapol[i]);
      }
    }

    incr_salt_ptrs (db);

    db->salts_buf[db->salts_cnt] = salt;

    db->salts_cnt++;

    /* index */

    if (salt->indexes_buf == NULL)
    {
      salt->indexes_buf = mymalloc (sizeof (index_t *));

      salt->indexes_buf[0] = init_new_index ();

      salt->indexes_cnt++;
    }

    index_t *index = salt->indexes_buf[0];

    incr_digest_ptrs (index);

    index->digests_buf[index->digests_cnt] = digest;

    index->digests_cnt++;

    status_info.proc_hashes++;
  }
  else
  {
    while ((entire_line_len = fgetl (fp, entire_line_buf)) != -1)
    {
      char *hash_buf = NULL;
      char *line_buf = entire_line_buf;
      int   line_len = entire_line_len;
      int   hash_len = 0;

      char *salt_buf = NULL;
      int   salt_len = 0;
      int   result   = 0;

      if (engine_parameter->username == 1)
      {
        int i;

        for (i = 0; *line_buf != engine_parameter->separator && i < line_len; i++) line_buf++;

        if (i == line_len) result = LINE_SEPARATOR_UNMATCHED;
        else
        {
          line_buf += 1;

          line_len -= i + 1;
        }
      }

      if (result == 0)
      {
        result = parse_hash_line (line_buf, line_len, engine_parameter->hash_type, engine_parameter->hash_mode, &hash_buf, &hash_len, engine_parameter->salt_type, &salt_buf, &salt_len, engine_parameter->separator, engine_parameter->hex_salt);
      }

      switch (result)
      {
        case LINE_COMMENT:
          continue;

        case LINE_GLOBAL_ZERO:
          continue;

        case LINE_GLOBAL_LENGTH:
          log_warning ("Skipping line: %s (line length exception)", entire_line_buf);
          continue;

        case LINE_HASH_LENGTH:
          log_warning ("Skipping line: %s (hash length exception)", entire_line_buf);
          continue;

        case LINE_SALT_LENGTH:
          log_warning ("Skipping line: %s (salt length exception)", entire_line_buf);
          continue;

        case LINE_SEPARATOR_UNMATCHED:
          log_warning ("Skipping line: %s (separator unmatched)", entire_line_buf);
          continue;

        case LINE_SIGNATURE_UNMATCHED:
          log_warning ("Skipping line: %s (signature unmatched)", entire_line_buf);
          continue;

        case LINE_HASH_VALUE:
          log_warning ("Skipping line: %s (hash value exception)", entire_line_buf);
          continue;

        case LINE_UNKNOWN_ERROR:
          log_warning ("Skipping line: %s (unknown error)", entire_line_buf);
          continue;
      }

      if ((engine_parameter->hash_type == HASH_TYPE_MD5) && ((engine_parameter->salt_type == SALT_TYPE_NONE) || (engine_parameter->salt_type == SALT_TYPE_EXTERNAL)))
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md5[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md5[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if ((engine_parameter->hash_type == HASH_TYPE_MD5) && (engine_parameter->salt_type == SALT_TYPE_INCLUDED))
      {
        if (strchr (salt_buf, engine_parameter->separator) != NULL) separator_warnings++;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md5[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md5[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        if (engine_parameter->hash_mode == 23)
        {
          memcpy (salt_search->salt_plain_buf + salt_len, "\nskyper\n", 8);

          salt_len += 8;
          salt_search->salt_plain_len = salt_len;
        }

        if (engine_parameter->hash_mode == 2811 || engine_parameter->hash_mode == 3610 || engine_parameter->hash_mode == 3910 ||
            engine_parameter->hash_mode == 3720 || engine_parameter->hash_mode == 3721)
        {
          digest_md5_sse2_t digests;

          digest_t dgst[4];

          plain_t plains[4];

          uint32_t i;

          for (i = 0; i < 4; i += 1)
          {
            memcpy (&plains[i].buf, salt_search->salt_plain_buf, salt_search->salt_plain_len);

            plains[i].len = salt_search->salt_plain_len;
          }

          md5_init_sse2 (&digests);

          md5_final_sse2_max55 (plains, &digests);

          transpose_md5_digest (&digests, dgst);

          BYTESWAP (dgst[0].buf.md5[0]);
          BYTESWAP (dgst[0].buf.md5[1]);
          BYTESWAP (dgst[0].buf.md5[2]);
          BYTESWAP (dgst[0].buf.md5[3]);

          char hex_tmp[4][8];

          uint_to_hex_lower (dgst[0].buf.md5[0], hex_tmp[0]);
          uint_to_hex_lower (dgst[0].buf.md5[1], hex_tmp[1]);
          uint_to_hex_lower (dgst[0].buf.md5[2], hex_tmp[2]);
          uint_to_hex_lower (dgst[0].buf.md5[3], hex_tmp[3]);

          for (i = 0; i < 4; i += 1)
          {
             memcpy (&salt_search->salt_plain_struct[i], hex_tmp[0], 32);

             salt_search->salt_plain_struct[i].len = 32;
          }
        }

        if (engine_parameter->hash_mode == 60)
        {
          uint32_t ipad_dgst[4][4] __attribute__ ((aligned (16)));
          uint32_t opad_dgst[4][4] __attribute__ ((aligned (16)));

          uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
          uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

          uint32_t *salt_ptr = (uint32_t *) salt_search->salt_plain_buf;

          int j;

          for (j = 0; j < 16; j++)
          {
            ipad_buf[j][0] = 0x36363636 ^ salt_ptr[j];
            opad_buf[j][0] = 0x5c5c5c5c ^ salt_ptr[j];
          }

          ipad_dgst[0][0] = MD5M_A;
          ipad_dgst[1][0] = MD5M_B;
          ipad_dgst[2][0] = MD5M_C;
          ipad_dgst[3][0] = MD5M_D;

          opad_dgst[0][0] = MD5M_A;
          opad_dgst[1][0] = MD5M_B;
          opad_dgst[2][0] = MD5M_C;
          opad_dgst[3][0] = MD5M_D;

          hashcat_md5_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
          hashcat_md5_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

          salt_search->ipad_prehashed_buf = mymalloc (16);
          salt_search->opad_prehashed_buf = mymalloc (16);

          salt_search->ipad_prehashed_buf[0] = ipad_dgst[0][0];
          salt_search->ipad_prehashed_buf[1] = ipad_dgst[1][0];
          salt_search->ipad_prehashed_buf[2] = ipad_dgst[2][0];
          salt_search->ipad_prehashed_buf[3] = ipad_dgst[3][0];

          salt_search->opad_prehashed_buf[0] = opad_dgst[0][0];
          salt_search->opad_prehashed_buf[1] = opad_dgst[1][0];
          salt_search->opad_prehashed_buf[2] = opad_dgst[2][0];
          salt_search->opad_prehashed_buf[3] = opad_dgst[3][0];
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if ((engine_parameter->hash_type == HASH_TYPE_SHA1) && ((engine_parameter->salt_type == SALT_TYPE_NONE) || (engine_parameter->salt_type == SALT_TYPE_EXTERNAL)))
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }
        else if ((engine_parameter->hash_mode == 121) && (engine_parameter->salt_type == SALT_TYPE_EXTERNAL))
        {
          // make sure this task is done only ONCE at all!
          uint32_t iterate_max = MIN (3, db->salts_cnt);

          uint32_t i;

          uint32_t not_prehashed_yet = 1;

          // is this check enough ?
          for (i = 0; i < iterate_max; i += 1)
          {
            if (db->salts_buf[i]->salt_plain_struct[0].len > 0)
            {
              not_prehashed_yet = 0;
              break;
            }
          }
          if (not_prehashed_yet == 1)
          {
            // could be a very time intensive task when used w/ a huge list of external salts but we need to populate salt_plain_struct anyway
            uint32_t i;

            for (i = 0; i < db->salts_cnt; i += 1)
            {
              salt_t *salt_tmp = db->salts_buf[i];

              if (salt_tmp == NULL) continue;

              uint32_t salt_len = salt_tmp->salt_plain_len;

              char tolower_tmp[salt_len];

              uint32_t j;

              for (j = 0; j < salt_len; j += 1) tolower_tmp[j] = tolower (salt_tmp->salt_plain_buf[j]);

              for (j = 0; j < 4; j += 1)
              {
                salt_tmp->salt_plain_struct[j].len = salt_len;

                memcpy (&salt_tmp->salt_plain_struct[j], tolower_tmp, salt_len);
              }
            }
          }
        }
        else if ((engine_parameter->hash_mode == 160) && (engine_parameter->salt_type == SALT_TYPE_EXTERNAL))
        {
          // make sure this task is done only ONCE at all!
          uint32_t iterate_max = MIN (3, db->salts_cnt);

          uint32_t i;

          uint32_t not_prehashed_yet = 1;

          // is this check enough ?
          for (i = 0; i < iterate_max; i += 1)
          {
            if (db->salts_buf[i]->salt_plain_struct[0].len > 0)
            {
              not_prehashed_yet = 0;
              break;
            }
          }
          if (not_prehashed_yet == 1)
          {
            // could be a very time intensive task when used w/ a huge list of external salts but we need to populate salt_plain_struct anyway
            uint32_t i;

            for (i = 0; i < db->salts_cnt; i += 1)
            {
              salt_t *salt_tmp = db->salts_buf[i];

              if (salt_tmp == NULL) continue;

              salt_tmp->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

              memset (salt_tmp->salt_prehashed_buf, 0, BLOCK_SIZE);

              memcpy (salt_tmp->salt_prehashed_buf, salt_tmp->salt_plain_buf, salt_tmp->salt_plain_len);

              uint32_t ipad_dgst[5][4] __attribute__ ((aligned (16)));
              uint32_t opad_dgst[5][4] __attribute__ ((aligned (16)));

              uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
              uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

              uint32_t *salt_ptr = (uint32_t *) salt_tmp->salt_plain_buf;

              int j;

              for (j = 0; j < 16; j++)
              {
                ipad_buf[j][0] = 0x36363636 ^ salt_ptr[j];
                opad_buf[j][0] = 0x5c5c5c5c ^ salt_ptr[j];
              }

              ipad_dgst[0][0] = SHA1M_A;
              ipad_dgst[1][0] = SHA1M_B;
              ipad_dgst[2][0] = SHA1M_C;
              ipad_dgst[3][0] = SHA1M_D;
              ipad_dgst[4][0] = SHA1M_E;

              opad_dgst[0][0] = SHA1M_A;
              opad_dgst[1][0] = SHA1M_B;
              opad_dgst[2][0] = SHA1M_C;
              opad_dgst[3][0] = SHA1M_D;
              opad_dgst[4][0] = SHA1M_E;

              hashcat_sha1_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
              hashcat_sha1_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

              salt_tmp->ipad_prehashed_buf = mymalloc (20);
              salt_tmp->opad_prehashed_buf = mymalloc (20);

              salt_tmp->ipad_prehashed_buf[0] = ipad_dgst[0][0];
              salt_tmp->ipad_prehashed_buf[1] = ipad_dgst[1][0];
              salt_tmp->ipad_prehashed_buf[2] = ipad_dgst[2][0];
              salt_tmp->ipad_prehashed_buf[3] = ipad_dgst[3][0];
              salt_tmp->ipad_prehashed_buf[4] = ipad_dgst[4][0];

              salt_tmp->opad_prehashed_buf[0] = opad_dgst[0][0];
              salt_tmp->opad_prehashed_buf[1] = opad_dgst[1][0];
              salt_tmp->opad_prehashed_buf[2] = opad_dgst[2][0];
              salt_tmp->opad_prehashed_buf[3] = opad_dgst[3][0];
              salt_tmp->opad_prehashed_buf[4] = opad_dgst[4][0];
            }
          }
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if ((engine_parameter->hash_type == HASH_TYPE_SHA1) && (engine_parameter->salt_type == SALT_TYPE_INCLUDED))
      {
        if (strchr (salt_buf, engine_parameter->separator) != NULL) separator_warnings++;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf,     salt_buf, salt_len);
        memcpy (salt_search->salt_prehashed_buf, salt_buf, salt_len);

        salt_search->salt_plain_len     = salt_len;
        salt_search->salt_prehashed_len = salt_len;

        if (engine_parameter->hash_mode == 121)
        {
          int i;

          char tolower_tmp[salt_len];

          for (i = 0; i < salt_len; i++) tolower_tmp[i] = tolower (salt_buf[i]);

          for (i = 0; i < 4; i++)
          {
            salt_search->salt_plain_struct[i].len = salt_len;

            memcpy (&salt_search->salt_plain_struct[i], tolower_tmp, salt_len);
          }
        }
        else if (engine_parameter->hash_mode == 160)
        {
          uint32_t ipad_dgst[5][4] __attribute__ ((aligned (16)));
          uint32_t opad_dgst[5][4] __attribute__ ((aligned (16)));

          uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
          uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

          uint32_t *salt_ptr = (uint32_t *) salt_search->salt_plain_buf;

          int j;

          for (j = 0; j < 16; j++)
          {
            ipad_buf[j][0] = 0x36363636 ^ salt_ptr[j];
            opad_buf[j][0] = 0x5c5c5c5c ^ salt_ptr[j];
          }

          ipad_dgst[0][0] = SHA1M_A;
          ipad_dgst[1][0] = SHA1M_B;
          ipad_dgst[2][0] = SHA1M_C;
          ipad_dgst[3][0] = SHA1M_D;
          ipad_dgst[4][0] = SHA1M_E;

          opad_dgst[0][0] = SHA1M_A;
          opad_dgst[1][0] = SHA1M_B;
          opad_dgst[2][0] = SHA1M_C;
          opad_dgst[3][0] = SHA1M_D;
          opad_dgst[4][0] = SHA1M_E;

          hashcat_sha1_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
          hashcat_sha1_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

          salt_search->ipad_prehashed_buf = mymalloc (20);
          salt_search->opad_prehashed_buf = mymalloc (20);

          salt_search->ipad_prehashed_buf[0] = ipad_dgst[0][0];
          salt_search->ipad_prehashed_buf[1] = ipad_dgst[1][0];
          salt_search->ipad_prehashed_buf[2] = ipad_dgst[2][0];
          salt_search->ipad_prehashed_buf[3] = ipad_dgst[3][0];
          salt_search->ipad_prehashed_buf[4] = ipad_dgst[4][0];

          salt_search->opad_prehashed_buf[0] = opad_dgst[0][0];
          salt_search->opad_prehashed_buf[1] = opad_dgst[1][0];
          salt_search->opad_prehashed_buf[2] = opad_dgst[2][0];
          salt_search->opad_prehashed_buf[3] = opad_dgst[3][0];
          salt_search->opad_prehashed_buf[4] = opad_dgst[4][0];
        }
        else if (engine_parameter->hash_mode == 5800 && plains_iteration == NULL)
        {
          typedef struct
          {
            uint dec;
            uint len;

          } plain_iterator_entry_t;

          plain_iterator_entry_t items[1024] =
          {
            {0x00000030, 1}, {0x00000031, 1}, {0x00000032, 1}, {0x00000033, 1}, {0x00000034, 1}, {0x00000035, 1}, {0x00000036, 1}, {0x00000037, 1},
            {0x00000038, 1}, {0x00000039, 1}, {0x00003031, 2}, {0x00003131, 2}, {0x00003231, 2}, {0x00003331, 2}, {0x00003431, 2}, {0x00003531, 2},
            {0x00003631, 2}, {0x00003731, 2}, {0x00003831, 2}, {0x00003931, 2}, {0x00003032, 2}, {0x00003132, 2}, {0x00003232, 2}, {0x00003332, 2},
            {0x00003432, 2}, {0x00003532, 2}, {0x00003632, 2}, {0x00003732, 2}, {0x00003832, 2}, {0x00003932, 2}, {0x00003033, 2}, {0x00003133, 2},
            {0x00003233, 2}, {0x00003333, 2}, {0x00003433, 2}, {0x00003533, 2}, {0x00003633, 2}, {0x00003733, 2}, {0x00003833, 2}, {0x00003933, 2},
            {0x00003034, 2}, {0x00003134, 2}, {0x00003234, 2}, {0x00003334, 2}, {0x00003434, 2}, {0x00003534, 2}, {0x00003634, 2}, {0x00003734, 2},
            {0x00003834, 2}, {0x00003934, 2}, {0x00003035, 2}, {0x00003135, 2}, {0x00003235, 2}, {0x00003335, 2}, {0x00003435, 2}, {0x00003535, 2},
            {0x00003635, 2}, {0x00003735, 2}, {0x00003835, 2}, {0x00003935, 2}, {0x00003036, 2}, {0x00003136, 2}, {0x00003236, 2}, {0x00003336, 2},
            {0x00003436, 2}, {0x00003536, 2}, {0x00003636, 2}, {0x00003736, 2}, {0x00003836, 2}, {0x00003936, 2}, {0x00003037, 2}, {0x00003137, 2},
            {0x00003237, 2}, {0x00003337, 2}, {0x00003437, 2}, {0x00003537, 2}, {0x00003637, 2}, {0x00003737, 2}, {0x00003837, 2}, {0x00003937, 2},
            {0x00003038, 2}, {0x00003138, 2}, {0x00003238, 2}, {0x00003338, 2}, {0x00003438, 2}, {0x00003538, 2}, {0x00003638, 2}, {0x00003738, 2},
            {0x00003838, 2}, {0x00003938, 2}, {0x00003039, 2}, {0x00003139, 2}, {0x00003239, 2}, {0x00003339, 2}, {0x00003439, 2}, {0x00003539, 2},
            {0x00003639, 2}, {0x00003739, 2}, {0x00003839, 2}, {0x00003939, 2}, {0x00303031, 3}, {0x00313031, 3}, {0x00323031, 3}, {0x00333031, 3},
            {0x00343031, 3}, {0x00353031, 3}, {0x00363031, 3}, {0x00373031, 3}, {0x00383031, 3}, {0x00393031, 3}, {0x00303131, 3}, {0x00313131, 3},
            {0x00323131, 3}, {0x00333131, 3}, {0x00343131, 3}, {0x00353131, 3}, {0x00363131, 3}, {0x00373131, 3}, {0x00383131, 3}, {0x00393131, 3},
            {0x00303231, 3}, {0x00313231, 3}, {0x00323231, 3}, {0x00333231, 3}, {0x00343231, 3}, {0x00353231, 3}, {0x00363231, 3}, {0x00373231, 3},
            {0x00383231, 3}, {0x00393231, 3}, {0x00303331, 3}, {0x00313331, 3}, {0x00323331, 3}, {0x00333331, 3}, {0x00343331, 3}, {0x00353331, 3},
            {0x00363331, 3}, {0x00373331, 3}, {0x00383331, 3}, {0x00393331, 3}, {0x00303431, 3}, {0x00313431, 3}, {0x00323431, 3}, {0x00333431, 3},
            {0x00343431, 3}, {0x00353431, 3}, {0x00363431, 3}, {0x00373431, 3}, {0x00383431, 3}, {0x00393431, 3}, {0x00303531, 3}, {0x00313531, 3},
            {0x00323531, 3}, {0x00333531, 3}, {0x00343531, 3}, {0x00353531, 3}, {0x00363531, 3}, {0x00373531, 3}, {0x00383531, 3}, {0x00393531, 3},
            {0x00303631, 3}, {0x00313631, 3}, {0x00323631, 3}, {0x00333631, 3}, {0x00343631, 3}, {0x00353631, 3}, {0x00363631, 3}, {0x00373631, 3},
            {0x00383631, 3}, {0x00393631, 3}, {0x00303731, 3}, {0x00313731, 3}, {0x00323731, 3}, {0x00333731, 3}, {0x00343731, 3}, {0x00353731, 3},
            {0x00363731, 3}, {0x00373731, 3}, {0x00383731, 3}, {0x00393731, 3}, {0x00303831, 3}, {0x00313831, 3}, {0x00323831, 3}, {0x00333831, 3},
            {0x00343831, 3}, {0x00353831, 3}, {0x00363831, 3}, {0x00373831, 3}, {0x00383831, 3}, {0x00393831, 3}, {0x00303931, 3}, {0x00313931, 3},
            {0x00323931, 3}, {0x00333931, 3}, {0x00343931, 3}, {0x00353931, 3}, {0x00363931, 3}, {0x00373931, 3}, {0x00383931, 3}, {0x00393931, 3},
            {0x00303032, 3}, {0x00313032, 3}, {0x00323032, 3}, {0x00333032, 3}, {0x00343032, 3}, {0x00353032, 3}, {0x00363032, 3}, {0x00373032, 3},
            {0x00383032, 3}, {0x00393032, 3}, {0x00303132, 3}, {0x00313132, 3}, {0x00323132, 3}, {0x00333132, 3}, {0x00343132, 3}, {0x00353132, 3},
            {0x00363132, 3}, {0x00373132, 3}, {0x00383132, 3}, {0x00393132, 3}, {0x00303232, 3}, {0x00313232, 3}, {0x00323232, 3}, {0x00333232, 3},
            {0x00343232, 3}, {0x00353232, 3}, {0x00363232, 3}, {0x00373232, 3}, {0x00383232, 3}, {0x00393232, 3}, {0x00303332, 3}, {0x00313332, 3},
            {0x00323332, 3}, {0x00333332, 3}, {0x00343332, 3}, {0x00353332, 3}, {0x00363332, 3}, {0x00373332, 3}, {0x00383332, 3}, {0x00393332, 3},
            {0x00303432, 3}, {0x00313432, 3}, {0x00323432, 3}, {0x00333432, 3}, {0x00343432, 3}, {0x00353432, 3}, {0x00363432, 3}, {0x00373432, 3},
            {0x00383432, 3}, {0x00393432, 3}, {0x00303532, 3}, {0x00313532, 3}, {0x00323532, 3}, {0x00333532, 3}, {0x00343532, 3}, {0x00353532, 3},
            {0x00363532, 3}, {0x00373532, 3}, {0x00383532, 3}, {0x00393532, 3}, {0x00303632, 3}, {0x00313632, 3}, {0x00323632, 3}, {0x00333632, 3},
            {0x00343632, 3}, {0x00353632, 3}, {0x00363632, 3}, {0x00373632, 3}, {0x00383632, 3}, {0x00393632, 3}, {0x00303732, 3}, {0x00313732, 3},
            {0x00323732, 3}, {0x00333732, 3}, {0x00343732, 3}, {0x00353732, 3}, {0x00363732, 3}, {0x00373732, 3}, {0x00383732, 3}, {0x00393732, 3},
            {0x00303832, 3}, {0x00313832, 3}, {0x00323832, 3}, {0x00333832, 3}, {0x00343832, 3}, {0x00353832, 3}, {0x00363832, 3}, {0x00373832, 3},
            {0x00383832, 3}, {0x00393832, 3}, {0x00303932, 3}, {0x00313932, 3}, {0x00323932, 3}, {0x00333932, 3}, {0x00343932, 3}, {0x00353932, 3},
            {0x00363932, 3}, {0x00373932, 3}, {0x00383932, 3}, {0x00393932, 3}, {0x00303033, 3}, {0x00313033, 3}, {0x00323033, 3}, {0x00333033, 3},
            {0x00343033, 3}, {0x00353033, 3}, {0x00363033, 3}, {0x00373033, 3}, {0x00383033, 3}, {0x00393033, 3}, {0x00303133, 3}, {0x00313133, 3},
            {0x00323133, 3}, {0x00333133, 3}, {0x00343133, 3}, {0x00353133, 3}, {0x00363133, 3}, {0x00373133, 3}, {0x00383133, 3}, {0x00393133, 3},
            {0x00303233, 3}, {0x00313233, 3}, {0x00323233, 3}, {0x00333233, 3}, {0x00343233, 3}, {0x00353233, 3}, {0x00363233, 3}, {0x00373233, 3},
            {0x00383233, 3}, {0x00393233, 3}, {0x00303333, 3}, {0x00313333, 3}, {0x00323333, 3}, {0x00333333, 3}, {0x00343333, 3}, {0x00353333, 3},
            {0x00363333, 3}, {0x00373333, 3}, {0x00383333, 3}, {0x00393333, 3}, {0x00303433, 3}, {0x00313433, 3}, {0x00323433, 3}, {0x00333433, 3},
            {0x00343433, 3}, {0x00353433, 3}, {0x00363433, 3}, {0x00373433, 3}, {0x00383433, 3}, {0x00393433, 3}, {0x00303533, 3}, {0x00313533, 3},
            {0x00323533, 3}, {0x00333533, 3}, {0x00343533, 3}, {0x00353533, 3}, {0x00363533, 3}, {0x00373533, 3}, {0x00383533, 3}, {0x00393533, 3},
            {0x00303633, 3}, {0x00313633, 3}, {0x00323633, 3}, {0x00333633, 3}, {0x00343633, 3}, {0x00353633, 3}, {0x00363633, 3}, {0x00373633, 3},
            {0x00383633, 3}, {0x00393633, 3}, {0x00303733, 3}, {0x00313733, 3}, {0x00323733, 3}, {0x00333733, 3}, {0x00343733, 3}, {0x00353733, 3},
            {0x00363733, 3}, {0x00373733, 3}, {0x00383733, 3}, {0x00393733, 3}, {0x00303833, 3}, {0x00313833, 3}, {0x00323833, 3}, {0x00333833, 3},
            {0x00343833, 3}, {0x00353833, 3}, {0x00363833, 3}, {0x00373833, 3}, {0x00383833, 3}, {0x00393833, 3}, {0x00303933, 3}, {0x00313933, 3},
            {0x00323933, 3}, {0x00333933, 3}, {0x00343933, 3}, {0x00353933, 3}, {0x00363933, 3}, {0x00373933, 3}, {0x00383933, 3}, {0x00393933, 3},
            {0x00303034, 3}, {0x00313034, 3}, {0x00323034, 3}, {0x00333034, 3}, {0x00343034, 3}, {0x00353034, 3}, {0x00363034, 3}, {0x00373034, 3},
            {0x00383034, 3}, {0x00393034, 3}, {0x00303134, 3}, {0x00313134, 3}, {0x00323134, 3}, {0x00333134, 3}, {0x00343134, 3}, {0x00353134, 3},
            {0x00363134, 3}, {0x00373134, 3}, {0x00383134, 3}, {0x00393134, 3}, {0x00303234, 3}, {0x00313234, 3}, {0x00323234, 3}, {0x00333234, 3},
            {0x00343234, 3}, {0x00353234, 3}, {0x00363234, 3}, {0x00373234, 3}, {0x00383234, 3}, {0x00393234, 3}, {0x00303334, 3}, {0x00313334, 3},
            {0x00323334, 3}, {0x00333334, 3}, {0x00343334, 3}, {0x00353334, 3}, {0x00363334, 3}, {0x00373334, 3}, {0x00383334, 3}, {0x00393334, 3},
            {0x00303434, 3}, {0x00313434, 3}, {0x00323434, 3}, {0x00333434, 3}, {0x00343434, 3}, {0x00353434, 3}, {0x00363434, 3}, {0x00373434, 3},
            {0x00383434, 3}, {0x00393434, 3}, {0x00303534, 3}, {0x00313534, 3}, {0x00323534, 3}, {0x00333534, 3}, {0x00343534, 3}, {0x00353534, 3},
            {0x00363534, 3}, {0x00373534, 3}, {0x00383534, 3}, {0x00393534, 3}, {0x00303634, 3}, {0x00313634, 3}, {0x00323634, 3}, {0x00333634, 3},
            {0x00343634, 3}, {0x00353634, 3}, {0x00363634, 3}, {0x00373634, 3}, {0x00383634, 3}, {0x00393634, 3}, {0x00303734, 3}, {0x00313734, 3},
            {0x00323734, 3}, {0x00333734, 3}, {0x00343734, 3}, {0x00353734, 3}, {0x00363734, 3}, {0x00373734, 3}, {0x00383734, 3}, {0x00393734, 3},
            {0x00303834, 3}, {0x00313834, 3}, {0x00323834, 3}, {0x00333834, 3}, {0x00343834, 3}, {0x00353834, 3}, {0x00363834, 3}, {0x00373834, 3},
            {0x00383834, 3}, {0x00393834, 3}, {0x00303934, 3}, {0x00313934, 3}, {0x00323934, 3}, {0x00333934, 3}, {0x00343934, 3}, {0x00353934, 3},
            {0x00363934, 3}, {0x00373934, 3}, {0x00383934, 3}, {0x00393934, 3}, {0x00303035, 3}, {0x00313035, 3}, {0x00323035, 3}, {0x00333035, 3},
            {0x00343035, 3}, {0x00353035, 3}, {0x00363035, 3}, {0x00373035, 3}, {0x00383035, 3}, {0x00393035, 3}, {0x00303135, 3}, {0x00313135, 3},
            {0x00323135, 3}, {0x00333135, 3}, {0x00343135, 3}, {0x00353135, 3}, {0x00363135, 3}, {0x00373135, 3}, {0x00383135, 3}, {0x00393135, 3},
            {0x00303235, 3}, {0x00313235, 3}, {0x00323235, 3}, {0x00333235, 3}, {0x00343235, 3}, {0x00353235, 3}, {0x00363235, 3}, {0x00373235, 3},
            {0x00383235, 3}, {0x00393235, 3}, {0x00303335, 3}, {0x00313335, 3}, {0x00323335, 3}, {0x00333335, 3}, {0x00343335, 3}, {0x00353335, 3},
            {0x00363335, 3}, {0x00373335, 3}, {0x00383335, 3}, {0x00393335, 3}, {0x00303435, 3}, {0x00313435, 3}, {0x00323435, 3}, {0x00333435, 3},
            {0x00343435, 3}, {0x00353435, 3}, {0x00363435, 3}, {0x00373435, 3}, {0x00383435, 3}, {0x00393435, 3}, {0x00303535, 3}, {0x00313535, 3},
            {0x00323535, 3}, {0x00333535, 3}, {0x00343535, 3}, {0x00353535, 3}, {0x00363535, 3}, {0x00373535, 3}, {0x00383535, 3}, {0x00393535, 3},
            {0x00303635, 3}, {0x00313635, 3}, {0x00323635, 3}, {0x00333635, 3}, {0x00343635, 3}, {0x00353635, 3}, {0x00363635, 3}, {0x00373635, 3},
            {0x00383635, 3}, {0x00393635, 3}, {0x00303735, 3}, {0x00313735, 3}, {0x00323735, 3}, {0x00333735, 3}, {0x00343735, 3}, {0x00353735, 3},
            {0x00363735, 3}, {0x00373735, 3}, {0x00383735, 3}, {0x00393735, 3}, {0x00303835, 3}, {0x00313835, 3}, {0x00323835, 3}, {0x00333835, 3},
            {0x00343835, 3}, {0x00353835, 3}, {0x00363835, 3}, {0x00373835, 3}, {0x00383835, 3}, {0x00393835, 3}, {0x00303935, 3}, {0x00313935, 3},
            {0x00323935, 3}, {0x00333935, 3}, {0x00343935, 3}, {0x00353935, 3}, {0x00363935, 3}, {0x00373935, 3}, {0x00383935, 3}, {0x00393935, 3},
            {0x00303036, 3}, {0x00313036, 3}, {0x00323036, 3}, {0x00333036, 3}, {0x00343036, 3}, {0x00353036, 3}, {0x00363036, 3}, {0x00373036, 3},
            {0x00383036, 3}, {0x00393036, 3}, {0x00303136, 3}, {0x00313136, 3}, {0x00323136, 3}, {0x00333136, 3}, {0x00343136, 3}, {0x00353136, 3},
            {0x00363136, 3}, {0x00373136, 3}, {0x00383136, 3}, {0x00393136, 3}, {0x00303236, 3}, {0x00313236, 3}, {0x00323236, 3}, {0x00333236, 3},
            {0x00343236, 3}, {0x00353236, 3}, {0x00363236, 3}, {0x00373236, 3}, {0x00383236, 3}, {0x00393236, 3}, {0x00303336, 3}, {0x00313336, 3},
            {0x00323336, 3}, {0x00333336, 3}, {0x00343336, 3}, {0x00353336, 3}, {0x00363336, 3}, {0x00373336, 3}, {0x00383336, 3}, {0x00393336, 3},
            {0x00303436, 3}, {0x00313436, 3}, {0x00323436, 3}, {0x00333436, 3}, {0x00343436, 3}, {0x00353436, 3}, {0x00363436, 3}, {0x00373436, 3},
            {0x00383436, 3}, {0x00393436, 3}, {0x00303536, 3}, {0x00313536, 3}, {0x00323536, 3}, {0x00333536, 3}, {0x00343536, 3}, {0x00353536, 3},
            {0x00363536, 3}, {0x00373536, 3}, {0x00383536, 3}, {0x00393536, 3}, {0x00303636, 3}, {0x00313636, 3}, {0x00323636, 3}, {0x00333636, 3},
            {0x00343636, 3}, {0x00353636, 3}, {0x00363636, 3}, {0x00373636, 3}, {0x00383636, 3}, {0x00393636, 3}, {0x00303736, 3}, {0x00313736, 3},
            {0x00323736, 3}, {0x00333736, 3}, {0x00343736, 3}, {0x00353736, 3}, {0x00363736, 3}, {0x00373736, 3}, {0x00383736, 3}, {0x00393736, 3},
            {0x00303836, 3}, {0x00313836, 3}, {0x00323836, 3}, {0x00333836, 3}, {0x00343836, 3}, {0x00353836, 3}, {0x00363836, 3}, {0x00373836, 3},
            {0x00383836, 3}, {0x00393836, 3}, {0x00303936, 3}, {0x00313936, 3}, {0x00323936, 3}, {0x00333936, 3}, {0x00343936, 3}, {0x00353936, 3},
            {0x00363936, 3}, {0x00373936, 3}, {0x00383936, 3}, {0x00393936, 3}, {0x00303037, 3}, {0x00313037, 3}, {0x00323037, 3}, {0x00333037, 3},
            {0x00343037, 3}, {0x00353037, 3}, {0x00363037, 3}, {0x00373037, 3}, {0x00383037, 3}, {0x00393037, 3}, {0x00303137, 3}, {0x00313137, 3},
            {0x00323137, 3}, {0x00333137, 3}, {0x00343137, 3}, {0x00353137, 3}, {0x00363137, 3}, {0x00373137, 3}, {0x00383137, 3}, {0x00393137, 3},
            {0x00303237, 3}, {0x00313237, 3}, {0x00323237, 3}, {0x00333237, 3}, {0x00343237, 3}, {0x00353237, 3}, {0x00363237, 3}, {0x00373237, 3},
            {0x00383237, 3}, {0x00393237, 3}, {0x00303337, 3}, {0x00313337, 3}, {0x00323337, 3}, {0x00333337, 3}, {0x00343337, 3}, {0x00353337, 3},
            {0x00363337, 3}, {0x00373337, 3}, {0x00383337, 3}, {0x00393337, 3}, {0x00303437, 3}, {0x00313437, 3}, {0x00323437, 3}, {0x00333437, 3},
            {0x00343437, 3}, {0x00353437, 3}, {0x00363437, 3}, {0x00373437, 3}, {0x00383437, 3}, {0x00393437, 3}, {0x00303537, 3}, {0x00313537, 3},
            {0x00323537, 3}, {0x00333537, 3}, {0x00343537, 3}, {0x00353537, 3}, {0x00363537, 3}, {0x00373537, 3}, {0x00383537, 3}, {0x00393537, 3},
            {0x00303637, 3}, {0x00313637, 3}, {0x00323637, 3}, {0x00333637, 3}, {0x00343637, 3}, {0x00353637, 3}, {0x00363637, 3}, {0x00373637, 3},
            {0x00383637, 3}, {0x00393637, 3}, {0x00303737, 3}, {0x00313737, 3}, {0x00323737, 3}, {0x00333737, 3}, {0x00343737, 3}, {0x00353737, 3},
            {0x00363737, 3}, {0x00373737, 3}, {0x00383737, 3}, {0x00393737, 3}, {0x00303837, 3}, {0x00313837, 3}, {0x00323837, 3}, {0x00333837, 3},
            {0x00343837, 3}, {0x00353837, 3}, {0x00363837, 3}, {0x00373837, 3}, {0x00383837, 3}, {0x00393837, 3}, {0x00303937, 3}, {0x00313937, 3},
            {0x00323937, 3}, {0x00333937, 3}, {0x00343937, 3}, {0x00353937, 3}, {0x00363937, 3}, {0x00373937, 3}, {0x00383937, 3}, {0x00393937, 3},
            {0x00303038, 3}, {0x00313038, 3}, {0x00323038, 3}, {0x00333038, 3}, {0x00343038, 3}, {0x00353038, 3}, {0x00363038, 3}, {0x00373038, 3},
            {0x00383038, 3}, {0x00393038, 3}, {0x00303138, 3}, {0x00313138, 3}, {0x00323138, 3}, {0x00333138, 3}, {0x00343138, 3}, {0x00353138, 3},
            {0x00363138, 3}, {0x00373138, 3}, {0x00383138, 3}, {0x00393138, 3}, {0x00303238, 3}, {0x00313238, 3}, {0x00323238, 3}, {0x00333238, 3},
            {0x00343238, 3}, {0x00353238, 3}, {0x00363238, 3}, {0x00373238, 3}, {0x00383238, 3}, {0x00393238, 3}, {0x00303338, 3}, {0x00313338, 3},
            {0x00323338, 3}, {0x00333338, 3}, {0x00343338, 3}, {0x00353338, 3}, {0x00363338, 3}, {0x00373338, 3}, {0x00383338, 3}, {0x00393338, 3},
            {0x00303438, 3}, {0x00313438, 3}, {0x00323438, 3}, {0x00333438, 3}, {0x00343438, 3}, {0x00353438, 3}, {0x00363438, 3}, {0x00373438, 3},
            {0x00383438, 3}, {0x00393438, 3}, {0x00303538, 3}, {0x00313538, 3}, {0x00323538, 3}, {0x00333538, 3}, {0x00343538, 3}, {0x00353538, 3},
            {0x00363538, 3}, {0x00373538, 3}, {0x00383538, 3}, {0x00393538, 3}, {0x00303638, 3}, {0x00313638, 3}, {0x00323638, 3}, {0x00333638, 3},
            {0x00343638, 3}, {0x00353638, 3}, {0x00363638, 3}, {0x00373638, 3}, {0x00383638, 3}, {0x00393638, 3}, {0x00303738, 3}, {0x00313738, 3},
            {0x00323738, 3}, {0x00333738, 3}, {0x00343738, 3}, {0x00353738, 3}, {0x00363738, 3}, {0x00373738, 3}, {0x00383738, 3}, {0x00393738, 3},
            {0x00303838, 3}, {0x00313838, 3}, {0x00323838, 3}, {0x00333838, 3}, {0x00343838, 3}, {0x00353838, 3}, {0x00363838, 3}, {0x00373838, 3},
            {0x00383838, 3}, {0x00393838, 3}, {0x00303938, 3}, {0x00313938, 3}, {0x00323938, 3}, {0x00333938, 3}, {0x00343938, 3}, {0x00353938, 3},
            {0x00363938, 3}, {0x00373938, 3}, {0x00383938, 3}, {0x00393938, 3}, {0x00303039, 3}, {0x00313039, 3}, {0x00323039, 3}, {0x00333039, 3},
            {0x00343039, 3}, {0x00353039, 3}, {0x00363039, 3}, {0x00373039, 3}, {0x00383039, 3}, {0x00393039, 3}, {0x00303139, 3}, {0x00313139, 3},
            {0x00323139, 3}, {0x00333139, 3}, {0x00343139, 3}, {0x00353139, 3}, {0x00363139, 3}, {0x00373139, 3}, {0x00383139, 3}, {0x00393139, 3},
            {0x00303239, 3}, {0x00313239, 3}, {0x00323239, 3}, {0x00333239, 3}, {0x00343239, 3}, {0x00353239, 3}, {0x00363239, 3}, {0x00373239, 3},
            {0x00383239, 3}, {0x00393239, 3}, {0x00303339, 3}, {0x00313339, 3}, {0x00323339, 3}, {0x00333339, 3}, {0x00343339, 3}, {0x00353339, 3},
            {0x00363339, 3}, {0x00373339, 3}, {0x00383339, 3}, {0x00393339, 3}, {0x00303439, 3}, {0x00313439, 3}, {0x00323439, 3}, {0x00333439, 3},
            {0x00343439, 3}, {0x00353439, 3}, {0x00363439, 3}, {0x00373439, 3}, {0x00383439, 3}, {0x00393439, 3}, {0x00303539, 3}, {0x00313539, 3},
            {0x00323539, 3}, {0x00333539, 3}, {0x00343539, 3}, {0x00353539, 3}, {0x00363539, 3}, {0x00373539, 3}, {0x00383539, 3}, {0x00393539, 3},
            {0x00303639, 3}, {0x00313639, 3}, {0x00323639, 3}, {0x00333639, 3}, {0x00343639, 3}, {0x00353639, 3}, {0x00363639, 3}, {0x00373639, 3},
            {0x00383639, 3}, {0x00393639, 3}, {0x00303739, 3}, {0x00313739, 3}, {0x00323739, 3}, {0x00333739, 3}, {0x00343739, 3}, {0x00353739, 3},
            {0x00363739, 3}, {0x00373739, 3}, {0x00383739, 3}, {0x00393739, 3}, {0x00303839, 3}, {0x00313839, 3}, {0x00323839, 3}, {0x00333839, 3},
            {0x00343839, 3}, {0x00353839, 3}, {0x00363839, 3}, {0x00373839, 3}, {0x00383839, 3}, {0x00393839, 3}, {0x00303939, 3}, {0x00313939, 3},
            {0x00323939, 3}, {0x00333939, 3}, {0x00343939, 3}, {0x00353939, 3}, {0x00363939, 3}, {0x00373939, 3}, {0x00383939, 3}, {0x00393939, 3},
            {0x30303031, 4}, {0x31303031, 4}, {0x32303031, 4}, {0x33303031, 4}, {0x34303031, 4}, {0x35303031, 4}, {0x36303031, 4}, {0x37303031, 4},
            {0x38303031, 4}, {0x39303031, 4}, {0x30313031, 4}, {0x31313031, 4}, {0x32313031, 4}, {0x33313031, 4}, {0x34313031, 4}, {0x35313031, 4},
            {0x36313031, 4}, {0x37313031, 4}, {0x38313031, 4}, {0x39313031, 4}, {0x30323031, 4}, {0x31323031, 4}, {0x32323031, 4}, {0x33323031, 4},
          };

          plains_iteration = malloc (1024 * sizeof (plain_t*));

          uint32_t i;

          for (i = 0; i < 1024; i++)
          {
            plains_iteration[i] = malloc (4 * sizeof (plain_t));
            plains_iteration[i][0].buf[0] = items[i].dec;
            plains_iteration[i][0].len = items[i].len;
            plains_iteration[i][1].buf[0] = items[i].dec;
            plains_iteration[i][1].len = items[i].len;
            plains_iteration[i][2].buf[0] = items[i].dec;
            plains_iteration[i][2].len = items[i].len;
            plains_iteration[i][3].buf[0] = items[i].dec;
            plains_iteration[i][3].len = items[i].len;
          }
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt_pre)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt_pre);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MYSQL)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.mysql[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.mysql[1] = hex_to_uint (&hash_buf[8]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.mysql[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.mysql[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.mysql[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_PHPASS)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        phpass_decode ((unsigned char *) &digest->buf.md5, (unsigned char *) hash_buf);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);
        salt_search->signature = mymalloc (PHPASS_SIGN + 1);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);
        memset (salt_search->signature, 0, PHPASS_SIGN + 1);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);
        memcpy (salt_search->signature, line_buf, PHPASS_SIGN);

        salt_search->iterations = 1u << base64b_char2int (line_buf[PHPASS_SIGN]);

        salt_search->salt_plain_len = salt_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MD5UNIX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        md5unix_decode ((unsigned char *) &digest->buf.md5, (unsigned char *) hash_buf);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        if (memcmp (line_buf + MD5UNIX_SIGN, "rounds=", 7) == 0)
        {
          int iter;

          char *iter_buf = line_buf + MD5UNIX_SIGN + 7;

          for (iter = 0; *iter_buf >= '0' && *iter_buf <= '9' && iter < 7; iter_buf += 1, iter += 1) continue;

          *iter_buf = 0x0;

          salt_search->iterations = atoi (line_buf + MD5UNIX_SIGN + 7);
        }
        else
        {
          salt_search->iterations = MD5UNIX_ROUNDS;
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MD5SUN)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        md5sun_decode ((unsigned char *) &digest->buf.md5, (unsigned char *) hash_buf);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        int iter;

        char *iter_buf = line_buf + MD5SUN_SIGN + 8;

        for (iter = 0; *iter_buf >= '0' && *iter_buf <= '9' && iter < 7; iter_buf += 1, iter += 1) continue;

        *iter_buf = 0x0;

        salt_search->iterations = atoi (line_buf + MD5SUN_SIGN + 8) + MD5SUN_ROUNDS_MIN;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA1B64)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        sha1b64_decode ((unsigned char *) &digest->buf.sha1, (unsigned char *) hash_buf);

        BYTESWAP (digest->buf.sha1[0]);
        BYTESWAP (digest->buf.sha1[1]);
        BYTESWAP (digest->buf.sha1[2]);
        BYTESWAP (digest->buf.sha1[3]);
        BYTESWAP (digest->buf.sha1[4]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA1B64S)
      {
        /* salt 1 */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        /* digest */

        digest_t *digest = init_new_digest ();

        sha1b64s_decode ((unsigned char *) &digest->buf.sha1, (unsigned char *) salt_search->salt_plain_buf, line_len - SHA1B64S_SIGN, &salt_search->salt_plain_len, hash_buf);

        BYTESWAP (digest->buf.sha1[0]);
        BYTESWAP (digest->buf.sha1[1]);
        BYTESWAP (digest->buf.sha1[2]);
        BYTESWAP (digest->buf.sha1[3]);
        BYTESWAP (digest->buf.sha1[4]);

        /* salt 2 */

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MD4)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md4[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md4[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md4[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md4[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md4[0]);
        BYTESWAP (digest->buf.md4[1]);
        BYTESWAP (digest->buf.md4[2]);
        BYTESWAP (digest->buf.md4[3]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.md4[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.md4[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.md4[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_DCC)
      {
        if (strchr (salt_buf, engine_parameter->separator) != NULL) separator_warnings++;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md4[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md4[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md4[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md4[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md4[0]);
        BYTESWAP (digest->buf.md4[1]);
        BYTESWAP (digest->buf.md4[2]);
        BYTESWAP (digest->buf.md4[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        /* precompute salt */

        int p;

        for (p = 0; p < salt_len; p++) salt_search->salt_prehashed_buf[p * 2] = tolower (salt_search->salt_plain_buf[p]);

        salt_search->salt_prehashed_len = salt_len * 2;

        // fill salt_plain_struct

        for (p = 0; p < 4; p++)
        {
          salt_search->salt_plain_struct[p].len = salt_search->salt_prehashed_len;

          memcpy (&salt_search->salt_plain_struct[p], salt_search->salt_prehashed_buf, salt_search->salt_prehashed_len);
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MD5CHAP)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md5[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md5[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        uint32_t tmp[4];

        tmp[0] = hex_to_uint (&salt_buf[0]);
        tmp[1] = hex_to_uint (&salt_buf[8]);
        tmp[2] = hex_to_uint (&salt_buf[16]);
        tmp[3] = hex_to_uint (&salt_buf[24]);

        BYTESWAP (tmp[0]);
        BYTESWAP (tmp[1]);
        BYTESWAP (tmp[2]);
        BYTESWAP (tmp[3]);

        salt_search->md5chap_idbyte = hex_to_char (&line_buf[66]);

        memcpy (salt_search->salt_plain_buf, tmp, 16);

        salt_search->salt_plain_len = 16;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MSSQL2000)
      {
        if (strchr (salt_buf, engine_parameter->separator) != NULL) separator_warnings++;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[40]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[48]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[56]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[64]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[72]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        uint32_t *hsalt = (uint32_t *) salt_search->salt_plain_buf;

        *hsalt = hex_to_uint (salt_buf);

        BYTESWAP (*hsalt);

        salt_search->salt_plain_len = 4;

        uint32_t *hdigest = (uint32_t *) salt_search->salt_prehashed_buf;

        hdigest[0] = hex_to_uint (&hash_buf[0]);
        hdigest[1] = hex_to_uint (&hash_buf[8]);
        hdigest[2] = hex_to_uint (&hash_buf[16]);
        hdigest[3] = hex_to_uint (&hash_buf[24]);
        hdigest[4] = hex_to_uint (&hash_buf[32]);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MSSQL2005)
      {
        if (strchr (salt_buf, engine_parameter->separator) != NULL) separator_warnings++;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        uint32_t *hsalt = (uint32_t *) salt_search->salt_plain_buf;

        *hsalt = hex_to_uint (salt_buf);

        BYTESWAP (*hsalt);

        salt_search->salt_plain_len = 4;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_EPIV6)
      {
        char tmp_buf[100];

        /* digest */

        digest_t *digest = init_new_digest ();

        memset (tmp_buf, 0, sizeof (tmp_buf));

        base64_decode (base64_to_int, hash_buf, 28, tmp_buf);

        memcpy (digest->buf.sha1, tmp_buf, 20);

        BYTESWAP (digest->buf.sha1[0]);
        BYTESWAP (digest->buf.sha1[1]);
        BYTESWAP (digest->buf.sha1[2]);
        BYTESWAP (digest->buf.sha1[3]);
        BYTESWAP (digest->buf.sha1[4]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memset (tmp_buf, 0, sizeof (tmp_buf));

        int tmp_len = base64_decode (base64_to_int, salt_buf, salt_len, tmp_buf);

        memcpy (salt_search->salt_plain_buf, tmp_buf, tmp_len);

        salt_search->salt_plain_len = tmp_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if ((engine_parameter->hash_type == HASH_TYPE_SHA256) && ((engine_parameter->salt_type == SALT_TYPE_NONE) || (engine_parameter->salt_type == SALT_TYPE_EXTERNAL)))
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha256[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha256[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha256[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha256[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha256[4] = hex_to_uint (&hash_buf[32]);
        digest->buf.sha256[5] = hex_to_uint (&hash_buf[40]);
        digest->buf.sha256[6] = hex_to_uint (&hash_buf[48]);
        digest->buf.sha256[7] = hex_to_uint (&hash_buf[56]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if ((engine_parameter->hash_type == HASH_TYPE_SHA256) && (engine_parameter->salt_type == SALT_TYPE_INCLUDED))
      {
        if (strchr (salt_buf, engine_parameter->separator) != NULL) separator_warnings++;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha256[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha256[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha256[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha256[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha256[4] = hex_to_uint (&hash_buf[32]);
        digest->buf.sha256[5] = hex_to_uint (&hash_buf[40]);
        digest->buf.sha256[6] = hex_to_uint (&hash_buf[48]);
        digest->buf.sha256[7] = hex_to_uint (&hash_buf[56]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf,     salt_buf, salt_len);
        memcpy (salt_search->salt_prehashed_buf, salt_buf, salt_len);

        salt_search->salt_plain_len     = salt_len;
        salt_search->salt_prehashed_len = salt_len;

        if (engine_parameter->hash_mode == 1460)
        {
          uint32_t ipad_dgst[8][4] __attribute__ ((aligned (16)));
          uint32_t opad_dgst[8][4] __attribute__ ((aligned (16)));

          uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
          uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

          uint32_t *salt_ptr = (uint32_t *) salt_search->salt_plain_buf;

          int j;

          for (j = 0; j < 16; j++)
          {
            ipad_buf[j][0] = 0x36363636 ^ salt_ptr[j];
            opad_buf[j][0] = 0x5c5c5c5c ^ salt_ptr[j];
          }

          ipad_dgst[0][0] = SHA256M_A;
          ipad_dgst[1][0] = SHA256M_B;
          ipad_dgst[2][0] = SHA256M_C;
          ipad_dgst[3][0] = SHA256M_D;
          ipad_dgst[4][0] = SHA256M_E;
          ipad_dgst[5][0] = SHA256M_F;
          ipad_dgst[6][0] = SHA256M_G;
          ipad_dgst[7][0] = SHA256M_H;

          opad_dgst[0][0] = SHA256M_A;
          opad_dgst[1][0] = SHA256M_B;
          opad_dgst[2][0] = SHA256M_C;
          opad_dgst[3][0] = SHA256M_D;
          opad_dgst[4][0] = SHA256M_E;
          opad_dgst[5][0] = SHA256M_F;
          opad_dgst[6][0] = SHA256M_G;
          opad_dgst[7][0] = SHA256M_H;

          hashcat_sha256_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
          hashcat_sha256_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

          salt_search->ipad_prehashed_buf = mymalloc (32);
          salt_search->opad_prehashed_buf = mymalloc (32);

          salt_search->ipad_prehashed_buf[0] = ipad_dgst[0][0];
          salt_search->ipad_prehashed_buf[1] = ipad_dgst[1][0];
          salt_search->ipad_prehashed_buf[2] = ipad_dgst[2][0];
          salt_search->ipad_prehashed_buf[3] = ipad_dgst[3][0];
          salt_search->ipad_prehashed_buf[4] = ipad_dgst[4][0];
          salt_search->ipad_prehashed_buf[5] = ipad_dgst[5][0];
          salt_search->ipad_prehashed_buf[6] = ipad_dgst[6][0];
          salt_search->ipad_prehashed_buf[7] = ipad_dgst[7][0];

          salt_search->opad_prehashed_buf[0] = opad_dgst[0][0];
          salt_search->opad_prehashed_buf[1] = opad_dgst[1][0];
          salt_search->opad_prehashed_buf[2] = opad_dgst[2][0];
          salt_search->opad_prehashed_buf[3] = opad_dgst[3][0];
          salt_search->opad_prehashed_buf[4] = opad_dgst[4][0];
          salt_search->opad_prehashed_buf[5] = opad_dgst[5][0];
          salt_search->opad_prehashed_buf[6] = opad_dgst[6][0];
          salt_search->opad_prehashed_buf[7] = opad_dgst[7][0];
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt_pre)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt_pre);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MD5APR)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        md5apr_decode ((unsigned char *) &digest->buf.md5, (unsigned char *) hash_buf);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        if (memcmp (line_buf + MD5APR_SIGN, "rounds=", 7) == 0)
        {
          int iter;

          char *iter_buf = line_buf + MD5APR_SIGN + 7;

          for (iter = 0; *iter_buf >= '0' && *iter_buf <= '9' && iter < 7; iter_buf += 1, iter += 1) continue;

          *iter_buf = 0x0;

          salt_search->iterations = atoi (line_buf + MD5APR_SIGN + 7);
        }
        else
        {
          salt_search->iterations = MD5APR_ROUNDS;
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if ((engine_parameter->hash_type == HASH_TYPE_SHA512) && ((engine_parameter->salt_type == SALT_TYPE_NONE) || (engine_parameter->salt_type == SALT_TYPE_EXTERNAL)))
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha512[ 0] = hex_to_uint64 (&hash_buf[  0]);
        digest->buf.sha512[ 1] = hex_to_uint64 (&hash_buf[ 16]);
        digest->buf.sha512[ 2] = hex_to_uint64 (&hash_buf[ 32]);
        digest->buf.sha512[ 3] = hex_to_uint64 (&hash_buf[ 48]);
        digest->buf.sha512[ 4] = hex_to_uint64 (&hash_buf[ 64]);
        digest->buf.sha512[ 5] = hex_to_uint64 (&hash_buf[ 80]);
        digest->buf.sha512[ 6] = hex_to_uint64 (&hash_buf[ 96]);
        digest->buf.sha512[ 7] = hex_to_uint64 (&hash_buf[112]);

        /* salts */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[(uint32_t) digest->buf.sha512[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[(uint32_t) digest->buf.sha512[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[(uint32_t) digest->buf.sha512[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if ((engine_parameter->hash_type == HASH_TYPE_SHA512) && (engine_parameter->salt_type == SALT_TYPE_INCLUDED))
      {
        if (strchr (salt_buf, engine_parameter->separator) != NULL) separator_warnings++;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha512[ 0] = hex_to_uint64 (&hash_buf[  0]);
        digest->buf.sha512[ 1] = hex_to_uint64 (&hash_buf[ 16]);
        digest->buf.sha512[ 2] = hex_to_uint64 (&hash_buf[ 32]);
        digest->buf.sha512[ 3] = hex_to_uint64 (&hash_buf[ 48]);
        digest->buf.sha512[ 4] = hex_to_uint64 (&hash_buf[ 64]);
        digest->buf.sha512[ 5] = hex_to_uint64 (&hash_buf[ 80]);
        digest->buf.sha512[ 6] = hex_to_uint64 (&hash_buf[ 96]);
        digest->buf.sha512[ 7] = hex_to_uint64 (&hash_buf[112]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (128);
        salt_search->salt_prehashed_buf = mymalloc (128);

        memset (salt_search->salt_plain_buf,     0, 128);
        memset (salt_search->salt_prehashed_buf, 0, 128);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        if (engine_parameter->hash_mode == 1760)
        {
          uint64_t ipad_dgst[8][2] __attribute__ ((aligned (16)));
          uint64_t opad_dgst[8][2] __attribute__ ((aligned (16)));

          uint64_t ipad_buf[16][2] __attribute__ ((aligned (16)));
          uint64_t opad_buf[16][2] __attribute__ ((aligned (16)));

          uint64_t *salt_ptr = (uint64_t *) salt_search->salt_plain_buf;

          int j;

          for (j = 0; j < 16; j++)
          {
            ipad_buf[j][0] = 0x3636363636363636 ^ salt_ptr[j];
            opad_buf[j][0] = 0x5c5c5c5c5c5c5c5c ^ salt_ptr[j];
          }

          ipad_dgst[0][0] = SHA512M_A;
          ipad_dgst[1][0] = SHA512M_B;
          ipad_dgst[2][0] = SHA512M_C;
          ipad_dgst[3][0] = SHA512M_D;
          ipad_dgst[4][0] = SHA512M_E;
          ipad_dgst[5][0] = SHA512M_F;
          ipad_dgst[6][0] = SHA512M_G;
          ipad_dgst[7][0] = SHA512M_H;

          opad_dgst[0][0] = SHA512M_A;
          opad_dgst[1][0] = SHA512M_B;
          opad_dgst[2][0] = SHA512M_C;
          opad_dgst[3][0] = SHA512M_D;
          opad_dgst[4][0] = SHA512M_E;
          opad_dgst[5][0] = SHA512M_F;
          opad_dgst[6][0] = SHA512M_G;
          opad_dgst[7][0] = SHA512M_H;

          hashcat_sha512_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
          hashcat_sha512_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

          salt_search->ipad_prehashed_buf64 = mymalloc (64);
          salt_search->opad_prehashed_buf64 = mymalloc (64);

          salt_search->ipad_prehashed_buf64[0] = ipad_dgst[0][0];
          salt_search->ipad_prehashed_buf64[1] = ipad_dgst[1][0];
          salt_search->ipad_prehashed_buf64[2] = ipad_dgst[2][0];
          salt_search->ipad_prehashed_buf64[3] = ipad_dgst[3][0];
          salt_search->ipad_prehashed_buf64[4] = ipad_dgst[4][0];
          salt_search->ipad_prehashed_buf64[5] = ipad_dgst[5][0];
          salt_search->ipad_prehashed_buf64[6] = ipad_dgst[6][0];
          salt_search->ipad_prehashed_buf64[7] = ipad_dgst[7][0];

          salt_search->opad_prehashed_buf64[0] = opad_dgst[0][0];
          salt_search->opad_prehashed_buf64[1] = opad_dgst[1][0];
          salt_search->opad_prehashed_buf64[2] = opad_dgst[2][0];
          salt_search->opad_prehashed_buf64[3] = opad_dgst[3][0];
          salt_search->opad_prehashed_buf64[4] = opad_dgst[4][0];
          salt_search->opad_prehashed_buf64[5] = opad_dgst[5][0];
          salt_search->opad_prehashed_buf64[6] = opad_dgst[6][0];
          salt_search->opad_prehashed_buf64[7] = opad_dgst[7][0];
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA512UNIX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        sha512unix_decode ((unsigned char *) &digest->buf.sha512, (unsigned char *) hash_buf);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (128);

        memset (salt_search->salt_plain_buf, 0, 128);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        if (memcmp (line_buf + SHA512UNIX_SIGN, "rounds=", 7) == 0)
        {
          int iter;

          char *iter_buf = line_buf + SHA512UNIX_SIGN + 7;

          for (iter = 0; *iter_buf >= '0' && *iter_buf <= '9' && iter < 7; iter_buf += 1, iter += 1) continue;

          *iter_buf = 0x0;

          salt_search->iterations = atoi (line_buf + SHA512UNIX_SIGN + 7);
        }
        else
        {
          salt_search->iterations = SHA512UNIX_ROUNDS;
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_OSX1)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */
        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (128);
        salt_search->salt_prehashed_buf = mymalloc (128);

        memset (salt_search->salt_plain_buf,     0, 128);
        memset (salt_search->salt_prehashed_buf, 0, 128);

        memcpy (salt_search->salt_plain_buf,     salt_buf, salt_len);

        salt_len = salt_len / 2;

        uint32_t * salt_bin = (uint32_t *) salt_search->salt_prehashed_buf;

        salt_bin[0] = hex_to_uint (&salt_buf[0]);

        BYTESWAP (salt_bin[0]);

        uint32_t i;

        for (i = 0; i < 4; i += 1)
        {
          memcpy (&salt_search->salt_plain_struct[i], salt_search->salt_prehashed_buf, salt_len);

          salt_search->salt_plain_struct[i].len = salt_len;
        }

        salt_search->salt_plain_len     = salt_len;
        salt_search->salt_prehashed_len = salt_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt_pre)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt_pre);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_OSX512)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha512[ 0] = hex_to_uint64 (&hash_buf[  0]);
        digest->buf.sha512[ 1] = hex_to_uint64 (&hash_buf[ 16]);
        digest->buf.sha512[ 2] = hex_to_uint64 (&hash_buf[ 32]);
        digest->buf.sha512[ 3] = hex_to_uint64 (&hash_buf[ 48]);
        digest->buf.sha512[ 4] = hex_to_uint64 (&hash_buf[ 64]);
        digest->buf.sha512[ 5] = hex_to_uint64 (&hash_buf[ 80]);
        digest->buf.sha512[ 6] = hex_to_uint64 (&hash_buf[ 96]);
        digest->buf.sha512[ 7] = hex_to_uint64 (&hash_buf[112]);

        /* salt */
        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (128);
        salt_search->salt_prehashed_buf = mymalloc (128);

        memset (salt_search->salt_plain_buf,     0, 128);
        memset (salt_search->salt_prehashed_buf, 0, 128);

        memcpy (salt_search->salt_plain_buf,     salt_buf, salt_len);

        salt_len = salt_len / 2;

        uint32_t * salt_bin = (uint32_t *) salt_search->salt_prehashed_buf;

        salt_bin[0] = hex_to_uint (&salt_buf[0]);

        BYTESWAP (salt_bin[0]);

        salt_search->salt_plain_len     = salt_len;
        salt_search->salt_prehashed_len = salt_len;

        uint32_t i;

        for (i = 0; i < 4; i += 1)
        {
          memcpy (&salt_search->salt_plain_struct[i], salt_search->salt_prehashed_buf, salt_len);

          salt_search->salt_plain_struct[i].len = salt_len;
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt_pre)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt_pre);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MSSQL2012)
      {
        if (strchr (salt_buf, engine_parameter->separator) != NULL) separator_warnings++;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha512[ 0] = hex_to_uint64 (&hash_buf[  0]);
        digest->buf.sha512[ 1] = hex_to_uint64 (&hash_buf[ 16]);
        digest->buf.sha512[ 2] = hex_to_uint64 (&hash_buf[ 32]);
        digest->buf.sha512[ 3] = hex_to_uint64 (&hash_buf[ 48]);
        digest->buf.sha512[ 4] = hex_to_uint64 (&hash_buf[ 64]);
        digest->buf.sha512[ 5] = hex_to_uint64 (&hash_buf[ 80]);
        digest->buf.sha512[ 6] = hex_to_uint64 (&hash_buf[ 96]);
        digest->buf.sha512[ 7] = hex_to_uint64 (&hash_buf[112]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (128);
        salt_search->salt_prehashed_buf = mymalloc (128);

        memset (salt_search->salt_plain_buf,     0, 128);
        memset (salt_search->salt_prehashed_buf, 0, 128);

        uint32_t *hsalt = (uint32_t *) salt_search->salt_plain_buf;

        *hsalt = hex_to_uint (salt_buf);

        BYTESWAP (*hsalt);

        salt_search->salt_plain_len = 4;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_DESCRYPT)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        descrypt_decode ((unsigned char *) &digest->buf.descrypt, (unsigned char *) hash_buf);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_KECCAK)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        uint32_t mdlen = line_len / 2;

        uint32_t rsiz = 200 - (2 * mdlen);

        uint32_t i;

        for (i = 0; i < mdlen / 8; i++)
        {
          digest->buf.keccak[i] = hex_to_uint64 (&hash_buf[i * 16]);

          BYTESWAP64 (digest->buf.keccak[i]);
        }

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->keccak_mdlen = mdlen;
        salt_search->keccak_rsiz  = rsiz;

        salt_search->salt_plain_buf = mymalloc (4);

        memcpy (salt_search->salt_plain_buf, &mdlen, 4);

        salt_search->salt_plain_len = 4;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_IKEPSK_MD5)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md5[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md5[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->ikepsk = mymalloc (sizeof (ikepsk_t));

        memcpy (salt_search->ikepsk, salt_buf, sizeof (ikepsk_t));

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt_ikepsk)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt_ikepsk);
        }
        else
        {
          myfree (salt_search->ikepsk);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_IKEPSK_SHA1)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->ikepsk = mymalloc (sizeof (ikepsk_t));

        memcpy (salt_search->ikepsk, salt_buf, sizeof (ikepsk_t));

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt_ikepsk)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt_ikepsk);
        }
        else
        {
          myfree (salt_search->ikepsk);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_NETNTLMv1)
      {
        static const uint32_t c_SPtrans[8][64] =
        {
          {
            /* nibble 0 */
            0x02080800, 0x00080000, 0x02000002, 0x02080802,
            0x02000000, 0x00080802, 0x00080002, 0x02000002,
            0x00080802, 0x02080800, 0x02080000, 0x00000802,
            0x02000802, 0x02000000, 0x00000000, 0x00080002,
            0x00080000, 0x00000002, 0x02000800, 0x00080800,
            0x02080802, 0x02080000, 0x00000802, 0x02000800,
            0x00000002, 0x00000800, 0x00080800, 0x02080002,
            0x00000800, 0x02000802, 0x02080002, 0x00000000,
            0x00000000, 0x02080802, 0x02000800, 0x00080002,
            0x02080800, 0x00080000, 0x00000802, 0x02000800,
            0x02080002, 0x00000800, 0x00080800, 0x02000002,
            0x00080802, 0x00000002, 0x02000002, 0x02080000,
            0x02080802, 0x00080800, 0x02080000, 0x02000802,
            0x02000000, 0x00000802, 0x00080002, 0x00000000,
            0x00080000, 0x02000000, 0x02000802, 0x02080800,
            0x00000002, 0x02080002, 0x00000800, 0x00080802,
          },
          {
            /* nibble 1 */
            0x40108010, 0x00000000, 0x00108000, 0x40100000,
            0x40000010, 0x00008010, 0x40008000, 0x00108000,
            0x00008000, 0x40100010, 0x00000010, 0x40008000,
            0x00100010, 0x40108000, 0x40100000, 0x00000010,
            0x00100000, 0x40008010, 0x40100010, 0x00008000,
            0x00108010, 0x40000000, 0x00000000, 0x00100010,
            0x40008010, 0x00108010, 0x40108000, 0x40000010,
            0x40000000, 0x00100000, 0x00008010, 0x40108010,
            0x00100010, 0x40108000, 0x40008000, 0x00108010,
            0x40108010, 0x00100010, 0x40000010, 0x00000000,
            0x40000000, 0x00008010, 0x00100000, 0x40100010,
            0x00008000, 0x40000000, 0x00108010, 0x40008010,
            0x40108000, 0x00008000, 0x00000000, 0x40000010,
            0x00000010, 0x40108010, 0x00108000, 0x40100000,
            0x40100010, 0x00100000, 0x00008010, 0x40008000,
            0x40008010, 0x00000010, 0x40100000, 0x00108000,
          },
          {
            /* nibble 2 */
            0x04000001, 0x04040100, 0x00000100, 0x04000101,
            0x00040001, 0x04000000, 0x04000101, 0x00040100,
            0x04000100, 0x00040000, 0x04040000, 0x00000001,
            0x04040101, 0x00000101, 0x00000001, 0x04040001,
            0x00000000, 0x00040001, 0x04040100, 0x00000100,
            0x00000101, 0x04040101, 0x00040000, 0x04000001,
            0x04040001, 0x04000100, 0x00040101, 0x04040000,
            0x00040100, 0x00000000, 0x04000000, 0x00040101,
            0x04040100, 0x00000100, 0x00000001, 0x00040000,
            0x00000101, 0x00040001, 0x04040000, 0x04000101,
            0x00000000, 0x04040100, 0x00040100, 0x04040001,
            0x00040001, 0x04000000, 0x04040101, 0x00000001,
            0x00040101, 0x04000001, 0x04000000, 0x04040101,
            0x00040000, 0x04000100, 0x04000101, 0x00040100,
            0x04000100, 0x00000000, 0x04040001, 0x00000101,
            0x04000001, 0x00040101, 0x00000100, 0x04040000,
          },
          {
            /* nibble 3 */
            0x00401008, 0x10001000, 0x00000008, 0x10401008,
            0x00000000, 0x10400000, 0x10001008, 0x00400008,
            0x10401000, 0x10000008, 0x10000000, 0x00001008,
            0x10000008, 0x00401008, 0x00400000, 0x10000000,
            0x10400008, 0x00401000, 0x00001000, 0x00000008,
            0x00401000, 0x10001008, 0x10400000, 0x00001000,
            0x00001008, 0x00000000, 0x00400008, 0x10401000,
            0x10001000, 0x10400008, 0x10401008, 0x00400000,
            0x10400008, 0x00001008, 0x00400000, 0x10000008,
            0x00401000, 0x10001000, 0x00000008, 0x10400000,
            0x10001008, 0x00000000, 0x00001000, 0x00400008,
            0x00000000, 0x10400008, 0x10401000, 0x00001000,
            0x10000000, 0x10401008, 0x00401008, 0x00400000,
            0x10401008, 0x00000008, 0x10001000, 0x00401008,
            0x00400008, 0x00401000, 0x10400000, 0x10001008,
            0x00001008, 0x10000000, 0x10000008, 0x10401000,
          },
          {
            /* nibble 4 */
            0x08000000, 0x00010000, 0x00000400, 0x08010420,
            0x08010020, 0x08000400, 0x00010420, 0x08010000,
            0x00010000, 0x00000020, 0x08000020, 0x00010400,
            0x08000420, 0x08010020, 0x08010400, 0x00000000,
            0x00010400, 0x08000000, 0x00010020, 0x00000420,
            0x08000400, 0x00010420, 0x00000000, 0x08000020,
            0x00000020, 0x08000420, 0x08010420, 0x00010020,
            0x08010000, 0x00000400, 0x00000420, 0x08010400,
            0x08010400, 0x08000420, 0x00010020, 0x08010000,
            0x00010000, 0x00000020, 0x08000020, 0x08000400,
            0x08000000, 0x00010400, 0x08010420, 0x00000000,
            0x00010420, 0x08000000, 0x00000400, 0x00010020,
            0x08000420, 0x00000400, 0x00000000, 0x08010420,
            0x08010020, 0x08010400, 0x00000420, 0x00010000,
            0x00010400, 0x08010020, 0x08000400, 0x00000420,
            0x00000020, 0x00010420, 0x08010000, 0x08000020,
          },
          {
            /* nibble 5 */
            0x80000040, 0x00200040, 0x00000000, 0x80202000,
            0x00200040, 0x00002000, 0x80002040, 0x00200000,
            0x00002040, 0x80202040, 0x00202000, 0x80000000,
            0x80002000, 0x80000040, 0x80200000, 0x00202040,
            0x00200000, 0x80002040, 0x80200040, 0x00000000,
            0x00002000, 0x00000040, 0x80202000, 0x80200040,
            0x80202040, 0x80200000, 0x80000000, 0x00002040,
            0x00000040, 0x00202000, 0x00202040, 0x80002000,
            0x00002040, 0x80000000, 0x80002000, 0x00202040,
            0x80202000, 0x00200040, 0x00000000, 0x80002000,
            0x80000000, 0x00002000, 0x80200040, 0x00200000,
            0x00200040, 0x80202040, 0x00202000, 0x00000040,
            0x80202040, 0x00202000, 0x00200000, 0x80002040,
            0x80000040, 0x80200000, 0x00202040, 0x00000000,
            0x00002000, 0x80000040, 0x80002040, 0x80202000,
            0x80200000, 0x00002040, 0x00000040, 0x80200040,
          },
          {
            /* nibble 6 */
            0x00004000, 0x00000200, 0x01000200, 0x01000004,
            0x01004204, 0x00004004, 0x00004200, 0x00000000,
            0x01000000, 0x01000204, 0x00000204, 0x01004000,
            0x00000004, 0x01004200, 0x01004000, 0x00000204,
            0x01000204, 0x00004000, 0x00004004, 0x01004204,
            0x00000000, 0x01000200, 0x01000004, 0x00004200,
            0x01004004, 0x00004204, 0x01004200, 0x00000004,
            0x00004204, 0x01004004, 0x00000200, 0x01000000,
            0x00004204, 0x01004000, 0x01004004, 0x00000204,
            0x00004000, 0x00000200, 0x01000000, 0x01004004,
            0x01000204, 0x00004204, 0x00004200, 0x00000000,
            0x00000200, 0x01000004, 0x00000004, 0x01000200,
            0x00000000, 0x01000204, 0x01000200, 0x00004200,
            0x00000204, 0x00004000, 0x01004204, 0x01000000,
            0x01004200, 0x00000004, 0x00004004, 0x01004204,
            0x01000004, 0x01004200, 0x01004000, 0x00004004,
          },
          {
            /* nibble 7 */
            0x20800080, 0x20820000, 0x00020080, 0x00000000,
            0x20020000, 0x00800080, 0x20800000, 0x20820080,
            0x00000080, 0x20000000, 0x00820000, 0x00020080,
            0x00820080, 0x20020080, 0x20000080, 0x20800000,
            0x00020000, 0x00820080, 0x00800080, 0x20020000,
            0x20820080, 0x20000080, 0x00000000, 0x00820000,
            0x20000000, 0x00800000, 0x20020080, 0x20800080,
            0x00800000, 0x00020000, 0x20820000, 0x00000080,
            0x00800000, 0x00020000, 0x20000080, 0x20820080,
            0x00020080, 0x20000000, 0x00000000, 0x00820000,
            0x20800080, 0x20020080, 0x20020000, 0x00800080,
            0x20820000, 0x00000080, 0x00800080, 0x20020000,
            0x20820080, 0x00800000, 0x20800000, 0x20000080,
            0x00820000, 0x00020080, 0x20020080, 0x20800000,
            0x00000080, 0x20820000, 0x00820080, 0x00000000,
            0x20000000, 0x20800080, 0x00020000, 0x00820080,
          },
        };

        static const uint32_t c_skb[8][64] =
        {
          {
            /* for C bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
            0x00000000, 0x00000010, 0x20000000, 0x20000010,
            0x00010000, 0x00010010, 0x20010000, 0x20010010,
            0x00000800, 0x00000810, 0x20000800, 0x20000810,
            0x00010800, 0x00010810, 0x20010800, 0x20010810,
            0x00000020, 0x00000030, 0x20000020, 0x20000030,
            0x00010020, 0x00010030, 0x20010020, 0x20010030,
            0x00000820, 0x00000830, 0x20000820, 0x20000830,
            0x00010820, 0x00010830, 0x20010820, 0x20010830,
            0x00080000, 0x00080010, 0x20080000, 0x20080010,
            0x00090000, 0x00090010, 0x20090000, 0x20090010,
            0x00080800, 0x00080810, 0x20080800, 0x20080810,
            0x00090800, 0x00090810, 0x20090800, 0x20090810,
            0x00080020, 0x00080030, 0x20080020, 0x20080030,
            0x00090020, 0x00090030, 0x20090020, 0x20090030,
            0x00080820, 0x00080830, 0x20080820, 0x20080830,
            0x00090820, 0x00090830, 0x20090820, 0x20090830,
          },
          {
            /* for C bits (numbered as per FIPS 46) 7 8 10 11 12 13 */
            0x00000000, 0x02000000, 0x00002000, 0x02002000,
            0x00200000, 0x02200000, 0x00202000, 0x02202000,
            0x00000004, 0x02000004, 0x00002004, 0x02002004,
            0x00200004, 0x02200004, 0x00202004, 0x02202004,
            0x00000400, 0x02000400, 0x00002400, 0x02002400,
            0x00200400, 0x02200400, 0x00202400, 0x02202400,
            0x00000404, 0x02000404, 0x00002404, 0x02002404,
            0x00200404, 0x02200404, 0x00202404, 0x02202404,
            0x10000000, 0x12000000, 0x10002000, 0x12002000,
            0x10200000, 0x12200000, 0x10202000, 0x12202000,
            0x10000004, 0x12000004, 0x10002004, 0x12002004,
            0x10200004, 0x12200004, 0x10202004, 0x12202004,
            0x10000400, 0x12000400, 0x10002400, 0x12002400,
            0x10200400, 0x12200400, 0x10202400, 0x12202400,
            0x10000404, 0x12000404, 0x10002404, 0x12002404,
            0x10200404, 0x12200404, 0x10202404, 0x12202404,
          },
          {
            /* for C bits (numbered as per FIPS 46) 14 15 16 17 19 20 */
            0x00000000, 0x00000001, 0x00040000, 0x00040001,
            0x01000000, 0x01000001, 0x01040000, 0x01040001,
            0x00000002, 0x00000003, 0x00040002, 0x00040003,
            0x01000002, 0x01000003, 0x01040002, 0x01040003,
            0x00000200, 0x00000201, 0x00040200, 0x00040201,
            0x01000200, 0x01000201, 0x01040200, 0x01040201,
            0x00000202, 0x00000203, 0x00040202, 0x00040203,
            0x01000202, 0x01000203, 0x01040202, 0x01040203,
            0x08000000, 0x08000001, 0x08040000, 0x08040001,
            0x09000000, 0x09000001, 0x09040000, 0x09040001,
            0x08000002, 0x08000003, 0x08040002, 0x08040003,
            0x09000002, 0x09000003, 0x09040002, 0x09040003,
            0x08000200, 0x08000201, 0x08040200, 0x08040201,
            0x09000200, 0x09000201, 0x09040200, 0x09040201,
            0x08000202, 0x08000203, 0x08040202, 0x08040203,
            0x09000202, 0x09000203, 0x09040202, 0x09040203,
          },
          {
            /* for C bits (numbered as per FIPS 46) 21 23 24 26 27 28 */
            0x00000000, 0x00100000, 0x00000100, 0x00100100,
            0x00000008, 0x00100008, 0x00000108, 0x00100108,
            0x00001000, 0x00101000, 0x00001100, 0x00101100,
            0x00001008, 0x00101008, 0x00001108, 0x00101108,
            0x04000000, 0x04100000, 0x04000100, 0x04100100,
            0x04000008, 0x04100008, 0x04000108, 0x04100108,
            0x04001000, 0x04101000, 0x04001100, 0x04101100,
            0x04001008, 0x04101008, 0x04001108, 0x04101108,
            0x00020000, 0x00120000, 0x00020100, 0x00120100,
            0x00020008, 0x00120008, 0x00020108, 0x00120108,
            0x00021000, 0x00121000, 0x00021100, 0x00121100,
            0x00021008, 0x00121008, 0x00021108, 0x00121108,
            0x04020000, 0x04120000, 0x04020100, 0x04120100,
            0x04020008, 0x04120008, 0x04020108, 0x04120108,
            0x04021000, 0x04121000, 0x04021100, 0x04121100,
            0x04021008, 0x04121008, 0x04021108, 0x04121108,
          },
          {
            /* for D bits (numbered as per FIPS 46) 1 2 3 4 5 6 */
            0x00000000, 0x10000000, 0x00010000, 0x10010000,
            0x00000004, 0x10000004, 0x00010004, 0x10010004,
            0x20000000, 0x30000000, 0x20010000, 0x30010000,
            0x20000004, 0x30000004, 0x20010004, 0x30010004,
            0x00100000, 0x10100000, 0x00110000, 0x10110000,
            0x00100004, 0x10100004, 0x00110004, 0x10110004,
            0x20100000, 0x30100000, 0x20110000, 0x30110000,
            0x20100004, 0x30100004, 0x20110004, 0x30110004,
            0x00001000, 0x10001000, 0x00011000, 0x10011000,
            0x00001004, 0x10001004, 0x00011004, 0x10011004,
            0x20001000, 0x30001000, 0x20011000, 0x30011000,
            0x20001004, 0x30001004, 0x20011004, 0x30011004,
            0x00101000, 0x10101000, 0x00111000, 0x10111000,
            0x00101004, 0x10101004, 0x00111004, 0x10111004,
            0x20101000, 0x30101000, 0x20111000, 0x30111000,
            0x20101004, 0x30101004, 0x20111004, 0x30111004,
          },
          {
            /* for D bits (numbered as per FIPS 46) 8 9 11 12 13 14 */
            0x00000000, 0x08000000, 0x00000008, 0x08000008,
            0x00000400, 0x08000400, 0x00000408, 0x08000408,
            0x00020000, 0x08020000, 0x00020008, 0x08020008,
            0x00020400, 0x08020400, 0x00020408, 0x08020408,
            0x00000001, 0x08000001, 0x00000009, 0x08000009,
            0x00000401, 0x08000401, 0x00000409, 0x08000409,
            0x00020001, 0x08020001, 0x00020009, 0x08020009,
            0x00020401, 0x08020401, 0x00020409, 0x08020409,
            0x02000000, 0x0A000000, 0x02000008, 0x0A000008,
            0x02000400, 0x0A000400, 0x02000408, 0x0A000408,
            0x02020000, 0x0A020000, 0x02020008, 0x0A020008,
            0x02020400, 0x0A020400, 0x02020408, 0x0A020408,
            0x02000001, 0x0A000001, 0x02000009, 0x0A000009,
            0x02000401, 0x0A000401, 0x02000409, 0x0A000409,
            0x02020001, 0x0A020001, 0x02020009, 0x0A020009,
            0x02020401, 0x0A020401, 0x02020409, 0x0A020409,
          },
          {
            /* for D bits (numbered as per FIPS 46) 16 17 18 19 20 21 */
            0x00000000, 0x00000100, 0x00080000, 0x00080100,
            0x01000000, 0x01000100, 0x01080000, 0x01080100,
            0x00000010, 0x00000110, 0x00080010, 0x00080110,
            0x01000010, 0x01000110, 0x01080010, 0x01080110,
            0x00200000, 0x00200100, 0x00280000, 0x00280100,
            0x01200000, 0x01200100, 0x01280000, 0x01280100,
            0x00200010, 0x00200110, 0x00280010, 0x00280110,
            0x01200010, 0x01200110, 0x01280010, 0x01280110,
            0x00000200, 0x00000300, 0x00080200, 0x00080300,
            0x01000200, 0x01000300, 0x01080200, 0x01080300,
            0x00000210, 0x00000310, 0x00080210, 0x00080310,
            0x01000210, 0x01000310, 0x01080210, 0x01080310,
            0x00200200, 0x00200300, 0x00280200, 0x00280300,
            0x01200200, 0x01200300, 0x01280200, 0x01280300,
            0x00200210, 0x00200310, 0x00280210, 0x00280310,
            0x01200210, 0x01200310, 0x01280210, 0x01280310,
          },
          {
            /* for D bits (numbered as per FIPS 46) 22 23 24 25 27 28 */
            0x00000000, 0x04000000, 0x00040000, 0x04040000,
            0x00000002, 0x04000002, 0x00040002, 0x04040002,
            0x00002000, 0x04002000, 0x00042000, 0x04042000,
            0x00002002, 0x04002002, 0x00042002, 0x04042002,
            0x00000020, 0x04000020, 0x00040020, 0x04040020,
            0x00000022, 0x04000022, 0x00040022, 0x04040022,
            0x00002020, 0x04002020, 0x00042020, 0x04042020,
            0x00002022, 0x04002022, 0x00042022, 0x04042022,
            0x00000800, 0x04000800, 0x00040800, 0x04040800,
            0x00000802, 0x04000802, 0x00040802, 0x04040802,
            0x00002800, 0x04002800, 0x00042800, 0x04042800,
            0x00002802, 0x04002802, 0x00042802, 0x04042802,
            0x00000820, 0x04000820, 0x00040820, 0x04040820,
            0x00000822, 0x04000822, 0x00040822, 0x04040822,
            0x00002820, 0x04002820, 0x00042820, 0x04042820,
            0x00002822, 0x04002822, 0x00042822, 0x04042822
          }
        };

        /* parse line */

        char *user_pos = line_buf;

        char *unused_pos = strchr (user_pos, ':');

        if (unused_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint user_len = unused_pos - user_pos;

        unused_pos++;

        char *domain_pos = strchr (unused_pos, ':');

        if (domain_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint unused_len = domain_pos - unused_pos;

        domain_pos++;

        char *srvchall_pos = strchr (domain_pos, ':');

        if (srvchall_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint domain_len = srvchall_pos - domain_pos;

        srvchall_pos++;

        char *hash_pos = strchr (srvchall_pos, ':');

        if (hash_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint srvchall_len = hash_pos - srvchall_pos;

        hash_pos++;

        char *clichall_pos = strchr (hash_pos, ':');

        if (clichall_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint hash_len = clichall_pos - hash_pos;

        clichall_pos++;

        uint clichall_len = line_len - user_len - 1 - unused_len - 1 - domain_len - 1 - srvchall_len - 1 - hash_len - 1;

        if (clichall_len != 16)
        {
          log_warning ("Skipping hash: %s (salt length exception)", line_buf);

          continue;
        }

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md4[0] = hex_to_uint (&hash_pos[0]);
        digest->buf.md4[1] = hex_to_uint (&hash_pos[8]);
        digest->buf.md4[2] = hex_to_uint (&hash_pos[16]);
        digest->buf.md4[3] = hex_to_uint (&hash_pos[24]);
        digest->buf.md4[4] = hex_to_uint (&hash_pos[32]);
        digest->buf.md4[5] = hex_to_uint (&hash_pos[40]);

        BYTESWAP (digest->buf.md4[0]);
        BYTESWAP (digest->buf.md4[1]);
        BYTESWAP (digest->buf.md4[2]);
        BYTESWAP (digest->buf.md4[3]);
        BYTESWAP (digest->buf.md4[4]);
        BYTESWAP (digest->buf.md4[5]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        uint32_t *sptr = (uint32_t *) salt_search->salt_plain_buf;

        sptr[0] = hex_to_uint (&clichall_pos[0]);
        sptr[1] = hex_to_uint (&clichall_pos[8]);

        BYTESWAP (sptr[0]);
        BYTESWAP (sptr[1]);

        salt_search->salt_plain_len = 8;

        /* precompute netntlmv1 exploit stop */

        netntlm_t *netntlm = (netntlm_t * ) malloc (sizeof (netntlm_t));

        salt_search->netntlm = netntlm;

        netntlm->user_len     = user_len     * 2;
        netntlm->domain_len   = domain_len   * 2;
        netntlm->srvchall_len = srvchall_len / 2;
        netntlm->clichall_len = clichall_len / 2;

        char *userdomain_ptr = (char *) netntlm->userdomain_buf;
        char *chall_ptr      = (char *) netntlm->chall_buf;

        /**
         * store metadata
         */

        uint32_t i;

        for (i = 0; i < user_len; i++)
        {
          *userdomain_ptr++ = toupper (user_pos[i]);
          *userdomain_ptr++ = 0;
        }

        for (i = 0; i < domain_len; i++)
        {
          *userdomain_ptr++ = domain_pos[i];
          *userdomain_ptr++ = 0;
        }

        for (i = 0; i < srvchall_len; i += 2)
        {
          const char p0 = srvchall_pos[i + 0];
          const char p1 = srvchall_pos[i + 1];

          *chall_ptr++ = hex_convert (p1) << 0
                       | hex_convert (p0) << 4;
        }

        for (i = 0; i < clichall_len; i += 2)
        {
          const char p0 = clichall_pos[i + 0];
          const char p1 = clichall_pos[i + 1];

          *chall_ptr++ = hex_convert (p1) << 0
                       | hex_convert (p0) << 4;
        }

        // a bit cheating, but OK i think. this is because most
        // exploiting netntlm capture technique result in the same challange
        // so that multihash techniques can work, so we have to add the precomputed
        // last 2 byte from the md4 hash since its depending on the hash not the salt

        netntlm->chall_buf[255] = salt_search->netntlmv1_pc;

        /* special case: ESS */

        if (srvchall_len == 48)
        {
          if ((netntlm->chall_buf[2] == 0) && (netntlm->chall_buf[3] == 0) && (netntlm->chall_buf[4] == 0) && (netntlm->chall_buf[5] == 0))
          {
            uint w[16];

            w[ 0] = netntlm->chall_buf[6];
            w[ 1] = netntlm->chall_buf[7];
            w[ 2] = netntlm->chall_buf[0];
            w[ 3] = netntlm->chall_buf[1];
            w[ 4] = 0x80;
            w[ 5] = 0;
            w[ 6] = 0;
            w[ 7] = 0;
            w[ 8] = 0;
            w[ 9] = 0;
            w[10] = 0;
            w[11] = 0;
            w[12] = 0;
            w[13] = 0;
            w[14] = 16 * 8;
            w[15] = 0;

            uint dgst[4];

            dgst[0] = MAGIC_A;
            dgst[1] = MAGIC_B;
            dgst[2] = MAGIC_C;
            dgst[3] = MAGIC_D;

            md5_64H (w, dgst);

            sptr[0] = dgst[0];
            sptr[1] = dgst[1];
          }
        }

        /* precompute netntlmv1 exploit start */

        uint32_t Kc[16];
        uint32_t Kd[16];

        for (i = 0; i < 0x10000; i++)
        {
          uint32_t key_md4[2] = { i, 0 };
          uint32_t key_des[2] = { 0, 0 };

          transform_netntlmv1_key ((uint8_t *) key_md4, (uint8_t *) key_des);

          _des_keysetup (key_des, Kc, Kd, c_skb);

          uint32_t data3[2] = { sptr[0], sptr[1] };

          _des_encrypt (data3, Kc, Kd, c_SPtrans);

          if (data3[0] != digest->buf.md4[4]) continue;
          if (data3[1] != digest->buf.md4[5]) continue;

          salt_search->netntlmv1_pc = i;

          break;
        }

        memcpy (salt_search->salt_prehashed_buf, &digest->buf.md4[4], 8);

        /* store */

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt_netntlm)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt_netntlm);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_NETNTLMv2)
      {
        /* parse line */

        char *user_pos = line_buf;

        char *unused_pos = strchr (user_pos, ':');

        if (unused_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint user_len = unused_pos - user_pos;

        unused_pos++;

        char *domain_pos = strchr (unused_pos, ':');

        if (domain_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint unused_len = domain_pos - unused_pos;

        domain_pos++;

        char *srvchall_pos = strchr (domain_pos, ':');

        if (srvchall_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint domain_len = srvchall_pos - domain_pos;

        srvchall_pos++;

        char *hash_pos = strchr (srvchall_pos, ':');

        if (hash_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint srvchall_len = hash_pos - srvchall_pos;

        hash_pos++;

        char *clichall_pos = strchr (hash_pos, ':');

        if (clichall_pos == NULL)
        {
          log_warning ("Skipping hash: %s (signature unmatched)", line_buf);

          continue;
        }

        uint hash_len = clichall_pos - hash_pos;

        clichall_pos++;

        uint clichall_len = line_len - user_len - 1 - unused_len - 1 - domain_len - 1 - srvchall_len - 1 - hash_len - 1;

        if (clichall_len >= 1024)
        {
          log_warning ("Skipping hash: %s (salt length exception)", line_buf);

          continue;
        }

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_pos[ 0]);
        digest->buf.md5[1] = hex_to_uint (&hash_pos[ 8]);
        digest->buf.md5[2] = hex_to_uint (&hash_pos[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_pos[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        netntlm_t *netntlm = (netntlm_t * ) malloc (sizeof (netntlm_t));

        salt_search->netntlm = netntlm;

        netntlm->user_len     = user_len     * 2;
        netntlm->domain_len   = domain_len   * 2;
        netntlm->srvchall_len = srvchall_len / 2;
        netntlm->clichall_len = clichall_len / 2;

        char *userdomain_ptr = (char *) netntlm->userdomain_buf;
        char *chall_ptr      = (char *) netntlm->chall_buf;

        /**
         * handle username and domainname
         */

        uint i;

        for (i = 0; i < user_len; i++)
        {
          *userdomain_ptr++ = toupper (user_pos[i]);
          *userdomain_ptr++ = 0;
        }

        for (i = 0; i < domain_len; i++)
        {
          *userdomain_ptr++ = domain_pos[i];
          *userdomain_ptr++ = 0;
        }

        *userdomain_ptr++ = 0x80;

        /**
         * handle server challenge encoding
         */

        for (i = 0; i < srvchall_len; i += 2)
        {
          const char p0 = srvchall_pos[i + 0];
          const char p1 = srvchall_pos[i + 1];

          *chall_ptr++ = hex_convert (p1) << 0
                       | hex_convert (p0) << 4;
        }

        /**
         * handle client challenge encoding
         */

        for (i = 0; i < clichall_len; i += 2)
        {
          const char p0 = clichall_pos[i + 0];
          const char p1 = clichall_pos[i + 1];

          *chall_ptr++ = hex_convert (p1) << 0
                       | hex_convert (p0) << 4;
        }

        *chall_ptr++ = 0x80;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt_netntlm)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt_netntlm);
        }
        else
        {
          myfree (salt_search->netntlm);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_CISCO_SECRET4)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        char tmp_buf[100];

        memset (tmp_buf, 0, sizeof (tmp_buf));

        base64_decode (itoa64_to_int, hash_buf, 43, tmp_buf);

        memcpy (digest->buf.sha256, tmp_buf, 32);

        BYTESWAP (digest->buf.sha256[0]);
        BYTESWAP (digest->buf.sha256[1]);
        BYTESWAP (digest->buf.sha256[2]);
        BYTESWAP (digest->buf.sha256[3]);
        BYTESWAP (digest->buf.sha256[4]);
        BYTESWAP (digest->buf.sha256[5]);
        BYTESWAP (digest->buf.sha256[6]);
        BYTESWAP (digest->buf.sha256[7]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MD5AIX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        md5unix_decode ((unsigned char *) &digest->buf.md5, (unsigned char *) hash_buf);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        if (memcmp (line_buf + MD5AIX_SIGN, "rounds=", 7) == 0)
        {
          int iter;

          char *iter_buf = line_buf + MD5AIX_SIGN + 7;

          for (iter = 0; *iter_buf >= '0' && *iter_buf <= '9' && iter < 7; iter_buf += 1, iter += 1) continue;

          *iter_buf = 0x0;

          salt_search->iterations = atoi (line_buf + MD5AIX_SIGN + 7);
        }
        else
        {
          salt_search->iterations = MD5AIX_ROUNDS;
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA1AIX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        sha1aix_decode ((unsigned char *) &digest->buf.sha1, (unsigned char *) hash_buf);

        BYTESWAP (digest->buf.sha1[0]);
        BYTESWAP (digest->buf.sha1[1]);
        BYTESWAP (digest->buf.sha1[2]);
        BYTESWAP (digest->buf.sha1[3]);
        BYTESWAP (digest->buf.sha1[4]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        char iter[3] = { line_buf[SHA1AIX_SIGN], line_buf[SHA1AIX_SIGN + 1], 0 };

        salt_search->iterations = 1u << atoi (iter);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA256AIX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        sha256aix_decode ((unsigned char *) &digest->buf.sha256, (unsigned char *) hash_buf);

        BYTESWAP (digest->buf.sha256[0]);
        BYTESWAP (digest->buf.sha256[1]);
        BYTESWAP (digest->buf.sha256[2]);
        BYTESWAP (digest->buf.sha256[3]);
        BYTESWAP (digest->buf.sha256[4]);
        BYTESWAP (digest->buf.sha256[5]);
        BYTESWAP (digest->buf.sha256[6]);
        BYTESWAP (digest->buf.sha256[7]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        char iter[3] = { line_buf[SHA256AIX_SIGN], line_buf[SHA256AIX_SIGN + 1], 0 };

        salt_search->iterations = 1u << atoi (iter);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA512AIX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        sha512aix_decode ((unsigned char *) &digest->buf.sha512, (unsigned char *) hash_buf);

        BYTESWAP64 (digest->buf.sha512[0]);
        BYTESWAP64 (digest->buf.sha512[1]);
        BYTESWAP64 (digest->buf.sha512[2]);
        BYTESWAP64 (digest->buf.sha512[3]);
        BYTESWAP64 (digest->buf.sha512[4]);
        BYTESWAP64 (digest->buf.sha512[5]);
        BYTESWAP64 (digest->buf.sha512[6]);
        BYTESWAP64 (digest->buf.sha512[7]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        char iter[3] = { line_buf[SHA512AIX_SIGN], line_buf[SHA512AIX_SIGN + 1], 0 };

        salt_search->iterations = 1u << atoi (iter);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if ((engine_parameter->hash_type == HASH_TYPE_GOST) && ((engine_parameter->salt_type == SALT_TYPE_NONE) || (engine_parameter->salt_type == SALT_TYPE_EXTERNAL)))
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.gost[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.gost[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.gost[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.gost[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.gost[4] = hex_to_uint (&hash_buf[32]);
        digest->buf.gost[5] = hex_to_uint (&hash_buf[40]);
        digest->buf.gost[6] = hex_to_uint (&hash_buf[48]);
        digest->buf.gost[7] = hex_to_uint (&hash_buf[56]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.gost[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.gost[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.gost[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA1FORTIGATE)
      {
        /* salt 1 */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        salt_search->salt_plain_len = SALT_SIZE_SHA1FORTIGATE;

        /* digest */

        digest_t *digest = init_new_digest ();

        sha1fortigate_decode ((unsigned char *) &digest->buf.sha1, (unsigned char *) salt_search->salt_plain_buf, hash_buf);

        BYTESWAP (digest->buf.sha1[0]);
        BYTESWAP (digest->buf.sha1[1]);
        BYTESWAP (digest->buf.sha1[2]);
        BYTESWAP (digest->buf.sha1[3]);
        BYTESWAP (digest->buf.sha1[4]);

        // fill the fortigate_magic plain_t array

        int i;

        for (i = 0; i < 4; i++)
        {
          salt_search->additional_plain_struct[i].len = 24;

          memcpy (&salt_search->additional_plain_struct[i].buf, FORTIGATE_MAGIC_A, 24);
        }

        /* salt 2 */

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_PBKDF2OSX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha512[ 0] = hex_to_uint64 (&hash_buf[  0]);
        digest->buf.sha512[ 1] = hex_to_uint64 (&hash_buf[ 16]);
        digest->buf.sha512[ 2] = hex_to_uint64 (&hash_buf[ 32]);
        digest->buf.sha512[ 3] = hex_to_uint64 (&hash_buf[ 48]);
        digest->buf.sha512[ 4] = hex_to_uint64 (&hash_buf[ 64]);
        digest->buf.sha512[ 5] = hex_to_uint64 (&hash_buf[ 80]);
        digest->buf.sha512[ 6] = hex_to_uint64 (&hash_buf[ 96]);
        digest->buf.sha512[ 7] = hex_to_uint64 (&hash_buf[112]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        int iter;

        for (iter = 0; iter < salt_len; iter += 2) salt_search->salt_plain_buf[iter / 2] = hex_to_char (&salt_buf[iter]);

        salt_search->salt_plain_len = salt_len / 2;

        char *iter_buf = line_buf + PBKDF2OSX_SIGN;

        for (iter = 0; *iter_buf >= '0' && *iter_buf <= '9' && iter < 7; iter_buf += 1, iter += 1) continue;

        *iter_buf = 0x0;

        salt_search->iterations = atoi (line_buf + PBKDF2OSX_SIGN);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_PBKDF2GRUB)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha512[ 0] = hex_to_uint64 (&hash_buf[  0]);
        digest->buf.sha512[ 1] = hex_to_uint64 (&hash_buf[ 16]);
        digest->buf.sha512[ 2] = hex_to_uint64 (&hash_buf[ 32]);
        digest->buf.sha512[ 3] = hex_to_uint64 (&hash_buf[ 48]);
        digest->buf.sha512[ 4] = hex_to_uint64 (&hash_buf[ 64]);
        digest->buf.sha512[ 5] = hex_to_uint64 (&hash_buf[ 80]);
        digest->buf.sha512[ 6] = hex_to_uint64 (&hash_buf[ 96]);
        digest->buf.sha512[ 7] = hex_to_uint64 (&hash_buf[112]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        int iter;

        for (iter = 0; iter < salt_len; iter += 2) salt_search->salt_plain_buf[iter / 2] = hex_to_char (&salt_buf[iter]);

        salt_search->salt_plain_len = salt_len / 2;

        char *iter_buf = line_buf + PBKDF2GRUB_SIGN;

        for (iter = 0; *iter_buf >= '0' && *iter_buf <= '9' && iter < 7; iter_buf += 1, iter += 1) continue;

        *iter_buf = 0x0;

        salt_search->iterations = atoi (line_buf + PBKDF2GRUB_SIGN);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MD5CISCO_PIX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        md5cisco_decode (hash_buf, (uint32_t *) &digest->buf.md5);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA1ORACLE)
      {
        /* salt 1 */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        salt_search->salt_plain_buf[0] = hex_to_char (&salt_buf[0]);
        salt_search->salt_plain_buf[1] = hex_to_char (&salt_buf[2]);
        salt_search->salt_plain_buf[2] = hex_to_char (&salt_buf[4]);
        salt_search->salt_plain_buf[3] = hex_to_char (&salt_buf[6]);
        salt_search->salt_plain_buf[4] = hex_to_char (&salt_buf[8]);
        salt_search->salt_plain_buf[5] = hex_to_char (&salt_buf[10]);
        salt_search->salt_plain_buf[6] = hex_to_char (&salt_buf[12]);
        salt_search->salt_plain_buf[7] = hex_to_char (&salt_buf[14]);
        salt_search->salt_plain_buf[8] = hex_to_char (&salt_buf[16]);
        salt_search->salt_plain_buf[9] = hex_to_char (&salt_buf[18]);

        salt_search->salt_plain_len = salt_len / 2;

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt 2 */

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_HMACRAKP)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (256);

        salt_search->salt_plain_len = salt_len / 2;

        memset (salt_search->salt_plain_buf, 0, 256);

        uint32_t i;

        for (i = 0; i < salt_search->salt_plain_len; i++) salt_search->salt_plain_buf[i] = hex_to_char (&salt_buf[i * 2]);

        salt_search->salt_plain_buf[salt_len / 2] = 0x80;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_BCRYPT)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        salt_search->salt_plain_len = 16;

        salt_search->signature = mymalloc (BCRYPT_SIGN + 1);

        memset (salt_search->signature, 0, BCRYPT_SIGN + 1);

        memcpy (salt_search->signature, line_buf, BCRYPT_SIGN);

        bcrypt_decode ((char *) digest->buf.bcrypt, salt_search->salt_plain_buf, hash_buf, salt_buf);

        BYTESWAP (digest->buf.bcrypt[0]);
        BYTESWAP (digest->buf.bcrypt[1]);
        BYTESWAP (digest->buf.bcrypt[2]);
        BYTESWAP (digest->buf.bcrypt[3]);
        BYTESWAP (digest->buf.bcrypt[4]);
        BYTESWAP (digest->buf.bcrypt[5]);

        digest->buf.bcrypt[5] &= ~0xff;

        uint32_t *rptr = (uint32_t *) salt_search->salt_plain_buf;

        BYTESWAP (rptr[0]);
        BYTESWAP (rptr[1]);
        BYTESWAP (rptr[2]);
        BYTESWAP (rptr[3]);

        char iter[3] = { line_buf[BCRYPT_SIGN], line_buf[BCRYPT_SIGN + 1], 0 };

        salt_search->iterations = 1u << atoi (iter);

        if ((db->salts_cnt != 0) && (salt_search->iterations != db->salts_buf[0]->iterations))
        {
          log_error ("All bcrypt hashes must have the same iteration count");

          exit (-1);
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA256UNIX)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        sha256unix_decode ((unsigned char *) &digest->buf.sha256, (unsigned char *) hash_buf);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (64);

        memset (salt_search->salt_plain_buf, 0, 64);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        if (memcmp (line_buf + SHA256UNIX_SIGN, "rounds=", 7) == 0)
        {
          int iter;

          char *iter_buf = line_buf + SHA256UNIX_SIGN + 7;

          for (iter = 0; *iter_buf >= '0' && *iter_buf <= '9' && iter < 7; iter_buf += 1, iter += 1) continue;

          *iter_buf = 0x0;

          salt_search->iterations = atoi (line_buf + SHA256UNIX_SIGN + 7);
        }
        else
        {
          salt_search->iterations = SHA256UNIX_ROUNDS;
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_EPIV6_4)
      {
        char tmp_buf[65];

        /* digest */

        digest_t *digest = init_new_digest ();

        memset (tmp_buf, 0, sizeof (tmp_buf));

        base64_decode (base64_to_int, hash_buf, 64, tmp_buf);

        memcpy (digest->buf.sha256, tmp_buf, 64);

        BYTESWAP (digest->buf.sha256[0]);
        BYTESWAP (digest->buf.sha256[1]);
        BYTESWAP (digest->buf.sha256[2]);
        BYTESWAP (digest->buf.sha256[3]);
        BYTESWAP (digest->buf.sha256[4]);
        BYTESWAP (digest->buf.sha256[5]);
        BYTESWAP (digest->buf.sha256[6]);
        BYTESWAP (digest->buf.sha256[7]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memset (tmp_buf, 0, sizeof (tmp_buf));

        int tmp_len = base64_decode (base64_to_int, salt_buf, salt_len, tmp_buf);

        memcpy (salt_search->salt_plain_buf, tmp_buf, tmp_len);

        salt_search->salt_plain_len = tmp_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA512B64S)
      {
        /* salt 1 */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        /* digest */

        digest_t *digest = init_new_digest ();

        sha512b64s_decode ((unsigned char *) &digest->buf.sha512, (unsigned char *) salt_search->salt_plain_buf, line_len - SHA512B64S_SIGN, &salt_search->salt_plain_len, hash_buf);

        BYTESWAP64 (digest->buf.sha512[0]);
        BYTESWAP64 (digest->buf.sha512[1]);
        BYTESWAP64 (digest->buf.sha512[2]);
        BYTESWAP64 (digest->buf.sha512[3]);
        BYTESWAP64 (digest->buf.sha512[4]);
        BYTESWAP64 (digest->buf.sha512[5]);
        BYTESWAP64 (digest->buf.sha512[6]);
        BYTESWAP64 (digest->buf.sha512[7]);

        /* salt 2 */

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_EPIV4)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        salt_search->salt_plain_len = (SALT_SIZE_MIN_EPIV4 - 2) / 2;

        uint32_t i;

        for (i = 0; i < salt_search->salt_plain_len + 1; i++) salt_search->salt_plain_buf[i] = hex_to_char (&salt_buf[i * 2]);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SCRYPT)
      {
        char tmp_buf[65];

        /* digest */

        digest_t *digest = init_new_digest ();

        memset (tmp_buf, 0, sizeof (tmp_buf));

        base64_decode (base64_to_int, hash_buf, 64, tmp_buf);

        memcpy (digest->buf.sha256, tmp_buf, 64);

        BYTESWAP (digest->buf.sha256[0]);
        BYTESWAP (digest->buf.sha256[1]);
        BYTESWAP (digest->buf.sha256[2]);
        BYTESWAP (digest->buf.sha256[3]);
        BYTESWAP (digest->buf.sha256[4]);
        BYTESWAP (digest->buf.sha256[5]);
        BYTESWAP (digest->buf.sha256[6]);
        BYTESWAP (digest->buf.sha256[7]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memset (tmp_buf, 0, sizeof (tmp_buf));

        int tmp_len = base64_decode (base64_to_int, salt_buf, salt_len, tmp_buf);

        memcpy (salt_search->salt_plain_buf, tmp_buf, tmp_len);

        salt_search->salt_plain_len = tmp_len;

        // N
        char *N_pos = line_buf + SCRYPT_SIGN + 1;

        uint32_t N = atoi (N_pos);

        // r
        char *r_pos = strchr (N_pos, ':');

        r_pos++;

        uint32_t r = atoi (r_pos);

        // p
        char *p_pos = strchr (r_pos, ':');

        p_pos++;

        uint32_t p = atoi (p_pos);

        salt_search->scrypt_N = N;
        salt_search->scrypt_r = r;
        salt_search->scrypt_p = p;

        // more than only the following check needed?

        if ((db->salts_cnt != 0) && (salt_search->iterations != db->salts_buf[0]->iterations))
        {
          log_error ("All scrypt hashes must have the same work factor");

          exit (-1);
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_CISCO_SECRET9)
      {
        char tmp_buf[65];

        /* digest */

        digest_t *digest = init_new_digest ();

        memset (tmp_buf, 0, sizeof (tmp_buf));

        base64_decode (itoa64_to_int, hash_buf, 64, tmp_buf); // 64 is not a bug

        memcpy (digest->buf.sha256, tmp_buf, 64);

        BYTESWAP (digest->buf.sha256[0]);
        BYTESWAP (digest->buf.sha256[1]);
        BYTESWAP (digest->buf.sha256[2]);
        BYTESWAP (digest->buf.sha256[3]);
        BYTESWAP (digest->buf.sha256[4]);
        BYTESWAP (digest->buf.sha256[5]);
        BYTESWAP (digest->buf.sha256[6]);
        BYTESWAP (digest->buf.sha256[7]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        // fixed
        salt_search->scrypt_N = 16384;
        salt_search->scrypt_r = 1;
        salt_search->scrypt_p = 1;
        salt_search->iterations = 1;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_PHPS)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_buf[0]);

        digest->buf.md5[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md5[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        salt_search->salt_plain_len = salt_len;

        char *salt_buf_ptr = salt_search->salt_plain_buf;

        int i;

        for (i = 0; i < salt_len * 2; i += 2) *salt_buf_ptr++ = hex_to_char (&salt_buf[i]);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_DJANGOSHA1)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_HMAIL)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha256[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha256[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha256[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha256[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha256[4] = hex_to_uint (&hash_buf[32]);
        digest->buf.sha256[5] = hex_to_uint (&hash_buf[40]);
        digest->buf.sha256[6] = hex_to_uint (&hash_buf[48]);
        digest->buf.sha256[7] = hex_to_uint (&hash_buf[56]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MEDIAWIKI_B)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md5[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md5[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_buf[salt_len] = '-'; // this is the particularity of this hash type md5($salt.'-'.md5($pass))

        salt_search->salt_plain_len = salt_len + 1;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_CISCO_SECRET8)
      {
        char tmp_buf[65];

        /* digest */

        digest_t *digest = init_new_digest ();

        memset (tmp_buf, 0, sizeof (tmp_buf));

        base64_decode (itoa64_to_int, hash_buf, 64, tmp_buf);

        memcpy (digest->buf.sha256, tmp_buf, 64);

        BYTESWAP (digest->buf.sha256[0]);
        BYTESWAP (digest->buf.sha256[1]);
        BYTESWAP (digest->buf.sha256[2]);
        BYTESWAP (digest->buf.sha256[3]);
        BYTESWAP (digest->buf.sha256[4]);
        BYTESWAP (digest->buf.sha256[5]);
        BYTESWAP (digest->buf.sha256[6]);
        BYTESWAP (digest->buf.sha256[7]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        salt_search->iterations = CISCO_SECRET8_ROUNDS;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_DJANGO_SHA256)
      {
        char tmp_buf[65];

        /* digest */

        digest_t *digest = init_new_digest ();

        memset (tmp_buf, 0, sizeof (tmp_buf));

        base64_decode (base64_to_int, hash_buf, 64, tmp_buf);

        memcpy (digest->buf.sha256, tmp_buf, 64);

        BYTESWAP (digest->buf.sha256[0]);
        BYTESWAP (digest->buf.sha256[1]);
        BYTESWAP (digest->buf.sha256[2]);
        BYTESWAP (digest->buf.sha256[3]);
        BYTESWAP (digest->buf.sha256[4]);
        BYTESWAP (digest->buf.sha256[5]);
        BYTESWAP (digest->buf.sha256[6]);
        BYTESWAP (digest->buf.sha256[7]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        char *iter_buf = line_buf + DJANGO_SHA256_SIGN;

        salt_search->iterations = atoi (iter_buf);

        if (salt_search->iterations < 1)
        {
          log_warning ("Skipping hash: %s (iteration number incorrect)", line_buf);

          continue;
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (1, sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_PEOPLESOFT)
      {
        char tmp_buf[65];

        /* digest */

        digest_t *digest = init_new_digest ();

        memset (tmp_buf, 0, sizeof (tmp_buf));

        base64_decode (base64_to_int, hash_buf, 40, tmp_buf);

        memcpy (digest->buf.sha1, tmp_buf, 20);

        digest->buf.sha1[0] = __builtin_bswap32 (digest->buf.sha1[0]);
        digest->buf.sha1[1] = __builtin_bswap32 (digest->buf.sha1[1]);
        digest->buf.sha1[2] = __builtin_bswap32 (digest->buf.sha1[2]);
        digest->buf.sha1[3] = __builtin_bswap32 (digest->buf.sha1[3]);
        digest->buf.sha1[4] = __builtin_bswap32 (digest->buf.sha1[4]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.sha1[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_CRAM_MD5)
      {
        char tmp_buf[100];

        /* digest */

        digest_t *digest = init_new_digest ();

        memset (tmp_buf, 0, sizeof (tmp_buf));

        uint tmp_len = base64_decode (base64_to_int, hash_buf, hash_len, tmp_buf);

        if (tmp_len < 32)
        {
          log_warning ("Skipping line: %s (invalid base64 hash)", line_buf);

          continue;
        }

        char *digest_ptr = tmp_buf + (tmp_len - 32); // last 32 bytes

        digest->buf.md5[0] = hex_to_uint (&digest_ptr[0]);
        digest->buf.md5[1] = hex_to_uint (&digest_ptr[8]);
        digest->buf.md5[2] = hex_to_uint (&digest_ptr[16]);
        digest->buf.md5[3] = hex_to_uint (&digest_ptr[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        // hack: use the prehashed buffer to store the remaining data (about user etc)

        uint user_len = tmp_len - 32;

        memcpy (salt_search->salt_prehashed_buf, tmp_buf, user_len);

        salt_search->salt_prehashed_len = user_len;

        // actual salt

        memset (tmp_buf, 0, sizeof (tmp_buf));

        tmp_len = base64_decode (base64_to_int, salt_buf, salt_len, tmp_buf);

        memcpy (salt_search->salt_plain_buf, tmp_buf, tmp_len);

        salt_search->salt_plain_len = tmp_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_DRUPAL7)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        memset (digest->buf.sha512, 0, sizeof (digest->buf.sha512));

        drupal7_decode ((unsigned char *) &digest->buf.sha512, (unsigned char *) hash_buf);

        digest->buf.sha512[0] = __builtin_bswap64 (digest->buf.sha512[0]);
        digest->buf.sha512[1] = __builtin_bswap64 (digest->buf.sha512[1]);
        digest->buf.sha512[2] = __builtin_bswap64 (digest->buf.sha512[2]);
        digest->buf.sha512[3] = __builtin_bswap64 (digest->buf.sha512[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (128);

        memset (salt_search->salt_plain_buf, 0, 128);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        salt_search->iterations = 1u << base64b_char2int (line_buf[DRUPAL7_SIGN]);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MD5CISCO_ASA)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        md5cisco_decode (hash_buf, (uint32_t *) &digest->buf.md5);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (4);

        memset (salt_search->salt_plain_buf, 0, 4);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;
        salt_search->salt_prehashed_len = (salt_len < 4) ? salt_len : 4;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SAP_H_SHA1)
      {
        char tmp_buf[100];

        /* digest */

        memset (tmp_buf, 0, sizeof (tmp_buf));

        uint tmp_len = base64_decode (base64_to_int, hash_buf, hash_len, tmp_buf);

        /* digest */

        digest_t *digest = init_new_digest ();

        memcpy (digest->buf.sha1, tmp_buf, 20);

        digest->buf.sha1[0] = __builtin_bswap32 (digest->buf.sha1[0]);
        digest->buf.sha1[1] = __builtin_bswap32 (digest->buf.sha1[1]);
        digest->buf.sha1[2] = __builtin_bswap32 (digest->buf.sha1[2]);
        digest->buf.sha1[3] = __builtin_bswap32 (digest->buf.sha1[3]);
        digest->buf.sha1[4] = __builtin_bswap32 (digest->buf.sha1[4]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        salt_len = tmp_len - 20;

        memcpy (salt_search->salt_plain_buf, tmp_buf + 20, salt_len);

        salt_search->salt_plain_len = salt_len;

        salt_search->iterations = atoi (line_buf + SAP_H_SHA1_SIGN);

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_PRESTASHOP)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md5[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md5[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        memcpy (salt_search->salt_plain_buf, salt_buf, salt_len);

        salt_search->salt_plain_len = salt_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_prehashed_buf);

          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_POSTGRESQL_AUTH)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.md5[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.md5[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.md5[3] = hex_to_uint (&hash_buf[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        // 4 byte salt

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        int i;

        for (i = 0; i < salt_len; i ++)
        {
          salt_search->salt_plain_buf[i] = hex_to_char (&salt_buf[i * 2]);
        }

        salt_search->salt_plain_len = salt_len;

        // finally: fill the user_name plain_t array

        // get the user name

        char *user_pos = line_buf + POSTGRESQL_AUTH_SIGN;

        char *salt_pos = strchr (user_pos, '*');

        uint user_len = salt_pos - user_pos;

        for (i = 0; i < 4; i++)
        {
          salt_search->additional_plain_struct[i].len = user_len;

          memset (&salt_search->additional_plain_struct[i].buf, 0, sizeof (salt_search->additional_plain_struct[i].buf));
          memcpy (&salt_search->additional_plain_struct[i].buf, user_pos, user_len);
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_MYSQL_AUTH)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.sha1[0] = hex_to_uint (&hash_buf[0]);
        digest->buf.sha1[1] = hex_to_uint (&hash_buf[8]);
        digest->buf.sha1[2] = hex_to_uint (&hash_buf[16]);
        digest->buf.sha1[3] = hex_to_uint (&hash_buf[24]);
        digest->buf.sha1[4] = hex_to_uint (&hash_buf[32]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf, 0, BLOCK_SIZE);

        // 20 byte raw salt

        uint32_t *salt_ptr = (uint32_t *) salt_search->salt_plain_buf;

        salt_ptr[0] = hex_to_uint (&salt_buf[0]);
        salt_ptr[1] = hex_to_uint (&salt_buf[8]);
        salt_ptr[2] = hex_to_uint (&salt_buf[16]);
        salt_ptr[3] = hex_to_uint (&salt_buf[24]);
        salt_ptr[4] = hex_to_uint (&salt_buf[32]);

        BYTESWAP (salt_ptr[0]);
        BYTESWAP (salt_ptr[1]);
        BYTESWAP (salt_ptr[2]);
        BYTESWAP (salt_ptr[3]);
        BYTESWAP (salt_ptr[4]);

        salt_search->salt_plain_len = salt_len;

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SIP_AUTH)
      {
        // split the line

        // URI_server:

        char *URI_server_pos = line_buf + SIP_AUTH_SIGN;

        char *URI_client_pos = strchr (URI_server_pos, '*');

        URI_client_pos[0] = '\0';
        URI_client_pos++;

        // URI_client:

        char *user_pos = strchr (URI_client_pos, '*');

        user_pos[0] = '\0';
        user_pos++;

        // user:

        char *realm_pos = strchr (user_pos, '*');

        realm_pos[0] = '\0';
        realm_pos++;

        // realm:

        char *method_pos = strchr (realm_pos, '*');

        method_pos[0] = '\0';
        method_pos++;

        // method:

        char *URI_prefix_pos = strchr (method_pos, '*');

        URI_prefix_pos[0] = '\0';
        URI_prefix_pos++;

        // URI_prefix:

        char *URI_resource_pos = strchr (URI_prefix_pos, '*');

        URI_resource_pos[0] = '\0';
        URI_resource_pos++;

        // URI_resource:

        char *URI_suffix_pos = strchr (URI_resource_pos, '*');

        URI_suffix_pos[0] = '\0';
        URI_suffix_pos++;

        // URI_suffix:

        char *nonce_pos = strchr (URI_suffix_pos, '*');

        nonce_pos[0] = '\0';
        nonce_pos++;

        // nonce:

        char *nonce_client_pos = strchr (nonce_pos, '*');

        nonce_client_pos[0] = '\0';
        nonce_client_pos++;

        // nonce_client:

        char *nonce_count_pos = strchr (nonce_client_pos, '*');

        nonce_count_pos[0] = '\0';
        nonce_count_pos++;

        // nonce_count:

        char *qop_pos = strchr (nonce_count_pos, '*');

        qop_pos[0] = '\0';
        qop_pos++;

        // qop:

        char *directive_pos = strchr (qop_pos, '*');

        directive_pos[0] = '\0';
        directive_pos++;

        // directive

        char *digest_pos = strchr (directive_pos, '*');

        digest_pos[0] = '\0';
        digest_pos++;

        // then copy the parts to a sip_t struct

        sip_t *sip = (sip_t *) mycalloc (1, sizeof (sip_t));

        sip->URI_server = strdup (URI_server_pos);
        sip->URI_client = strdup (URI_client_pos);

        sip->user   = strdup (user_pos);
        sip->realm  = strdup (realm_pos);
        sip->method = strdup (method_pos);

        sip->URI_prefix   = strdup (URI_prefix_pos);
        sip->URI_resource = strdup (URI_resource_pos);
        sip->URI_suffix   = strdup (URI_suffix_pos);

        sip->nonce        = strdup (nonce_pos);
        sip->nonce_client = strdup (nonce_client_pos);
        sip->nonce_count  = strdup (nonce_count_pos);

        sip->qop       = strdup (qop_pos);
        sip->directive = strdup (directive_pos);

        /* digest */

        digest_t *digest = init_new_digest ();

        digest->buf.md5[0] = hex_to_uint (&digest_pos[0]);
        digest->buf.md5[1] = hex_to_uint (&digest_pos[8]);
        digest->buf.md5[2] = hex_to_uint (&digest_pos[16]);
        digest->buf.md5[3] = hex_to_uint (&digest_pos[24]);

        BYTESWAP (digest->buf.md5[0]);
        BYTESWAP (digest->buf.md5[1]);
        BYTESWAP (digest->buf.md5[2]);
        BYTESWAP (digest->buf.md5[3]);

        /* salt */

        salt_t *salt_search = init_new_salt ();

        salt_search->sip = sip;

        /*
         * HA2 (can be precomputed):
         * HA2 = md5 ($method . ":" . $uri)
         */

        plain_t plains[4];
        plain_t plains_tmp[4];

        plain_init (plains);

        digest_t dgst[4];

        digest_md5_sse2_t digests;

        md5_init_sse2 (&digests);

        uint method_len = strlen (method_pos);

        char *plain_tmp_ptr = (char *) plains_tmp[0].buf;

        memcpy (&plains_tmp[0].buf, method_pos, method_len);

        plain_tmp_ptr[method_len] = ':';

        plains_tmp[0].len = method_len + 1;

        md5_update_sse2 (plains, &digests, plains_tmp);

        uint URI_prefix_len = strlen (URI_prefix_pos);

        if (URI_prefix_len > 0)
        {
          memcpy (plain_tmp_ptr, URI_prefix_pos, URI_prefix_len);

          plain_tmp_ptr[URI_prefix_len] = ':';

          plains_tmp[0].len = URI_prefix_len + 1;

          md5_update_sse2 (plains, &digests, plains_tmp);
        }

        uint URI_resource_len = strlen (URI_resource_pos);

        memcpy (&plains_tmp[0].buf, URI_resource_pos, URI_resource_len);

        plains_tmp[0].len = URI_resource_len;

        md5_update_sse2 (plains, &digests, plains_tmp);

        uint URI_suffix_len = strlen (URI_suffix_pos);

        if (URI_suffix_len > 0)
        {
          plain_tmp_ptr[0] = ':';

          memcpy (plain_tmp_ptr + 1, URI_suffix_pos, URI_suffix_len);

          plains_tmp[0].len = 1 + URI_suffix_len;

          md5_update_sse2 (plains, &digests, plains_tmp);
        }

        md5_final_sse2 (plains, &digests);

        transpose_md5_digest (&digests, dgst);

        BYTESWAP (dgst[0].buf.md5[0]);
        BYTESWAP (dgst[0].buf.md5[1]);
        BYTESWAP (dgst[0].buf.md5[2]);
        BYTESWAP (dgst[0].buf.md5[3]);

        // construct the salt_plain_buf
        // there are 2 different cases:

        // we allow max 4 md5 "blocks", too much is too much ;)

        uint max_salt_len = 215; // because (64 + 64 + 64 + 55) - 32,  where 32 is the HA1 md5 hex hash

        salt_search->salt_plain_buf = mymalloc (max_salt_len);

        memset (salt_search->salt_plain_buf, 0, max_salt_len);

        uint nonce_len        = strlen (nonce_pos);
        uint nonce_count_len  = strlen (nonce_count_pos);
        uint nonce_client_len = strlen (nonce_client_pos);
        uint qop_len          = strlen (qop_pos);

        uint salt_len = 0;

        if ((strcmp (qop_pos, "auth") == 0) || (strcmp (qop_pos, "auth-int") == 0))
        {
          salt_len = 1 + nonce_len + 1 + nonce_count_len + 1 + nonce_client_len + 1 + qop_len + 1 + 32;

          if (salt_len > max_salt_len) salt_len = max_salt_len;

          snprintf (salt_search->salt_plain_buf, max_salt_len + 1, ":%s:%s:%s:%s:%08x%08x%08x%08x",
            nonce_pos,
            nonce_count_pos,
            nonce_client_pos,
            qop_pos,
            dgst[0].buf.md5[0],
            dgst[0].buf.md5[1],
            dgst[0].buf.md5[2],
            dgst[0].buf.md5[3]);
        }
        else
        {
          salt_len = 1 + nonce_len + 1 + 32;

          if (salt_len > max_salt_len) salt_len = max_salt_len;

          snprintf (salt_search->salt_plain_buf, max_salt_len + 1, ":%s:%08x%08x%08x%08x",
            nonce_pos,
            dgst[0].buf.md5[0],
            dgst[0].buf.md5[1],
            dgst[0].buf.md5[2],
            dgst[0].buf.md5[3]);
        }

        salt_search->salt_plain_len = salt_len;

        // additional_plain_struct = $user . ":" . $realm . ":"

        uint user_len  = strlen (user_pos);
        uint realm_len = strlen (realm_pos);

        uint32_t i;

        for (i = 0; i < 4; i++)
        {
          uint additional_plain_max_len = sizeof (salt_search->additional_plain_struct[i].buf);

          char *additional_plain_ptr = (char *) salt_search->additional_plain_struct[i].buf;

          memset (&salt_search->additional_plain_struct[i].buf, 0, additional_plain_max_len);

          int buf_len = snprintf (additional_plain_ptr, additional_plain_max_len, "%s:%s:", user_pos, realm_pos);

          int expected_buf_len = user_len + 1 + realm_len + 1;

          if (buf_len != expected_buf_len) // this should never occur because buffer is large enough, but we better have a check anyway
          {
            log_warning ("username and realm (%d bytes) do not fit within the buffer (%d bytes)", expected_buf_len, buf_len);
          }

          salt_search->additional_plain_struct[i].len = buf_len;
        }

        salt_t *salt;

        void *ptr;

        if ((ptr = __hc_tfind (salt_search, &root_salts, compare_salt)) == NULL)
        {
          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt_search;

          db->salts_cnt++;

          salt = salt_search;

          __hc_tsearch (salt_search, &root_salts, compare_salt);
        }
        else
        {
          myfree (salt_search->salt_plain_buf);

          myfree (salt_search);

          myfree (sip->URI_server);
          myfree (sip->URI_client);

          myfree (sip->user);
          myfree (sip->realm);
          myfree (sip->method);

          myfree (sip->URI_prefix);
          myfree (sip->URI_resource);
          myfree (sip->URI_suffix);

          myfree (sip->nonce);
          myfree (sip->nonce_client);
          myfree (sip->nonce_count);

          myfree (sip->qop);
          myfree (sip->directive);

          myfree (sip);

          salt = *(salt_t **) ptr;
        }

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mymalloc (sizeof (index_t *));

          salt->indexes_buf[0] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_SHA256B64)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        sha256b64_decode ((unsigned char *) digest->buf.sha256, (unsigned char *) hash_buf);

        digest->buf.sha256[0] = __builtin_bswap32 (digest->buf.sha256[0]);
        digest->buf.sha256[1] = __builtin_bswap32 (digest->buf.sha256[1]);
        digest->buf.sha256[2] = __builtin_bswap32 (digest->buf.sha256[2]);
        digest->buf.sha256[3] = __builtin_bswap32 (digest->buf.sha256[3]);
        digest->buf.sha256[4] = __builtin_bswap32 (digest->buf.sha256[4]);
        digest->buf.sha256[5] = __builtin_bswap32 (digest->buf.sha256[5]);
        digest->buf.sha256[6] = __builtin_bswap32 (digest->buf.sha256[6]);
        digest->buf.sha256[7] = __builtin_bswap32 (digest->buf.sha256[7]);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.sha256[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
      else if (engine_parameter->hash_type == HASH_TYPE_PLAIN)
      {
        /* digest */

        digest_t *digest = init_new_digest ();

        memcpy (digest->buf.plain, hash_buf, hash_len);

        /* salt */

        if (db->salts_cnt == 0)
        {
          salt_t *salt = init_new_salt ();

          incr_salt_ptrs (db);

          db->salts_buf[db->salts_cnt] = salt;

          db->salts_cnt++;
        }

        salt_t *salt = db->salts_buf[0];

        /* index */

        if (salt->indexes_buf == NULL)
        {
          salt->indexes_buf = mycalloc (INDEX_SIZE[INDEX_BITS], sizeof (index_t *));

          memset (salt->indexes_buf, 0, INDEX_SIZE[INDEX_BITS] * sizeof (index_t *));
        }

        if (salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS] == NULL)
        {
          salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS] = init_new_index ();

          salt->indexes_cnt++;
        }

        index_t *index = salt->indexes_buf[digest->buf.md5[0] >> INDEX_BITS];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        add_user (engine_parameter, index->digests_buf[index->digests_cnt], entire_line_buf, line_buf);

        index->digests_cnt++;

        status_info.proc_hashes++;
      }

      if (engine_parameter->show == 1) handle_show_request (out_fp, engine_parameter, pot, entire_line_buf, entire_line_len, hash_buf, salt_buf, salt_len, line_buf - entire_line_buf - 1);
      if (engine_parameter->left == 1) handle_left_request (out_fp, engine_parameter, pot, entire_line_buf, entire_line_len, hash_buf, salt_buf, salt_len);
    }
  }

  /*
   * potfile (show and left)
   */

  if (engine_parameter->show == 1 || engine_parameter->left == 1)
  {
    // cleanup
    uint i;

    if (pot != NULL)
    {
      for (i = 0; i < pot->pot_cnt; i++)
      {
        hash_t *hash_buf = &pot[i].hash;

        if (hash_buf->salt != NULL)
        {
          myfree (hash_buf->salt->salt_plain_buf);

          myfree (hash_buf->salt);
        }

        myfree (hash_buf->digest.plain);
      }

      myfree (pot);
    }

    if (out_fp != NULL) fclose (out_fp);

    exit (0);
  }

  if (separator_warnings > 0)
  {
    log_warning ("%d salts contain separator '%c'", separator_warnings, engine_parameter->separator);
  }

  if (engine_parameter->salt_type == SALT_TYPE_EXTERNAL)
  {
    salt_t *salt_src = db->salts_buf[0];

    uint32_t salts_idx;

    for (salts_idx = 1; salts_idx < db->salts_cnt; salts_idx++)
    {
      salt_t *salt_dst = db->salts_buf[salts_idx];

      salt_dst->indexes_buf   = salt_src->indexes_buf;
      salt_dst->indexes_cnt   = salt_src->indexes_cnt;
      salt_dst->indexes_avail = salt_src->indexes_avail;
      salt_dst->indexes_found = salt_src->indexes_found;
    }
  }

  /*
   * finally, sort them
   */

  if (status_info.proc_hashes == 0)
  {
    log_error ("No hashes loaded");

    exit (-1);
  }

  if (engine_parameter->salt_type == SALT_TYPE_NONE || engine_parameter->salt_type == SALT_TYPE_EXTERNAL)
  {
    salt_t *salt = db->salts_buf[0];

    uint32_t indexes_idx;

    for (indexes_idx = 0; indexes_idx < INDEX_SIZE[INDEX_BITS]; indexes_idx++)
    {
      index_t *index = salt->indexes_buf[indexes_idx];

      if (index == NULL) continue;

      switch (engine_parameter->hash_type)
      {
        case HASH_TYPE_MD5:           qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA1:          qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_MYSQL:         qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_mysql);      break;
        case HASH_TYPE_PHPASS:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_MD5UNIX:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_MD5SUN:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA1B64:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_SHA1B64S:      qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_MD4:           qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md4);        break;
        case HASH_TYPE_DCC:           qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md4);        break;
        case HASH_TYPE_MD5CHAP:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_MSSQL2000:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_MSSQL2005:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_EPIV6:         qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_SHA256:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_MD5APR:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA512:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_SHA512UNIX:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_DESCRYPT:      qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_descrypt);   break;
        case HASH_TYPE_KECCAK:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_keccak);     break;
        case HASH_TYPE_WPA:           qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_PSAFE3:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_IKEPSK_MD5:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_IKEPSK_SHA1:   qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_NETNTLMv1:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_netntlmv1);  break;
        case HASH_TYPE_NETNTLMv2:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_MD5AIX:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA1AIX:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_SHA256AIX:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_SHA512AIX:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_GOST:          qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_gost);       break;
        case HASH_TYPE_SHA1FORTIGATE: qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_PBKDF2OSX:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_PBKDF2GRUB:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_MD5CISCO_PIX:  qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA1ORACLE:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_HMACRAKP:      qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_BCRYPT:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_bcrypt);     break;
        case HASH_TYPE_SHA256UNIX:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_PLAIN:         qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_plain);      break;
        case HASH_TYPE_EPIV6_4:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_SHA512B64S:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_SCRYPT:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_CISCO_SECRET9: qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_PHPS:          qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_DJANGOSHA1:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_HMAIL:         qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_MEDIAWIKI_B:   qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_CISCO_SECRET8: qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_DJANGO_SHA256: qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_PEOPLESOFT:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_CRAM_MD5:      qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_DRUPAL7:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_MD5CISCO_ASA:  qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SAP_H_SHA1:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_PRESTASHOP:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA256B64:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
      }
    }
  }
  else
  {
    uint32_t salts_idx;

    for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
    {
      salt_t *salt = db->salts_buf[salts_idx];

      index_t *index = salt->indexes_buf[0];

      if (index == NULL) continue;

      switch (engine_parameter->hash_type)
      {
        case HASH_TYPE_MD5:           qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA1:          qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_MYSQL:         qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_mysql);      break;
        case HASH_TYPE_PHPASS:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_MD5UNIX:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_MD5SUN:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA1B64:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_SHA1B64S:      qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_MD4:           qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md4);        break;
        case HASH_TYPE_DCC:           qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md4);        break;
        case HASH_TYPE_MD5CHAP:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_MSSQL2000:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_MSSQL2005:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_EPIV6:         qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_SHA256:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_MD5APR:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA512:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_SHA512UNIX:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_DESCRYPT:      qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_descrypt);   break;
        case HASH_TYPE_KECCAK:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_keccak);     break;
        case HASH_TYPE_WPA:           qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_PSAFE3:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_IKEPSK_MD5:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_IKEPSK_SHA1:   qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_NETNTLMv1:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_netntlmv1);  break;
        case HASH_TYPE_NETNTLMv2:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_MD5AIX:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA1AIX:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_SHA256AIX:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_SHA512AIX:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_GOST:          qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_gost);       break;
        case HASH_TYPE_SHA1FORTIGATE: qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_PBKDF2OSX:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_PBKDF2GRUB:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_MD5CISCO_PIX:  qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA1ORACLE:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_HMACRAKP:      qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_BCRYPT:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_bcrypt);     break;
        case HASH_TYPE_SHA256UNIX:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_PLAIN:         qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_plain);      break;
        case HASH_TYPE_EPIV6_4:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_SHA512B64S:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_SCRYPT:        qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_CISCO_SECRET9: qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_PHPS:          qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_DJANGOSHA1:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_HMAIL:         qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_MEDIAWIKI_B:   qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_CISCO_SECRET8: qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_DJANGO_SHA256: qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
        case HASH_TYPE_PEOPLESOFT:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_CRAM_MD5:      qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_DRUPAL7:       qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha512);     break;
        case HASH_TYPE_MD5CISCO_ASA:  qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SAP_H_SHA1:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha1);       break;
        case HASH_TYPE_PRESTASHOP:    qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_md5);        break;
        case HASH_TYPE_SHA256B64:     qsort (index->digests_buf, index->digests_cnt, sizeof (digest_t *), compare_digest_sha256);     break;
      }
    }
  }

  // fill the salt_plain_struct, for instance to allow a call to sha*_update_sse2() with the salt field

  uint32_t salts_idx;

  if (engine_parameter->hash_mode != 2811 && engine_parameter->hash_mode != 3610 && engine_parameter->hash_mode != 3910 &&
      engine_parameter->hash_mode !=  121 && engine_parameter->hash_mode !=  122 && engine_parameter->hash_mode != 3720 &&
      engine_parameter->hash_mode != 3721 && engine_parameter->hash_mode != 1100 && engine_parameter->hash_mode != 1722)
  {
    for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
    {
      salt_t *salt = db->salts_buf[salts_idx];

      uint32_t i;

      for (i = 0; i < 4; i++)
      {
        memcpy (&salt->salt_plain_struct[i], salt->salt_plain_buf, salt->salt_plain_len);

        salt->salt_plain_struct[i].len = salt->salt_plain_len;
      }
    }
  }
}

void load_words (FILE *fp, words_t *words, engine_parameter_t *engine_parameter)
{
  size_t size;

  if ((size = fread (words->cache_buf, 1, words->cache_avail - 0x1000, fp)) > 0)
  {
    while (words->cache_buf[size - 1] != '\n')
    {
      if (feof (fp))
      {
        words->cache_buf[size] = '\n';

        size++;

        continue;
      }

      words->cache_buf[size] = fgetc (fp);

      if (size == words->cache_avail - 1)
      {
        if (words->cache_buf[size] != '\n') continue;
      }

      size++;
    }

    words->cache_cnt = size;

    char *pos = &words->cache_buf[0];

    while (pos != &words->cache_buf[size])
    {
      uint32_t i = 0;

      while ((&pos[i + 1] != &words->cache_buf[size]) && (pos[i] != '\n')) i++;

      add_word (pos, i, words, engine_parameter);

      pos += i + 1;
    }

    incr_words_buf (words);

    words->words_buf[words->words_cnt + 0] = words->cache_buf;
    words->words_len[words->words_cnt + 0] = 0;
    words->words_buf[words->words_cnt + 1] = words->cache_buf;
    words->words_len[words->words_cnt + 1] = 0;
    words->words_buf[words->words_cnt + 2] = words->cache_buf;
    words->words_len[words->words_cnt + 2] = 0;
    words->words_buf[words->words_cnt + 3] = words->cache_buf;
    words->words_len[words->words_cnt + 3] = 0;
  }
}

char *get_install_dir (char *progname)
{
  char *install_dir = mystrdup (progname);

  char *last_slash;

  if ((last_slash = strrchr (install_dir, '/')) != NULL)
  {
    *last_slash = 0;
  }
  else if ((last_slash = strrchr (install_dir, '\\')) != NULL)
  {
    *last_slash = 0;
  }
  else
  {
    install_dir[0] = '.';
    install_dir[1] = 0;
  }

  return (install_dir);
}

#ifdef _WIN32

void cpuid (uint32_t CPUInfo[4], const uint32_t InfoType)
{
  __cpuid ((int *) CPUInfo, (int) InfoType);
}

#else

void cpuid (uint32_t CPUInfo[4], const uint32_t InfoType)
{
  __asm__ __volatile__
  (
    "cpuid" :
      "=a" (CPUInfo[0]),
      "=b" (CPUInfo[1]),
      "=c" (CPUInfo[2]),
      "=d" (CPUInfo[3]) :
      "a"  (InfoType),
      "c"  (0)
  );
}

#endif

uint32_t avx_enabled ()
{
  uint32_t info[4];

  cpuid (info, 0);

  if (info[0] >= 0x00000001)
  {
    cpuid (info, 0x00000001);

    if (info[2] & (1 << 28)) return 1;
  }

  return 0;
}

uint32_t avx2_enabled ()
{
  uint32_t info[4];

  cpuid (info, 0);

  if (info[0] >= 0x00000001)
  {
    cpuid (info, 0x00000007);

    if (info[1] & (1 << 5)) return 1;
  }

  return 0;
}

uint32_t sse2_enabled ()
{
  uint32_t info[4];

  cpuid (info, 0);

  if (info[0] >= 0x00000001)
  {
    cpuid (info, 0x00000001);

    if (info[3] & (1 << 26)) return 1;
  }

  return 0;
}

uint32_t x64_enabled ()
{
  uint32_t info[4];

  cpuid (info, 0x80000000);

  if (info[0] >= 0x80000001)
  {
    cpuid (info, 0x80000001);

    if (info[3] & (1 << 29)) return 1;
  }

  return 0;
}

uint32_t xop_enabled ()
{
  uint32_t info[4];

  cpuid (info, 0x80000000);

  if (info[0] >= 0x80000001)
  {
    cpuid (info, 0x80000001);

    if (info[2] & (1 << 11)) return 1;
  }

  return 0;
}

int main (int argc, char *argv[])
{
  time (&proc_start);

  setvbuf (stdout, NULL, _IONBF, 0);

  uint32_t usage_view       = USAGE_VIEW;
  uint32_t version_view     = VERSION_VIEW;
  uint32_t quiet            = QUIET;
  uint32_t stdout_mode      = STDOUT_MODE;
  uint32_t remove           = REMOVE;
  uint32_t potfile_disable  = POTFILE_DISABLE;
  uint32_t output_format    = OUTFILE_FORMAT;
  uint32_t output_autohex   = OUTFILE_AUTOHEX;
  uint32_t hex_salt         = HEX_SALT;
  uint32_t benchmark        = BENCHMARK;
  uint32_t hex_charset      = HEX_CHARSET;
  uint32_t status           = STATUS;
  uint32_t status_timer     = STATUS_TIMER;
  uint32_t status_automat   = STATUS_AUTOMAT;
  uint32_t runtime          = RUNTIME;
  uint32_t attack_mode      = ATTACK_MODE;
  uint32_t hash_mode        = HASH_MODE;
  uint32_t debug_mode       = DEBUG_MODE;
  char    *file_rules       = NULL;
  char    *file_output      = NULL;
  char    *file_debug       = NULL;
  char    *file_salts       = NULL;
  uint32_t num_threads      = NUM_THREADS;
  uint32_t cache_size       = CACHE_SIZE;
  uint64_t words_skip       = WORDS_SKIP;
  uint64_t words_limit      = WORDS_LIMIT;
  uint32_t rp_gen           = RP_GEN;
  uint32_t rp_gen_func_min  = RP_GEN_FUNC_MIN;
  uint32_t rp_gen_func_max  = RP_GEN_FUNC_MAX;
  uint32_t rp_gen_seed      = RP_GEN_SEED;
  uint32_t username         = USERNAME;
  uint32_t show             = SHOW;
  uint32_t left             = LEFT;
  char     separator        = SEPARATOR;
  uint32_t toggle_min       = TOGGLE_MIN;
  uint32_t toggle_max       = TOGGLE_MAX;
  uint32_t increment        = INCREMENT;
  uint32_t increment_min    = INCREMENT_MIN;
  uint32_t increment_max    = INCREMENT_MAX;
  int      pw_min           = PW_MIN;
  int      pw_max           = PW_MAX;
  uint32_t wl_dist_len      = WL_DIST_LEN;
  uint32_t wl_max           = WL_MAX;
  uint32_t case_permute     = CASE_PERMUTE;
  uint32_t perm_min         = PERM_MIN;
  uint32_t perm_max         = PERM_MAX;
  uint32_t table_min        = TABLE_MIN;
  uint32_t table_max        = TABLE_MAX;
  int      elem_cnt_min     = ELEM_CNT_MIN;
  int      elem_cnt_max     = ELEM_CNT_MAX;
  char    *file_table       = NULL;
  char    *custom_charset_1 = NULL;
  char    *custom_charset_2 = NULL;
  char    *custom_charset_3 = NULL;
  char    *custom_charset_4 = NULL;

  /*
   * preinit: getopt
   */

  #define IDX_HELP            'h'
  #define IDX_VERSION         'V'
  #define IDX_QUIET           1002
  #define IDX_STDOUT_MODE     1003
  #define IDX_REMOVE          1004
  #define IDX_POTFILE_DISABLE 1005
  #define IDX_ATTACK_MODE     'a'
  #define IDX_HASH_MODE       'm'
  #define IDX_RULES_FILE      'r'
  #define IDX_OUTFILE         'o'
  #define IDX_OUTFILE_FORMAT  1006
  #define IDX_HEX_SALT        1007
  #define IDX_HEX_CHARSET     1008
  #define IDX_STATUS          1011
  #define IDX_STATUS_TIMER    1012
  #define IDX_STATUS_AUTOMAT  1013
  #define IDX_RUNTIME         1010
  #define IDX_BENCHMARK       'b'
  #define IDX_DEBUG_FILE      10001
  #define IDX_DEBUG_MODE      10002
  #define IDX_USERNAME        10003
  #define IDX_SHOW            10004
  #define IDX_LEFT            10005
  #define IDX_SALT_FILE       'e'
  #define IDX_THREADS         'n'
  #define IDX_SEGMENT_SIZE    'c'
  #define IDX_WORDS_SKIP      's'
  #define IDX_WORDS_LIMIT     'l'
  #define IDX_RP_GEN          'g'
  #define IDX_RP_GEN_FUNC_MIN 11001
  #define IDX_RP_GEN_FUNC_MAX 11002
  #define IDX_RP_GEN_SEED     11003
  #define IDX_SEPARATOR       'p'
  #define IDX_OUTFILE_AUTOHEX_DISABLE 11004
  #define IDX_TOGGLE_MIN      2001
  #define IDX_TOGGLE_MAX      2002
  #define IDX_INCREMENT       'i'
  #define IDX_INCREMENT_MIN   3002
  #define IDX_INCREMENT_MAX   3003
  #define IDX_PW_MIN          3004
  #define IDX_PW_MAX          3005
  #define IDX_CUSTOM_CHARSET_1 '1'
  #define IDX_CUSTOM_CHARSET_2 '2'
  #define IDX_CUSTOM_CHARSET_3 '3'
  #define IDX_CUSTOM_CHARSET_4 '4'
  #define IDX_PERM_MIN        4001
  #define IDX_PERM_MAX        4002
  #define IDX_TOGGLE_MIN      2001
  #define IDX_TOGGLE_MAX      2002
  #define IDX_TABLE_MIN       5001
  #define IDX_TABLE_MAX       5002
  #define IDX_TABLE_FILE      't'
  #define IDX_ELEM_CNT_MIN    6001
  #define IDX_ELEM_CNT_MAX    6002
  #define IDX_WL_DIST_LEN     6003
  #define IDX_WL_MAX          6004
  #define IDX_CASE_PERMUTE    6005

  struct option long_options[] =
  {
    {"help",            no_argument,       0, IDX_HELP},
    {"version",         no_argument,       0, IDX_VERSION},
    {"quiet",           no_argument,       0, IDX_QUIET},
    {"stdout",          no_argument,       0, IDX_STDOUT_MODE},
    {"username",        no_argument,       0, IDX_USERNAME},
    {"show",            no_argument,       0, IDX_SHOW},
    {"left",            no_argument,       0, IDX_LEFT},
    {"remove",          no_argument,       0, IDX_REMOVE},
    {"potfile-disable", no_argument,       0, IDX_POTFILE_DISABLE},
    {"attack-mode",     required_argument, 0, IDX_ATTACK_MODE},
    {"hash-type",       required_argument, 0, IDX_HASH_MODE},
    {"debug-mode",      required_argument, 0, IDX_DEBUG_MODE},
    {"rules-file",      required_argument, 0, IDX_RULES_FILE},
    {"outfile",         required_argument, 0, IDX_OUTFILE},
    {"outfile-format",  required_argument, 0, IDX_OUTFILE_FORMAT},
    {"hex-charset",     no_argument,       0, IDX_HEX_CHARSET},
    {"status",          no_argument,       0, IDX_STATUS},
    {"status-timer",    required_argument, 0, IDX_STATUS_TIMER},
    {"status-automat",  no_argument,       0, IDX_STATUS_AUTOMAT},
    {"runtime",         required_argument, 0, IDX_RUNTIME},
    {"benchmark",       no_argument,       0, IDX_BENCHMARK},
    {"hex-salt",        no_argument,       0, IDX_HEX_SALT},
    {"debug-file",      required_argument, 0, IDX_DEBUG_FILE},
    {"salt-file",       required_argument, 0, IDX_SALT_FILE},
    {"threads",         required_argument, 0, IDX_THREADS},
    {"segment-size",    required_argument, 0, IDX_SEGMENT_SIZE},
    {"words-skip",      required_argument, 0, IDX_WORDS_SKIP},
    {"words-limit",     required_argument, 0, IDX_WORDS_LIMIT},
    {"generate-rules",  required_argument, 0, IDX_RP_GEN},
    {"generate-rules-func-min",
                        required_argument, 0, IDX_RP_GEN_FUNC_MIN},
    {"generate-rules-func-max",
                        required_argument, 0, IDX_RP_GEN_FUNC_MAX},
    {"generate-rules-seed",
                        required_argument, 0, IDX_RP_GEN_SEED},
    {"outfile-autohex-disable",
                        no_argument,       0, IDX_OUTFILE_AUTOHEX_DISABLE},
    {"separator",       required_argument, 0, IDX_SEPARATOR},
    {"toggle-min",      required_argument, 0, IDX_TOGGLE_MIN},
    {"toggle-max",      required_argument, 0, IDX_TOGGLE_MAX},
    {"increment",       no_argument,       0, IDX_INCREMENT},
    {"increment-min",   required_argument, 0, IDX_INCREMENT_MIN},
    {"increment-max",   required_argument, 0, IDX_INCREMENT_MAX},
    {"pw-min",          required_argument, 0, IDX_PW_MIN},
    {"pw-max",          required_argument, 0, IDX_PW_MAX},
    {"perm-min",        required_argument, 0, IDX_PERM_MIN},
    {"perm-max",        required_argument, 0, IDX_PERM_MAX},
    {"table-min",       required_argument, 0, IDX_TABLE_MIN},
    {"table-max",       required_argument, 0, IDX_TABLE_MAX},
    {"table-file",      required_argument, 0, IDX_TABLE_FILE},
    {"elem-cnt-min",    required_argument, 0, IDX_ELEM_CNT_MIN},
    {"elem-cnt-max",    required_argument, 0, IDX_ELEM_CNT_MAX},
    {"wl-dist-len",     no_argument,       0, IDX_WL_DIST_LEN},
    {"wl-max",          required_argument, 0, IDX_WL_MAX},
    {"case-permute",    no_argument,       0, IDX_CASE_PERMUTE},
    {"custom-charset1", required_argument, 0, IDX_CUSTOM_CHARSET_1},
    {"custom-charset2", required_argument, 0, IDX_CUSTOM_CHARSET_2},
    {"custom-charset3", required_argument, 0, IDX_CUSTOM_CHARSET_3},
    {"custom-charset4", required_argument, 0, IDX_CUSTOM_CHARSET_4},
    {0, 0, 0, 0}
  };

  int option_index = 0;

  int output_format_chgd = 0;
  int rp_gen_seed_chgd   = 0;
  int num_threads_chgd   = 0;
  int runtime_chgd       = 0;
  int hash_mode_chgd     = 0;
  int attack_mode_chgd   = 0;
  int status_timer_chgd  = 0;
  int increment_min_chgd = 0;
  int increment_max_chgd = 0;
  int pw_min_chgd        = 0;
  int pw_max_chgd        = 0;
  int elem_cnt_max_chgd  = 0;

  int c;

  while ((c = getopt_long (argc, argv, "hVbia:m:r:t:o:e:n:1:2:3:4:c:s:l:g:p:", long_options, &option_index)) != -1)
  {
    switch (c)
    {
      case IDX_HELP:            usage_view         = 1;               break;
      case IDX_VERSION:         version_view       = 1;               break;
      case IDX_QUIET:           quiet              = 1;               break;
      case IDX_STDOUT_MODE:     stdout_mode        = 1;               break;
      case IDX_POTFILE_DISABLE: potfile_disable    = 1;               break;
      case IDX_USERNAME:        username           = 1;               break;
      case IDX_SHOW:            show               = 1;               break;
      case IDX_LEFT:            left               = 1;               break;
      case IDX_REMOVE:          remove             = 1;               break;
      case IDX_ATTACK_MODE:     attack_mode        = atoi (optarg);
                                attack_mode_chgd   = 1;               break;
      case IDX_HASH_MODE:       hash_mode          = atoi (optarg);
                                hash_mode_chgd     = 1;               break;
      case IDX_DEBUG_MODE:      debug_mode         = atoi (optarg);   break;
      case IDX_RULES_FILE:      file_rules         = optarg;          break;
      case IDX_OUTFILE:         file_output        = optarg;          break;
      case IDX_OUTFILE_FORMAT:  output_format      = atoi (optarg);
                                output_format_chgd = 1;               break;
      case IDX_HEX_SALT:        hex_salt           = 1;               break;
      case IDX_HEX_CHARSET:     hex_charset        = 1;               break;
      case IDX_STATUS:          status             = 1;               break;
      case IDX_STATUS_TIMER:    status_timer       = atoi (optarg);
                                status_timer_chgd  = 1;               break;
      case IDX_STATUS_AUTOMAT:  status_automat     = 1;               break;
      case IDX_RUNTIME:         runtime            = atoi (optarg);
                                runtime_chgd       = 1;               break;
      case IDX_BENCHMARK:       benchmark          = 1;               break;
      case IDX_DEBUG_FILE:      file_debug         = optarg;          break;
      case IDX_SALT_FILE:       file_salts         = optarg;          break;
      case IDX_THREADS:         num_threads_chgd   = 1;
                                num_threads        = atoi (optarg);   break;
      case IDX_SEGMENT_SIZE:    cache_size         = atoi (optarg);   break;
      case IDX_WORDS_SKIP:      words_skip         = atoll (optarg);  break;
      case IDX_WORDS_LIMIT:     words_limit        = atoll (optarg);  break;
      case IDX_RP_GEN:          rp_gen             = atoi (optarg);   break;
      case IDX_RP_GEN_FUNC_MIN: rp_gen_func_min    = atoi (optarg);   break;
      case IDX_RP_GEN_FUNC_MAX: rp_gen_func_max    = atoi (optarg);   break;
      case IDX_RP_GEN_SEED:     rp_gen_seed        = atoi (optarg);
                                rp_gen_seed_chgd   = 1;               break;
      case IDX_OUTFILE_AUTOHEX_DISABLE:
                                output_autohex     = 0;               break;
      case IDX_SEPARATOR:       separator          = optarg[0];       break;
      case IDX_TOGGLE_MIN:      toggle_min         = atoi (optarg);   break;
      case IDX_TOGGLE_MAX:      toggle_max         = atoi (optarg);   break;
      case IDX_INCREMENT:       increment          = 1;               break;
      case IDX_INCREMENT_MIN:   increment_min      = atoi (optarg);
                                increment_min_chgd = 1;               break;
      case IDX_INCREMENT_MAX:   increment_max      = atoi (optarg);
                                increment_max_chgd = 1;               break;
      case IDX_PW_MIN:          pw_min             = atoi (optarg);
                                pw_min_chgd        = 1;               break;
      case IDX_PW_MAX:          pw_max             = atoi (optarg);
                                pw_max_chgd        = 1;               break;
      case IDX_PERM_MIN:        perm_min           = atoi (optarg);   break;
      case IDX_PERM_MAX:        perm_max           = atoi (optarg);   break;
      case IDX_TABLE_MIN:       table_min          = atoi (optarg);   break;
      case IDX_TABLE_MAX:       table_max          = atoi (optarg);   break;
      case IDX_TABLE_FILE:      file_table         = optarg;          break;
      case IDX_ELEM_CNT_MIN:    elem_cnt_min       = atoi (optarg);   break;
      case IDX_ELEM_CNT_MAX:    elem_cnt_max       = atoi (optarg);
                                elem_cnt_max_chgd  = 1;               break;
      case IDX_WL_DIST_LEN:     wl_dist_len        = 1;               break;
      case IDX_WL_MAX:          wl_max             = atoi (optarg);   break;
      case IDX_CASE_PERMUTE:    case_permute       = 1;               break;
      case IDX_CUSTOM_CHARSET_1:  custom_charset_1 = optarg;          break;
      case IDX_CUSTOM_CHARSET_2:  custom_charset_2 = optarg;          break;
      case IDX_CUSTOM_CHARSET_3:  custom_charset_3 = optarg;          break;
      case IDX_CUSTOM_CHARSET_4:  custom_charset_4 = optarg;          break;

      default: exit (-1);
    }
  }

  /*
   * cpu check
   */

/*
  #ifdef __XOP__
  if (xop_enabled () == 0)
  {
    log_error ("CPU is not capable of XOP instruction set");

    exit (-1);
  }
  #endif

  #ifdef __AVX__
  if (avx_enabled () == 0)
  {
    log_error ("CPU is not capable of AVX instruction set");

    exit (-1);
  }
  #endif

  #ifdef __AVX2__
  if (avx2_enabled () == 0)
  {
    log_error ("CPU is not capable of AVX2 instruction set");

    exit (-1);
  }
  #endif

  #ifdef __x86_64__
  if (x64_enabled () == 0)
  {
    log_error ("CPU is not capable of 64 bit instruction set");

    exit (-1);
  }
  #endif

  if (sse2_enabled () == 0)
  {
    log_error ("CPU is not capable of SSE2 instruction set");

    exit (-1);
  }
*/
  /*
   * sanity check
   */

  if (version_view == 1)
  {
    log_info (VERSION_TXT);

    exit (-1);
  }

  if (usage_view == 1)
  {
    usage_big_print (PROGNAME);

    exit (-1);
  }

  int optreq = optind + 2;

  if (benchmark == 1)
  {
    optreq = optind;
  }

  if (stdout_mode)
  {
    quiet = 1;

    num_threads = 1;
    num_threads_chgd = 1;

    hash_mode = 666;

    optreq -= 1;
  }

  if (show == 0 && left == 0)
  {
    if (optreq > argc)
    {
      usage_mini_print (PROGNAME);

      exit (-1);
    }
  }

  if (attack_mode == 5)
  {
    if (file_table == NULL)
    {
      log_error ("--table-file must be specified in --attack-mode 5");

      exit (-1);
    }
  }

  if (attack_mode == 6)
  {
    log_error ("unsupported attack_mode -a 6");

    exit (-1);
  }

  if (attack_mode == 7)
  {
    log_error ("unsupported attack_mode -a 7");

    exit (-1);
  }

  if (attack_mode > 8)
  {
    log_error ("attack_mode > 8");

    exit (-1);
  }

  if (hash_mode > 99999)
  {
    log_error ("hash_mode > 99999");

    exit (-1);
  }

  if (debug_mode > 4)
  {
    log_error ("debug_mode > 4");

    exit (-1);
  }

  if (cache_size < 1)
  {
    log_error ("cache_size < 1");

    exit (-1);
  }

  if (attack_mode == 8)
  {
    cache_size *= 8;
  }

  if (toggle_min > toggle_max)
  {
    log_error ("toggle_min > toggle_max");

    exit (-1);
  }

  if (rp_gen_func_min > rp_gen_func_max)
  {
    log_error ("rp_gen_func_min > rp_gen_func_max");

    exit (-1);
  }

  if (increment_min > increment_max)
  {
    log_error ("increment min > increment_max");

    exit (-1);
  }

  if (pw_min_chgd)
  {
    if (attack_mode != 8)
    {
      log_error ("--pw-min is a reserved parameter for PRINCE attack mode");

      exit (-1);
    }
  }

  if (pw_max_chgd)
  {
    if (attack_mode != 8)
    {
      log_error ("--pw-max is a reserved parameter for PRINCE attack mode");

      exit (-1);
    }
  }

  if (increment_min < INCREMENT_MIN)
  {
    log_error ("invalid increment minimum specified");

    exit (-1);
  }

  if (increment_max > INCREMENT_MAX)
  {
    log_error ("invalid increment maximum specified");

    exit (-1);
  }

  if ((increment == 0) && (increment_min_chgd == 1))
  {
    log_error ("increment-min is only supported together with increment switch");

    return (-1);
  }

  if ((increment == 0) && (increment_max_chgd == 1))
  {
    log_error ("increment-max is only supported together with the increment switch");

    return (-1);
  }

  if (increment)
  {
    if (attack_mode != 3)
    {
      log_error ("increment mode is only supported for mask attack mode");

      return (-1);
    }
  }

  if (increment)
  {
    if (attack_mode == 8)
    {
      log_error ("increment switch not supported in PRINCE attack mode. Please use --pw-min and --pw-max instead");

      return (-1);
    }
  }

  if (perm_min > perm_max)
  {
    log_error ("perm_min > perm_max");

    exit (-1);
  }

  if (table_min > table_max)
  {
    log_error ("table_min > table_max");

    exit (-1);
  }

  if (pw_min <= 0)
  {
    log_error ("Value of --pw-min (%d) must be greater than %d\n", pw_min, 0);

    return (-1);
  }

  if (pw_max <= 0)
  {
    log_error ("Value of --pw-max (%d) must be greater than %d\n", pw_max, 0);

    return (-1);
  }

  if (elem_cnt_min <= 0)
  {
    log_error ("Value of --elem-cnt-min (%d) must be greater than %d\n", elem_cnt_min, 0);

    return (-1);
  }

  if (elem_cnt_max <= 0)
  {
    log_error ("Value of --elem-cnt-max (%d) must be greater than %d\n", elem_cnt_max, 0);

    return (-1);
  }

  if (pw_min > pw_max)
  {
    log_error ("Value of --pw-min (%d) must be smaller or equal than the value of --pw-max (%d)\n", pw_min, pw_max);

    return (-1);
  }

  if (elem_cnt_min > elem_cnt_max)
  {
    log_error ("Value of --elem-cnt-min (%d) must be smaller or equal than value of --elem-cnt-max (%d)\n", elem_cnt_min, elem_cnt_max);

    return (-1);
  }

  if (pw_min < IN_LEN_MIN)
  {
    log_error ("Value of --pw-min (%d) must be greater or equal than %d\n", pw_min, IN_LEN_MIN);

    return (-1);
  }

  if (pw_max > OUT_LEN_MAX)
  {
    log_error ("Value of --pw-max (%d) must be smaller or equal than %d\n", pw_max, OUT_LEN_MAX);

    return (-1);
  }

  if (elem_cnt_max > pw_max)
  {
    log_error ("Value of --elem-cnt-max (%d) must be smaller or equal than value of --pw-max (%d)\n", elem_cnt_max, pw_max);

    return (-1);
  }

  if (num_threads_chgd == 1)
  {
    if ((num_threads < MIN_THREADS) || (num_threads > MAX_THREADS))
    {
      log_error ("Number of threads must be between %u-%u", MIN_THREADS, MAX_THREADS);

      exit (-1);
    }
  }

  if ((toggle_min < TOGGLE_MIN) || (toggle_max > TOGGLE_MAX))
  {
    log_error ("Range for number of alphas must be between %u-%u", TOGGLE_MIN, TOGGLE_MAX);

    exit (-1);
  }

  if ((rp_gen_func_min < MIN_FUNCS) || (rp_gen_func_max > MAX_FUNCS))
  {
    log_error ("Range for number of functions must be between %u-%u", MIN_FUNCS, MAX_FUNCS);

    exit (-1);
  }

  if ((remove == 1) && (hash_mode == 2500))
  {
    log_error ("Remove feature disabled for hash_mode: %d", 2500);

    exit (-1);
  }

  if ((remove == 1) && (hash_mode == 5200))
  {
    log_error ("Remove feature disabled for hash_mode: %d", 5200);

    exit (-1);
  }

  if (output_format < 1 || output_format > 15)
  {
    log_error ("Output format not allowed");

    exit (-1);
  }

  if (left == 1)
  {
    if (output_format_chgd == 0)
    {
      output_format = 1;
    }
    else if (output_format > 1)
    {
      log_error ("--outfile-format > 1 not allowed together with --left");

      return (-1);
    }
  }

  if ((show == 1) && (output_format_chgd == 1))
  {
    if ((output_format >= 8) && (output_format <= 15))
    {
      log_error ("--show not allowed together with an outfile format that needs information about the crack position");

      return (-1);
    }
  }

  if (show == 1 && left == 1)
  {
    log_error ("--show cannot be combined with --left");

    exit (-1);
  }

  if (potfile_disable == 1)
  {
    if (show == 1)
    {
      log_error ("--show cannot be combined with --potfile-disable");

      exit (-1);
    }

    if (left == 1)
    {
      log_error ("--left cannot be combined with --potfile-disable");

      exit (-1);
    }
  }

  if (benchmark == 1)
  {
    if (left == 1)
    {
      log_error ("--left cannot be combined with --benchmark");

      exit (-1);
    }

    if (show == 1)
    {
      log_error ("--show cannot be combined with --benchmark");

      exit (-1);
    }

    if (potfile_disable == 1)
    {
      log_error ("--potfile_disable cannot be combined with --benchmark");

      exit (-1);
    }

    if (remove == 1)
    {
      log_error ("--remove cannot be combined with --benchmark");

      exit (-1);
    }

    if (stdout_mode == 1)
    {
      log_error ("--stdout cannot be combined with --benchmark");

      exit (-1);
    }

    if (file_salts != NULL)
    {
      log_error ("--salt-file cannot be combined with --benchmark");

      exit (-1);
    }

    if (attack_mode_chgd == 1)
    {
      if (attack_mode != 3)
      {
        log_error ("--attack-mode can only be set to mask attack in benchmark mode");

        exit (-1);
      }
    }

    attack_mode = 3;
  }

  if (username)
  {
    if ((hash_mode == 2500) || (hash_mode == 5200))
    {
      log_error ("mixing support for user names and hashes of type %s is not supported", strhashtype (hash_mode));

      exit (-1);
    }
  }

  if ((status == 1) && (benchmark == 1))
  {
    if (status_timer != 0)
    {
      log_error ("mixing support for --status and --benchmark is not allowed");

      exit (-1);
    }
  }

  if (status_timer_chgd == 1)
  {
    if (status == 0)
    {
      log_error ("status timer cannot be set since periodic status update (--status) was not enabled");

      exit (-1);
    }
  }

  // allow -r and -g only if attack modes are -a 0 or -a 1

  if (attack_mode > 1)
  {
    if (file_rules != NULL)
    {
      log_error ("rule file is not allowed with attack modes > 1");

      exit (-1);
    }

    if (rp_gen != RP_GEN)
    {
      log_error ("generating rules is not allowed with attack modes > 1");

      exit (-1);
    }
  }

  int n = -1;

  switch (hash_mode)
  {
    case 1:    n =   10; break;
    case 2:    n =   20; break;
    case 3:    n = 2600; break;
    case 4:    n = 3500; break;
    case 5:    n = 2611; break;
    case 6:    n = 3610; break;
    case 7:    n = 3710; break;
    case 8:    n = 3800; break;
    case 9:    n = 2811; break;
    case 15:   n = 2711; break;
    case 31:   n = 4300; break;
    case 103:  n = 4500; break;
    case 104:  n = 4600; break;
    case 105:  n =  121; break;
    case 600:  n =  101; break;
    case 700:  n =  111; break;
    case 800:  n =  124; break;
    case 1200: n = 4800; break;
    case 1300: n =  131; break;
  }

  if (n != -1)
  {
    log_error ("Old -m specified, use -m %d instead", n);

    return (-1);
  }

  /*
   * replace attack-mode 2 with new attack-mode 5
   */

  if (attack_mode == 2)
  {
    attack_mode = 5;

    table_min = toggle_min;
    table_max = toggle_max;

    file_table = "tables/toggle_case.table";
  }

  /*
   * potfile 1
   */

  char *file_pot = POTFILE;

  if (potfile_disable == 1)
  {
    file_pot = NULL;

    if (show == 1) show = 0;
    if (left == 1) left = 0;
  }

  /*
   * benchmark
   */

  if (benchmark == 1)
  {
    if ((runtime_chgd != 1) || (runtime <= 1))
    {
      runtime = 5;
    }

    quiet = 1;

    file_pot = NULL;

    increment_min = 7;
    increment_max = 7;
  }

  /*
   * Automatically determine the number of threads
   */

  if (num_threads_chgd == 0)
  {
    num_threads = get_num_cores ();

    if (num_threads == 0)
    {
      num_threads = NUM_THREADS;
    }
    else if (num_threads > MAX_THREADS)
    {
      num_threads = MAX_THREADS;
    }
  }

  /*
   * pre init
   */

  if (show == 0 && left == 0)
  {
    if ((quiet == 0) || (benchmark == 1)) log_info ("Initializing %s v%.2f with %u threads and %umb segment-size...\n", PROGNAME, ((float) VERSION_BIN) / 100, num_threads, cache_size);

    if (benchmark == 1)
    {
      char *cpu_model_name;

      if (get_cpu_model (&cpu_model_name) == 0)
      {
        log_info ("Device...........: %s", cpu_model_name);
      }

      #ifdef __HC_XOP__
        log_info ("Instruction set..: XOP");
      #endif

      #ifdef __HC_AVX__
        log_info ("Instruction set..: AVX");
      #endif

      #ifdef __HC_AVX2__
        log_info ("Instruction set..: AVX2");
      #endif

      #ifdef __HC_x86_64__
        log_info ("Instruction set..: x86_64");
      #endif

      #ifdef __HC_x86_32__
        log_info ("Instruction set..: x86_32");
      #endif

      log_info ("Number of threads: %i\n", num_threads);
    }
  }

  /*
   * init main buffers
   */

  engine_parameter_t *engine_parameter = init_new_engine_parameter ();

  engine_parameter->attack_mode    = attack_mode;
  engine_parameter->hash_mode      = hash_mode;
  engine_parameter->debug_mode     = debug_mode;
  engine_parameter->num_threads    = num_threads;
  engine_parameter->cache_size     = cache_size;
  engine_parameter->words_skip     = words_skip;
  engine_parameter->words_limit    = words_limit;
  engine_parameter->username       = username;
  engine_parameter->show           = show;
  engine_parameter->left           = left;
  engine_parameter->remove         = remove;
  engine_parameter->separator      = separator;
  engine_parameter->output_autohex = output_autohex;
  engine_parameter->quiet          = quiet;
  engine_parameter->file_output    = file_output;
  engine_parameter->hex_salt       = hex_salt;
  engine_parameter->hashcat_status = STATUS_STARTING;
  engine_parameter->benchmark      = benchmark;
  engine_parameter->maskcnt        = 1;
  engine_parameter->maskpos        = 0;
  engine_parameter->hex_charset    = hex_charset;
  engine_parameter->status_timer   = status_timer;
  engine_parameter->status_automat = status_automat;
  engine_parameter->runtime        = runtime;
  engine_parameter->file_debug     = file_debug;
  engine_parameter->perm_min       = perm_min;
  engine_parameter->perm_max       = perm_max;
  engine_parameter->table_min      = table_min;
  engine_parameter->table_max      = table_max;
  engine_parameter->output_format  = output_format;
  engine_parameter->file_pot       = file_pot;
  engine_parameter->pot            = NULL;
  engine_parameter->ms_paused      = 0;

  rules_t *rules = init_new_rules ();

  words_t *words = init_new_words ();

  words->cache_avail = engine_parameter->cache_size * 1024 * 1024;

  words->cache_buf = mymalloc (words->cache_avail);

  db_t *db = init_new_db ();

  db->rules = rules;

  db->words = words;

  /*
   * init start
   */

  if (rp_gen_seed_chgd == 0)
  {
    srand (proc_start); // i know, don't cry, it doesn't matter
  }
  else
  {
    srand (rp_gen_seed);
  }

  uint algorithm_pos = 0;
  uint algorithm_max = 1;

  uint *algorithms = default_benchmark_algorithms;

  if (benchmark == 1 && hash_mode_chgd == 0) algorithm_max = NUM_DEFAULT_BENCHMARK_ALGORITHMS;

  for (algorithm_pos = 0; algorithm_pos < algorithm_max; algorithm_pos++)
  {
    engine_parameter->hashcat_status = STATUS_INIT;

    hashcat_running = 1;

    status_info.engine_parameter = engine_parameter;

    status_info.db = db;

    /*
     * benchmark
     */

    if (benchmark == 1)
    {
      if (hash_mode_chgd == 0)
      {
        hash_mode = algorithms[algorithm_pos];

        engine_parameter->hash_mode = hash_mode;
      }

      if (db->salts_cnt == 0)
      {
        // salt

        incr_salt_ptrs (db);

        salt_t *salt_search = init_new_salt ();

        salt_search->salt_plain_buf     = mymalloc (BLOCK_SIZE);
        salt_search->salt_prehashed_buf = mymalloc (BLOCK_SIZE);

        memset (salt_search->salt_plain_buf,     0, BLOCK_SIZE);
        memset (salt_search->salt_prehashed_buf, 0, BLOCK_SIZE);

        salt_search->salt_plain_len = 10;

        salt_search->indexes_buf = mymalloc (sizeof (index_t *));

        salt_search->indexes_buf[0] = init_new_index ();

        salt_search->indexes_cnt++;

        db->salts_buf[db->salts_cnt] = salt_search;

        db->salts_cnt++;

        // hash

        digest_t *digest = init_new_digest ();

        // problem with -m 7100 = OS X v10.8: if I use '\0' to memset I get some founds, why?

        memset (digest->buf.sha512, 1, sizeof (digest->buf.sha512));

        index_t *index = salt_search->indexes_buf[0];

        incr_digest_ptrs (index);

        index->digests_buf[index->digests_cnt] = digest;

        index->digests_cnt++;

        status_info.proc_hashes++;
      }
    }

    /*
     * hash_type
     */

    switch (hash_mode)
    {
      case     0: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    10: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    11: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    12: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    20: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    21: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    23: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    30: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    40: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    50: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case    60: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case   100: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   101: engine_parameter->hash_type      = HASH_TYPE_SHA1B64;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1B64;
                  break;
      case   110: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   111: engine_parameter->hash_type      = HASH_TYPE_SHA1B64S;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1B64S;
                  break;
      case   112: engine_parameter->hash_type      = HASH_TYPE_SHA1ORACLE;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1ORACLE;
                  break;
      case   120: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   121: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   122: engine_parameter->hash_type      = HASH_TYPE_OSX1;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_OSX1;
                  break;
      case   123: engine_parameter->hash_type      = HASH_TYPE_EPIV4;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_EPIV4;
                  break;
      case   124: engine_parameter->hash_type      = HASH_TYPE_DJANGOSHA1;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_EPIV4;
                  break;
      case   130: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   131: engine_parameter->hash_type      = HASH_TYPE_MSSQL2000;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MSSQL2000;
                  break;
      case   132: engine_parameter->hash_type      = HASH_TYPE_MSSQL2005;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MSSQL2005;
                  break;
      case   133: engine_parameter->hash_type      = HASH_TYPE_PEOPLESOFT;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   140: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   141: engine_parameter->hash_type      = HASH_TYPE_EPIV6;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_EPIV6;
                  break;
      case   150: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   160: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   200: engine_parameter->hash_type      = HASH_TYPE_MYSQL;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MYSQL;
                  break;
      case   300: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case   400: engine_parameter->hash_type      = HASH_TYPE_PHPASS;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_PHPASS;
                  break;
      case   500: engine_parameter->hash_type      = HASH_TYPE_MD5UNIX;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5UNIX;
                  break;
      case   666: engine_parameter->hash_type      = HASH_TYPE_PLAIN;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_PLAIN;
                  break;
      case   900: engine_parameter->hash_type      = HASH_TYPE_MD4;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD4;
                  break;
      case  1000: engine_parameter->hash_type      = HASH_TYPE_MD4;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_NTLM;
                  break;
      case  1100: engine_parameter->hash_type      = HASH_TYPE_DCC;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_DCC;
                  break;
      case  1400: engine_parameter->hash_type      = HASH_TYPE_SHA256;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1410: engine_parameter->hash_type      = HASH_TYPE_SHA256;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1420: engine_parameter->hash_type      = HASH_TYPE_SHA256;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1421: engine_parameter->hash_type      = HASH_TYPE_HMAIL;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1430: engine_parameter->hash_type      = HASH_TYPE_SHA256;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1431: engine_parameter->hash_type      = HASH_TYPE_SHA256B64;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1440: engine_parameter->hash_type      = HASH_TYPE_SHA256;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1441: engine_parameter->hash_type      = HASH_TYPE_EPIV6_4;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_EPIV6_4;
                  break;
      case  1450: engine_parameter->hash_type      = HASH_TYPE_SHA256;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1460: engine_parameter->hash_type      = HASH_TYPE_SHA256;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  1500: engine_parameter->hash_type      = HASH_TYPE_DESCRYPT;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_DESCRYPT;
                  break;
      case  1600: engine_parameter->hash_type      = HASH_TYPE_MD5APR;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5APR;
                  break;
      case  1700: engine_parameter->hash_type      = HASH_TYPE_SHA512;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512;
                  break;
      case  1710: engine_parameter->hash_type      = HASH_TYPE_SHA512;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512;
                  break;
      case  1711: engine_parameter->hash_type      = HASH_TYPE_SHA512B64S;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512B64S;
                  break;
      case  1720: engine_parameter->hash_type      = HASH_TYPE_SHA512;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512;
                  break;
      case  1722: engine_parameter->hash_type      = HASH_TYPE_OSX512;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_OSX512;
                  break;
      case  1730: engine_parameter->hash_type      = HASH_TYPE_SHA512;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512;
                  break;
      case  1731: engine_parameter->hash_type      = HASH_TYPE_MSSQL2012;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MSSQL2012;
                  break;
      case  1740: engine_parameter->hash_type      = HASH_TYPE_SHA512;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512;
                  break;
      case  1750: engine_parameter->hash_type      = HASH_TYPE_SHA512;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512;
                  break;
      case  1760: engine_parameter->hash_type      = HASH_TYPE_SHA512;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512;
                  break;
      case  1800: engine_parameter->hash_type      = HASH_TYPE_SHA512UNIX;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512UNIX;
                  break;
      case  2400: engine_parameter->hash_type      = HASH_TYPE_MD5CISCO_PIX;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5CISCO;
                  break;
      case  2410: engine_parameter->hash_type      = HASH_TYPE_MD5CISCO_ASA;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5CISCO;
                  break;
      case  2500: engine_parameter->hash_type      = HASH_TYPE_WPA;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_WPA;
                  break;
      case  2600: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  2611: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  2612: engine_parameter->hash_type      = HASH_TYPE_PHPS;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  2711: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  2811: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  3200: engine_parameter->hash_type      = HASH_TYPE_BCRYPT;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_BCRYPT;
                  break;
      case  3300: engine_parameter->hash_type      = HASH_TYPE_MD5SUN;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5SUN;
                  break;
      case  3500: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  3610: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  3710: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  3711: engine_parameter->hash_type      = HASH_TYPE_MEDIAWIKI_B;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  3720: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  3721: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  3800: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  3910: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  4010: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  4110: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  4210: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  4300: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  4400: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  4500: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case  4600: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case  4700: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case  4800: engine_parameter->hash_type      = HASH_TYPE_MD5CHAP;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5CHAP;
                  break;
      case  4900: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case  5000: engine_parameter->hash_type      = HASH_TYPE_KECCAK;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_KECCAK;
                  break;
      case  5100: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  5200: engine_parameter->hash_type      = HASH_TYPE_PSAFE3;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  5300: engine_parameter->hash_type      = HASH_TYPE_IKEPSK_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case  5400: engine_parameter->hash_type      = HASH_TYPE_IKEPSK_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case  5500: engine_parameter->hash_type      = HASH_TYPE_NETNTLMv1;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_NETNTLMv1;
                  break;
      case  5600: engine_parameter->hash_type      = HASH_TYPE_NETNTLMv2;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_NETNTLMv2;
                  break;
      case  5700: engine_parameter->hash_type      = HASH_TYPE_CISCO_SECRET4;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256;
                  break;
      case  5800: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case  6300: engine_parameter->hash_type      = HASH_TYPE_MD5AIX;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5AIX;
                  break;
      case  6400: engine_parameter->hash_type      = HASH_TYPE_SHA256AIX;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256AIX;
                  break;
      case  6500: engine_parameter->hash_type      = HASH_TYPE_SHA512AIX;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512AIX;
                  break;
      case  6700: engine_parameter->hash_type      = HASH_TYPE_SHA1AIX;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1AIX;
                  break;
      case  6900: engine_parameter->hash_type      = HASH_TYPE_GOST;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_GOST;
                  break;
      case  7000: engine_parameter->hash_type      = HASH_TYPE_SHA1FORTIGATE;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_FORTIGATE;
                  break;
      case  7100: engine_parameter->hash_type      = HASH_TYPE_PBKDF2OSX;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_PBKDF2OSX;
                  break;
      case  7200: engine_parameter->hash_type      = HASH_TYPE_PBKDF2GRUB;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_PBKDF2GRUB;
                  break;
      case  7300: engine_parameter->hash_type      = HASH_TYPE_HMACRAKP;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_HMACRAKP;
                  break;
      case  7400: engine_parameter->hash_type      = HASH_TYPE_SHA256UNIX;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA256UNIX;
                  break;
      case  7600: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case  7900: engine_parameter->hash_type      = HASH_TYPE_DRUPAL7;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA512;
                  break;
      case  8400: engine_parameter->hash_type      = HASH_TYPE_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case  8900: engine_parameter->hash_type      = HASH_TYPE_SCRYPT;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SCRYPT;
                  break;
      case  9200: engine_parameter->hash_type      = HASH_TYPE_CISCO_SECRET8;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_CISCO_SECRET8;
                  break;
      case  9300: engine_parameter->hash_type      = HASH_TYPE_CISCO_SECRET9;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SCRYPT;
                  break;
      case  9900: engine_parameter->hash_type      = HASH_TYPE_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case 10000: engine_parameter->hash_type      = HASH_TYPE_DJANGO_SHA256;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_DJANGO_SHA256;
                  break;
      case 10200: engine_parameter->hash_type      = HASH_TYPE_CRAM_MD5;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case 10300: engine_parameter->hash_type      = HASH_TYPE_SAP_H_SHA1;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case 11000: engine_parameter->hash_type      = HASH_TYPE_PRESTASHOP;
                  engine_parameter->salt_type      = SALT_TYPE_INCLUDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case 11100: engine_parameter->hash_type      = HASH_TYPE_POSTGRESQL_AUTH;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case 11200: engine_parameter->hash_type      = HASH_TYPE_MYSQL_AUTH;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_SHA1;
                  break;
      case 11400: engine_parameter->hash_type      = HASH_TYPE_SIP_AUTH;
                  engine_parameter->salt_type      = SALT_TYPE_EMBEDDED;
                  engine_parameter->plain_size_max = PLAIN_SIZE_MD5;
                  break;
      case 99999: engine_parameter->hash_type      = HASH_TYPE_PLAIN;
                  engine_parameter->salt_type      = SALT_TYPE_NONE;
                  engine_parameter->plain_size_max = PLAIN_SIZE_PLAIN;
                  break;

      default:    log_error ("unknown hash_mode: %u", hash_mode); exit (-1);
                  break;
    }

    /*
     * misc stuff
     */

    uint isSalted = ((engine_parameter->salt_type == SALT_TYPE_INCLUDED)
                  |  (engine_parameter->salt_type == SALT_TYPE_EXTERNAL)
                  |  (engine_parameter->salt_type == SALT_TYPE_EMBEDDED));

    if (benchmark == 1)
    {
      // salt length

      if (isSalted)
      {
        db->salts_buf[0]->salt_plain_len = 8;
      }

      switch (hash_mode)
      {
        case    60: db->salts_buf[0]->ipad_prehashed_buf = mycalloc (16, 1);
                    db->salts_buf[0]->opad_prehashed_buf = mycalloc (16, 1);
                    break;
        case   160: db->salts_buf[0]->ipad_prehashed_buf = mycalloc (20, 1);
                    db->salts_buf[0]->opad_prehashed_buf = mycalloc (20, 1);
                    break;
        case  1460: db->salts_buf[0]->ipad_prehashed_buf = mycalloc (32, 1);
                    db->salts_buf[0]->opad_prehashed_buf = mycalloc (32, 1);
                    break;
        case  1760: db->salts_buf[0]->ipad_prehashed_buf64 = mycalloc (64, 1);
                    db->salts_buf[0]->opad_prehashed_buf64 = mycalloc (64, 1);
                    break;
        case  1500: db->salts_buf[0]->salt_plain_len = 2;
                    break;
        case  2410: db->salts_buf[0]->salt_plain_len = 4;
                    break;
        case  2500: memcpy (db->salts_buf[0]->salt_plain_buf, "hashcat.net", 11);
                    db->salts_buf[0]->wpa = (wpa_t *) mycalloc (1, sizeof (wpa_t));
                    db->salts_buf[0]->wpa->keyver = 1;
                    break;
        case  5000: db->salts_buf[0]->keccak_mdlen = 32;
                    db->salts_buf[0]->keccak_rsiz  = 136; // 200 - (2 * 32)
                    break;
        case  5300: {
                      ikepsk_t *ikepsk = mymalloc (sizeof (ikepsk_t));
                      ikepsk->nr_len  = 1;
                      ikepsk->msg_len = 1;

                      db->salts_buf[0]->ikepsk = ikepsk;
                    }
                    break;
        case  5400: {
                      ikepsk_t *ikepsk = mymalloc (sizeof (ikepsk_t));
                      ikepsk->nr_len  = 1;
                      ikepsk->msg_len = 1;

                      db->salts_buf[0]->ikepsk = ikepsk;
                    }
                    break;
        case  5500: {
                      netntlm_t *netntlm = mymalloc (sizeof (netntlm_t));
                      netntlm->user_len = 1;
                      netntlm->domain_len = 1;
                      netntlm->srvchall_len = 1;
                      netntlm->clichall_len = 1;

                      db->salts_buf[0]->netntlm = netntlm;
                    }
                    break;
        case  5600: {
                      netntlm_t *netntlm = mymalloc (sizeof (netntlm_t));
                      netntlm->user_len = 1;
                      netntlm->domain_len = 1;
                      netntlm->srvchall_len = 1;
                      netntlm->clichall_len = 1;

                      db->salts_buf[0]->netntlm = netntlm;
                    }
                    break;
        case  5800: {
                      db->salts_buf[0]->salt_plain_len = 16;
                      plains_iteration = mycalloc (1024, sizeof (plain_t*));

                      uint32_t i;

                      for (i = 0; i < 1024; i++)
                      {
                        plains_iteration[i] = mycalloc (4, sizeof (plain_t));
                      }
                    }
                    break;
        case  8400: db->salts_buf[0]->salt_plain_len = 40;
                    break;
        case  8900: db->salts_buf[0]->salt_plain_len = 16;
                    db->salts_buf[0]->scrypt_N = 16384;
                    db->salts_buf[0]->scrypt_r = 8;
                    db->salts_buf[0]->scrypt_p = 1;
                    break;
        case  9300: db->salts_buf[0]->salt_plain_len = 14;
                    db->salts_buf[0]->scrypt_N = 16384;
                    db->salts_buf[0]->scrypt_r = 1;
                    db->salts_buf[0]->scrypt_p = 1;
                    break;
        case 10300: db->salts_buf[0]->salt_plain_len = 24;
                    break;
      }

      // rounds

      switch (hash_mode)
      {
        case   400: db->salts_buf[0]->iterations = PHPASS_ROUNDS;
                    break;
        case   500: db->salts_buf[0]->iterations = MD5UNIX_ROUNDS;
                    break;
        case  1600: db->salts_buf[0]->iterations = MD5APR_ROUNDS;
                    break;
        case  1800: db->salts_buf[0]->iterations = SHA512UNIX_ROUNDS;
                    break;
        case  2500: db->salts_buf[0]->iterations = WPA2_ROUNDS;
                    break;
        case  3200: db->salts_buf[0]->iterations = BCRYPT_ROUNDS;
                    break;
        case  5200: db->salts_buf[0]->iterations = PSAFE3_ROUNDS;
                    break;
        case  5800: db->salts_buf[0]->iterations = ANDROID_PIN_ROUNDS - 1;
                    break;
        case  6300: db->salts_buf[0]->iterations = MD5UNIX_ROUNDS;
                    break;
        case  6400: db->salts_buf[0]->iterations = SHA256AIX_ROUNDS;
                    break;
        case  6500: db->salts_buf[0]->iterations = SHA512AIX_ROUNDS;
                    break;
        case  6700: db->salts_buf[0]->iterations = SHA1AIX_ROUNDS;
                    break;
        case  7100: db->salts_buf[0]->iterations = PBKDF2OSX_ROUNDS;
                    break;
        case  7200: db->salts_buf[0]->iterations = PBKDF2GRUB_ROUNDS;
                    break;
        case  7400: db->salts_buf[0]->iterations = SHA256UNIX_ROUNDS;
                    break;
        case  7900: db->salts_buf[0]->iterations = DRUPAL7_ROUNDS;
                    break;
        case  8900: db->salts_buf[0]->iterations = 1;
                    break;
        case  9200: db->salts_buf[0]->iterations = CISCO_SECRET8_ROUNDS;
                    break;
        case  9300: db->salts_buf[0]->iterations = 1;
                    break;
        case 10000: db->salts_buf[0]->iterations = DJANGO_SHA256_ROUNDS;
                    break;
        case 10300: db->salts_buf[0]->iterations = SAP_H_SHA1_ROUNDS;
                    break;
      }
    }

    /*
     * external salts
     */

    if (engine_parameter->salt_type == SALT_TYPE_INCLUDED && file_salts != NULL)
    {
      engine_parameter->salt_type = SALT_TYPE_EXTERNAL;

      FILE *fp;

      if ((fp = fopen (file_salts, "rb")) != NULL)
      {
        load_salts (fp, db, engine_parameter);

        fclose (fp);
      }
      else
      {
        log_error ("%s: %s", file_salts, strerror (errno));

        exit (-1);
      }

      if (quiet == 0) log_info ("Added external salts from file %s: %llu salts", file_salts, db->salts_cnt);
    }

    /*
     * potfile 2
     */

    if (show == 1 || left == 1)
    {
      FILE *pot_fp = NULL;

      pot_t *pot = NULL;

      uint pot_cnt   = 0;
      uint pot_avail = 0;

      if ((pot_fp = fopen (file_pot, "rb")) == NULL)
      {
        log_error ("ERROR: cannot open pot file '%s' (%d) : %s", file_pot, errno, strerror (errno));

        exit (-1);
      }

      uint line_num = 0;

      while (!feof (pot_fp))
      {
        line_num++;

        char line_buf[BUFSIZ];

        memset (line_buf, 0, BUFSIZ);

        int line_len = fgetl (pot_fp, line_buf);

        if (line_len < 1) continue;

        char *plain_buf = line_buf + line_len;

        int plain_len = 0;

        int i;

        int hash_len = 0;

        int salt_len = 0;

        char *ptr_salt;

        char *ptr_hash;

        int parser_status;

        int cut_iteration = MAX_CUT_ITER;

        do
        {
          for (i = line_len - 1; i; i--, plain_len++, plain_buf--, line_len--)
          {
            if (line_buf[i] == ':')
            {
              line_len--;

              break;
            }
          }

          parser_status = parse_hash_line (line_buf, line_len, engine_parameter->hash_type, hash_mode, &ptr_hash, &hash_len, engine_parameter->salt_type, &ptr_salt, &salt_len, separator, hex_salt);

        } while (parser_status == LINE_GLOBAL_LENGTH && --cut_iteration);

        if (parser_status != LINE_OK) continue;

        if (pot_avail == pot_cnt)
        {
          pot_avail += INCR_POT;

          pot = (pot_t *) myrealloc (pot, pot_avail * sizeof (pot_t));
        }

        pot_t *pot_ptr = &pot[pot_cnt];

        hash_t *hashes_buf = &pot_ptr->hash;

        // plain

        memcpy (pot_ptr->plain_buf, plain_buf, plain_len);

        pot_ptr->plain_len = plain_len;

        // salt

        if (isSalted)
        {
          hashes_buf->salt = (salt_t *) mymalloc (sizeof (salt_t));

          hashes_buf->salt->salt_plain_buf = mymalloc ((salt_len + 1) * sizeof (char *));

          memcpy (hashes_buf->salt->salt_plain_buf, ptr_salt, salt_len);

          hashes_buf->salt->salt_plain_len = salt_len;

          hashes_buf->salt->salt_plain_buf[salt_len] = 0;
        }
        else
        {
          hashes_buf->salt = NULL;
        }

        // digest

        hashes_buf->digest.plain = mymalloc ((hash_len + 1) * sizeof (char *));

        memcpy (hashes_buf->digest.plain, ptr_hash, hash_len);

        hashes_buf->digest.plain[hash_len] = 0;

        pot_cnt++;
      }

      fclose (pot_fp);

      if (pot_cnt > 0)
      {
        qsort (pot, pot_cnt, sizeof (pot_t), sort_by_pot);

        pot->pot_cnt = pot_cnt;

        engine_parameter->pot = pot;
      }
    }

    /*
     * hashes
     */

    digest_t *quick_digest = NULL;

    char *file_hashes = argv[optind + 0];

    if (stdout_mode == 0)
    {
      if (file_hashes)
      {
        if (benchmark == 1)
        {
          log_error ("Can not run benchmark against a hash file");

          exit (-1);
        }

        FILE *fp;

        if ((fp = fopen (file_hashes, "rb")) != NULL)
        {
          load_hashes (fp, db, engine_parameter);

          fclose (fp);
        }
        else
        {
          log_error ("%s: %s", file_hashes, strerror (errno));

          exit (-1);
        }

        if (quiet == 0) log_info ("Added hashes from file %s: %llu (%llu salts)", file_hashes, status_info.proc_hashes, db->salts_cnt);

        if (status_info.proc_hashes == 1)
        {
          if ((engine_parameter->salt_type == SALT_TYPE_NONE) || (engine_parameter->salt_type == SALT_TYPE_EXTERNAL))
          {
            salt_t *quick_salt = db->salts_buf[0];

            uint32_t indexes_idx;

            for (indexes_idx = 0; indexes_idx < INDEX_SIZE[INDEX_BITS]; indexes_idx++)
            {
              index_t *quick_index = quick_salt->indexes_buf[indexes_idx];

              if (quick_index != NULL)
              {
                quick_digest = quick_index->digests_buf[0];

                if (quiet == 0) log_info ("Activating quick-digest mode for single-hash");
              }
            }
          }
          else if ((engine_parameter->salt_type == SALT_TYPE_INCLUDED) || (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
          {
            salt_t *quick_salt = db->salts_buf[0];

            index_t *quick_index = quick_salt->indexes_buf[0];

            if (quick_index != NULL)
            {
              quick_digest = quick_index->digests_buf[0];

              if (quiet == 0) log_info ("Activating quick-digest mode for single-hash with salt");
            }
          }
        }
      }
      else if (benchmark == 1)
      {
        salt_t *quick_salt = db->salts_buf[0];

        index_t *quick_index = quick_salt->indexes_buf[0];

        quick_digest = quick_index->digests_buf[0];
      }

      engine_parameter->file_hashes = file_hashes;
    }

    /*
     * rules
     */

    if (file_rules != NULL)
    {
      FILE *fp;

      if ((fp = fopen (file_rules, "rb")) != NULL)
      {
        /*    char rule_buf[RP_RULE_BUFSIZ]; */
        char rule_buf[BUFSIZ];

        int rule_len;

        while ((rule_len = fgetl (fp, rule_buf)) != -1)
        {
          if (rule_len == 0) continue;

          if (rule_buf[0] == '#') continue;

          int rc = add_rule (rule_buf, rule_len, rules);

          if (rc == 0)
          {
            /* all ok */
          }
          else if (rc == -1)
          {
            log_warning ("Skipping rule: %s (syntax error)", rule_buf);
          }
          else if (rc == -3)
          {
            log_warning ("Skipping rule: %s (duplicate rule)", rule_buf);
          }
          else if (rc == -4)
          {
            log_warning ("Skipping rule: %s (duplicate result)", rule_buf);
          }
        }

        fclose (fp);
      }
      else
      {
        log_error ("%s: %s", file_rules, strerror (errno));

        exit (-1);
      }
    }
    else if (debug_mode != DEBUG_MODE)
    {
      if (rp_gen == 0) engine_parameter->debug_mode = DEBUG_MODE;
    }

    if (file_rules) if (quiet == 0) log_info ("Added rules from file %s: %llu", file_rules, rules->rules_cnt);

    if (rp_gen)
    {
      uint32_t rules_generated = 0;

      while (rules_generated < rp_gen)
      {
        char rule_buf[RP_RULE_BUFSIZ];

        memset (rule_buf, 0, BLOCK_SIZE);

        uint32_t rule_len = generate_random_rule (rule_buf, rp_gen_func_min, rp_gen_func_max);

        if (add_rule (rule_buf, rule_len, rules) == 0) rules_generated++;
      }

      if (quiet == 0) log_info ("Added rules from rule-generator: %u", rp_gen);
      if (rp_gen_seed_chgd == 0)
      {
        if (quiet == 0) log_info ("Generating rules from seed: %u", proc_start);
      }
      else
      {
        if (quiet == 0) log_info ("Generating rules from seed: %u", rp_gen_seed);
      }

    }

    /*
     * table
     */

    if (file_table != NULL)
    {
      memset (engine_parameter->table_buf, 0, sizeof (engine_parameter->table_buf));

      FILE *fp;

      if ((fp = fopen (file_table, "rb")) != NULL)
      {
        char table_buf[BUFSIZ];

        int table_len;

        while ((table_len = fgetl (fp, table_buf)) != -1)
        {
          char *ptr_buf = table_buf + 1 + 1;
          int   ptr_len = table_len - 1 - 1;

          if (ptr_len <  1) continue;
          if (ptr_len > 16) continue;

          if (table_buf[0] == '#') continue;
          if (table_buf[1] != '=') continue;

          uint8_t c = table_buf[0];

          tbl_t *tbl_ptr = (tbl_t *) &engine_parameter->table_buf[c];

          hc_wchar_t *hc_wchar_ptr = (hc_wchar_t *) &tbl_ptr->tbl_buf[tbl_ptr->tbl_cnt];

          memcpy (hc_wchar_ptr->w_buf, ptr_buf, ptr_len);

          hc_wchar_ptr->w_len = ptr_len;

          tbl_ptr->tbl_cnt++;

          if (tbl_ptr->tbl_cnt > 4096)
          {
            log_error ("Table is too large for single character '%c'\n", c);

            exit (1);
          }
        }

        fclose (fp);
      }
      else
      {
        log_error ("%s: %s", file_table, strerror (errno));

        exit (-1);
      }

      int i;

      for (i = 0; i < 256; i++)
      {
        if (engine_parameter->table_buf[i].tbl_cnt) continue;

        engine_parameter->table_buf[i].tbl_buf[0].w_buf[0] = i;
        engine_parameter->table_buf[i].tbl_buf[0].w_len    = 1;

        engine_parameter->table_buf[i].tbl_cnt = 1;
      }
    }

    /*
     * status view
     */

    if (quiet == 0) show_prompt ();

    ACCreateThreadEx (thr_keypress, keypress, NULL, NULL);

    /*
     * remove thread
     */

    if (remove)
    {
      ACCreateThreadEx (thr_removehash, removehash, NULL, NULL);
    }

    /*
     * runtime thread
     */

    if (runtime)
    {
      ACCreateThreadEx (thr_runtime, check_runtime, NULL, NULL);
    }

    /*
     * status thread
     */

    if (status)
    {
      if (status_timer != 0) ACCreateThreadEx (thr_status, periodic_status_display, NULL, NULL);
    }

    /*
     * catch signal user interrupt
     */

    signal (SIGINT, catch_int);

    /*
     * init end
     */

    engine_parameter->hashcat_status = STATUS_RUNNING;

    SetPriorityLow ();

    /*
     * scan wordlists
     */

    if (attack_mode == 0 || attack_mode == 1 || attack_mode == 2 || attack_mode == 4 || attack_mode == 5)
    {
      int i;

      for (i = optind + 1 - stdout_mode; i < argc; i++)
      {
        char **files = scan_directory (argv[i]);

        if ((words_limit != 0) && (engine_parameter->words_limit == 0)) break;

        int j;

        for (j = 0; files[j] != NULL; j++)
        {
          engine_parameter->file_words = files[j];

          if ((words_limit != 0) && (engine_parameter->words_limit == 0)) break;

          /*
           * words
           */

          FILE *fp;

          if ((fp = fopen (engine_parameter->file_words, "rb")) != NULL)
          {
            #if defined LINUX || defined OSX || defined FREEBSD
            struct stat file;

            stat (engine_parameter->file_words, &file);
            #endif

            #ifdef WINDOWS
            struct __stat64 file;

            _stat64 (engine_parameter->file_words, &file);
            #endif

            /* das ist mies. load_words laed nicht nicht genau cache_avail
               sondern etwas unbekanntes zwischen (cache_avail - 0x1000) und cache_avail. */

            status_info.segment_cnt = ceil (file.st_size / (words->cache_avail - 0x1000)) + 1;

            for (status_info.segment_pos = 1; !feof (fp); status_info.segment_pos++)
            {
              status_info.cache_start.tv_sec  = 0;
              status_info.cache_start.tv_usec = 0;

              words->cache_cnt = 0;
              words->words_cnt = 0;

              load_words (fp, words, engine_parameter);

              if ((words_skip != 0) && (engine_parameter->words_skip >= words->words_cnt))
              {
                engine_parameter->words_skip -= words->words_cnt;

                status_info.proc_words += words->words_cnt;

                __hc_tdestroy (root_cs, free);

                root_cs = NULL;

                continue;
              }

              gettimeofday (&status_info.cache_start, NULL);

              run_threads (engine_parameter, db, store_out, store_debug, myabort, quick_digest);

              if (quiet == 0)
              {
                if (engine_parameter->hashcat_status != STATUS_QUIT)
                {
                  log_info ("");

                  status_display ();

                  show_prompt ();
                }
              }

              if (engine_parameter->hashcat_status == STATUS_QUIT) break;
              if (engine_parameter->hashcat_status == STATUS_BYPASS) break;

              if (engine_parameter->words_skip < db->words->words_cnt)
              {
                if (engine_parameter->words_limit)
                {
                  engine_parameter->words_limit -= MIN (engine_parameter->words_limit, (db->words->words_cnt - engine_parameter->words_skip));
                }
              }

              if (engine_parameter->words_skip)
              {
                engine_parameter->words_skip -= MIN (engine_parameter->words_skip, db->words->words_cnt);
              }

              __hc_tdestroy (root_cs, free);

              root_cs = NULL;

              status_info.proc_words += words->words_cnt;

              if ((words_limit != 0) && (engine_parameter->words_limit == 0)) break;
            }

            fclose (fp);
          }
          else
          {
            log_error ("%s: %s", engine_parameter->file_words, strerror (errno));

            exit (-1);
          }

          if (engine_parameter->hashcat_status == STATUS_QUIT) break;

          // reset hashcat_status if dict was bypassed

          if (engine_parameter->hashcat_status == STATUS_BYPASS) engine_parameter->hashcat_status = STATUS_RUNNING;
        }

        if (engine_parameter->hashcat_status == STATUS_QUIT) break;
      }
    }
    else if (attack_mode == 3)
    {
      char *mask;

      char **masks = NULL;  // array of masks (used for .hcmask files)

      uint is_hcmask_file = 0;
      uint maskcnt = 0;

      FILE *hcmask_fp = NULL;

      if (benchmark == 0)
      {
        mask = argv[optind + 1 - stdout_mode];

        // check if the "mask" parameter was actually a regular .hcmask file

        struct stat file_stat;

        if (stat (mask, &file_stat) != -1)
        {
          is_hcmask_file = S_ISREG (file_stat.st_mode);

          if (is_hcmask_file == 1)
          {
            if ((hcmask_fp = fopen (mask, "r")) == NULL)
            {
              // whoops: failed to open file, try to handle it as mask provided directly in command line
              // fallback:

              is_hcmask_file = 0;
            }
            else
            {
              // read all masks into 'masks' array

              char line_buf[BUFSIZ];

              uint masks_avail = 0;

              while (!feof (hcmask_fp))
              {
                memset (line_buf, 0, BUFSIZ);

                int line_len = fgetl (hcmask_fp, line_buf);

                if (line_len < 1) continue;

                if (line_buf[0] == '#') continue;

                if (masks_avail == maskcnt)
                {
                  masks = (char **) myrealloc (masks, (masks_avail + INCR_MASK_PTR) * sizeof (char *));

                  masks_avail += INCR_MASK_PTR;
                }

                masks[maskcnt] = mystrdup (line_buf);

                maskcnt++;
              }
            }
          }
        }
      }
      else
      {
        mask = mystrdup ("?b?b?b?b?b?b?b");
      }

      if (hcmask_fp != NULL) fclose (hcmask_fp);

      if (is_hcmask_file == 0) // "normal" (non-hcmask) case, we only have 1 single mask
      {
        maskcnt++;

        masks = (char **) mymalloc (1 * sizeof (char *));

        masks[0] = mask;
      }
      else if (maskcnt == 0)
      {
        if (mask != NULL) log_error ("the .hcmask file '%s' does not contain valid mask(s)", mask);
        else              log_error ("the .hcmask file does not contain valid mask(s)");  // could this really happen?

        return (-1);
      }

      engine_parameter->maskcnt = maskcnt; // should never ever be 0, otherwise we could end up in a division by 0 (percentage calc)

      /**
       * built-in charset
       */

      cs_t mp_sys[6];

      memset (mp_sys, 0, sizeof (mp_sys));

      uint32_t donec[CHARSIZ];

      memset (donec, 0, sizeof (donec));

      uint32_t pos;
      uint32_t chr;

      for (pos = 0, chr =  'a'; chr <=  'z'; chr++) { donec[chr] = 1;
                                                      mp_sys[0].cs_buf[pos++] = chr;
                                                      mp_sys[0].cs_len = pos; }

      for (pos = 0, chr =  'A'; chr <=  'Z'; chr++) { donec[chr] = 1;
                                                      mp_sys[1].cs_buf[pos++] = chr;
                                                      mp_sys[1].cs_len = pos; }

      for (pos = 0, chr =  '0'; chr <=  '9'; chr++) { donec[chr] = 1;
                                                      mp_sys[2].cs_buf[pos++] = chr;
                                                      mp_sys[2].cs_len = pos; }

      for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) { if (donec[chr]) continue;
                                                      mp_sys[3].cs_buf[pos++] = chr;
                                                      mp_sys[3].cs_len = pos; }

      for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) { donec[chr] = 1;
                                                      mp_sys[4].cs_buf[pos++] = chr;
                                                      mp_sys[4].cs_len = pos; }

      for (pos = 0, chr = 0x00; chr <= 0xff; chr++) { donec[chr] = 1;
                                                      mp_sys[5].cs_buf[pos++] = chr;
                                                      mp_sys[5].cs_len = pos; }

      /**
       * expand custom masks
       */

      char mp_file[CHARSIZ + 1];

      cs_t mp_usr[4];

      memset (mp_usr, 0, sizeof (mp_usr));

      if (custom_charset_1)
      {
        FILE *fp = fopen (custom_charset_1, "rb");

        if (fp != NULL)
        {
          size_t len = fread (mp_file, 1, CHARSIZ, fp);

          fclose (fp);

          mp_expand (mp_file, len, mp_sys, mp_usr, 0, 0);
        }
        else
        {
          mp_expand (custom_charset_1, strlen (custom_charset_1), mp_sys, mp_usr, 0, 1);
        }
      }

      if (custom_charset_2)
      {
        FILE *fp = fopen (custom_charset_2, "rb");

        if (fp != NULL)
        {
          size_t len = fread (mp_file, 1, CHARSIZ, fp);

          fclose (fp);

          mp_expand (mp_file, len, mp_sys, mp_usr, 1, 0);
        }
        else
        {
          mp_expand (custom_charset_2, strlen (custom_charset_2), mp_sys, mp_usr, 1, 1);
        }
      }

      if (custom_charset_3)
      {
        FILE *fp = fopen (custom_charset_3, "rb");

        if (fp != NULL)
        {
          size_t len = fread (mp_file, 1, CHARSIZ, fp);

          fclose (fp);

          mp_expand (mp_file, len, mp_sys, mp_usr, 2, 0);
        }
        else
        {
          mp_expand (custom_charset_3, strlen (custom_charset_3), mp_sys, mp_usr, 2, 1);
        }
      }

      if (custom_charset_4)
      {
        FILE *fp = fopen (custom_charset_4, "rb");

        if (fp != NULL)
        {
          size_t len = fread (mp_file, 1, CHARSIZ, fp);

          fclose (fp);

          mp_expand (mp_file, len, mp_sys, mp_usr, 3, 0);
        }
        else
        {
          mp_expand (custom_charset_4, strlen (custom_charset_4), mp_sys, mp_usr, 3, 1);
        }
      }

      uint maskpos;

      for (maskpos = 0; maskpos < maskcnt; maskpos++)
      {
        mask = masks[maskpos];

        // parse the single hcmask lines into the components (?1,?2,?3,?4,mask)

        if (is_hcmask_file == 1)
        {
          if (mask[0] == '\\' && mask[1] == '#') mask++; // escaped comment sign (sharp) "\#"

          char *str_ptr;
          uint  str_pos;

          uint mask_offset = 0;

          uint separator_cnt;

          for (separator_cnt = 0; separator_cnt < 4; separator_cnt++)
          {
            str_ptr = strstr (mask + mask_offset, ",");

            if (str_ptr == NULL) break;

            str_pos = str_ptr - mask;

            // escaped separator, i.e. "\,"
            if (str_pos > 0)
            {
              if (mask[str_pos - 1] == '\\')
              {
                separator_cnt --;

                mask_offset = str_pos + 1;

                continue;
              }
            }

            // reset the offset

            mask_offset = 0;

            mask[str_pos] = '\0';

            switch (separator_cnt)
            {
              case 0:
                custom_charset_1 = mask;
                mp_expand (custom_charset_1, strlen (custom_charset_1), mp_sys, mp_usr, 0, 1);
                break;

              case 1:
                custom_charset_2 = mask;
                mp_expand (custom_charset_2, strlen (custom_charset_2), mp_sys, mp_usr, 1, 1);
                break;

              case 2:
                custom_charset_3 = mask;
                mp_expand (custom_charset_3, strlen (custom_charset_3), mp_sys, mp_usr, 2, 1);
                break;

              case 3:
                custom_charset_4 = mask;
                mp_expand (custom_charset_4, strlen (custom_charset_4), mp_sys, mp_usr, 3, 1);
                break;
            }

            mask = mask + str_pos + 1;
          }

          if (strlen (mask) < 1)
          {
            continue;
          }
        }

        engine_parameter->mask = mask;
        engine_parameter->maskpos = maskpos + 1; // +1 because loop starts at 0, instead of 1

        uint32_t css_cnt;

        cs_t *css_buf = mp_gen_css (mask, strlen (mask), mp_sys, mp_usr, &css_cnt);

        engine_parameter->css_buf = css_buf;
        engine_parameter->css_cnt = css_cnt;

        /**
         * loop through attack
         */

        uint32_t mask_min = css_cnt;
        uint32_t mask_max = css_cnt;

        if (increment)
        {
          mask_min = increment_min;
          mask_max = increment_max;
        }

        uint32_t mask_len;

        for (mask_len = mask_min; mask_len <= mask_max; mask_len++)
        {
          if (mask_len > css_cnt) break;

          status_info.segment_pos = 0;
          status_info.segment_cnt = 1;

          words->cache_cnt = 0;
          words->words_cnt = mp_get_sum (mask_len, css_buf);

          if ((words_skip != 0) && (engine_parameter->words_skip >= words->words_cnt))
          {
            engine_parameter->words_skip -= words->words_cnt;

            status_info.proc_words += words->words_cnt;

            continue;
          }

          engine_parameter->pw_len = mask_len;

          gettimeofday (&status_info.cache_start, NULL);

          run_threads (engine_parameter, db, store_out, store_debug, myabort, quick_digest);

          if (quiet == 0)
          {
            if (engine_parameter->hashcat_status != STATUS_QUIT)
            {
              log_info ("");

              status_display ();

              show_prompt ();
            }
          }

          if (engine_parameter->words_skip < db->words->words_cnt)
          {
            if (engine_parameter->words_limit)
            {
              engine_parameter->words_limit -= MIN (engine_parameter->words_limit, (db->words->words_cnt - engine_parameter->words_skip));
            }
          }

          if (engine_parameter->hashcat_status == STATUS_QUIT) break;
          if (engine_parameter->hashcat_status == STATUS_BYPASS)
          {
            engine_parameter->hashcat_status = STATUS_RUNNING;

            continue;
          }

          if (engine_parameter->words_skip)
          {
            engine_parameter->words_skip -= MIN (engine_parameter->words_skip, db->words->words_cnt);
          }

          status_info.proc_words += words->words_cnt;

          if ((words_limit != 0) && (engine_parameter->words_limit == 0)) break;
        }

        if (engine_parameter->hashcat_status == STATUS_BYPASS) engine_parameter->hashcat_status = STATUS_RUNNING;
      }
    }
    else if (attack_mode == 8)
    {
      /* hack: since run_threads () and hashing_xxxxx () will use these engine_parameter->words_skip and engine_parameter->words_limit
       * values, we need to make sure that we don't skip and limit twice, therefore we set them to 0 here, because the below PRINCE algo
       * already does the skipping/limiting
       */
      engine_parameter->words_skip  = 0;
      engine_parameter->words_limit = 0;

      mpz_t pw_ks_pos[OUT_LEN_MAX + 1];
      mpz_t pw_ks_cnt[OUT_LEN_MAX + 1];

      mpz_t total_ks_cnt;     mpz_init_set_si (total_ks_cnt,    0);
      mpz_t total_ks_pos;     mpz_init_set_si (total_ks_pos,    0);
      mpz_t total_ks_left;    mpz_init_set_si (total_ks_left,   0);
      mpz_t skip;             mpz_init_set_si (skip,            words_skip);
      mpz_t limit;            mpz_init_set_si (limit,           words_limit);
      mpz_t iter_max;         mpz_init_set_si (iter_max,        0);
      mpz_t tmp;              mpz_init_set_si (tmp,             0);

      db_entry_t *db_entries   = (db_entry_t *) calloc (pw_max + 1, sizeof (db_entry_t));
      pw_order_t *pw_orders    = (pw_order_t *) calloc (pw_max + 1, sizeof (pw_order_t));
      u64        *wordlen_dist = (u64 *)        calloc (pw_max + 1, sizeof (u64));

      char *file_words = argv[optind + 1 - stdout_mode];

      engine_parameter->file_words = file_words;

      FILE *read_fp = fopen (file_words, "rb");

      if (read_fp == NULL)
      {
        log_error ("%s: %s", file_words, strerror (errno));

        exit (-1);
      }

      /**
       * load words from wordlist
       */

      if (elem_cnt_max_chgd == 0)
      {
        elem_cnt_max = MIN (pw_max, ELEM_CNT_MAX);
      }

      u32 wl_cnt = 0;

      while (!feof (read_fp))
      {
        char buf[BUFSIZ];

        char *input_buf = fgets (buf, sizeof (buf), read_fp);

        if (input_buf == NULL) continue;

        const int input_len = in_superchop (input_buf);

        if (input_len < IN_LEN_MIN) continue;
        if (input_len > IN_LEN_MAX) continue;

        if (input_len > pw_max) continue;

        db_entry_t *db_entry = &db_entries[input_len];

        add_elem (db_entry, input_buf, input_len);

        if (case_permute)
        {
          const char old_c = input_buf[0];

          const char new_cu = toupper (old_c);
          const char new_cl = tolower (old_c);

          if (old_c != new_cu)
          {
            input_buf[0] = new_cu;

            add_elem (db_entry, input_buf, input_len);
          }

          if (old_c != new_cl)
          {
            input_buf[0] = new_cl;

            add_elem (db_entry, input_buf, input_len);
          }
        }

        wl_cnt++;

        if (wl_max > 0 && wl_cnt == wl_max) break;
      }

      fclose (read_fp);

      /**
       * init chains
       */

      int pw_len;

      for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
      {
        db_entry_t *db_entry = &db_entries[pw_len];

        const int pw_len1 = pw_len - 1;

        const u32 chains_cnt = 1 << pw_len1;

        u8 buf[OUT_LEN_MAX];

        chain_t chain_buf_new;

        chain_buf_new.buf = buf;

        u32 chains_idx;

        for (chains_idx = 0; chains_idx < chains_cnt; chains_idx++)
        {
          chain_gen_with_idx (&chain_buf_new, pw_len1, chains_idx);

          // make sure all the elements really exist

          int valid1 = chain_valid_with_db (&chain_buf_new, db_entries);

          if (valid1 == 0) continue;

          // boost by verify element count to be inside a specific range

          int valid2 = chain_valid_with_cnt_min (&chain_buf_new, elem_cnt_min);

          if (valid2 == 0) continue;

          int valid3 = chain_valid_with_cnt_max (&chain_buf_new, elem_cnt_max);

          if (valid3 == 0) continue;

          // add chain to database

          check_realloc_chains (db_entry);

          chain_t *chain_buf = &db_entry->chains_buf[db_entry->chains_cnt];

          memcpy (chain_buf, &chain_buf_new, sizeof (chain_t));

          chain_buf->buf = malloc_tiny (pw_len);

          memcpy (chain_buf->buf, chain_buf_new.buf, pw_len);

          mpz_init_set_si (chain_buf->ks_cnt, 0);
          mpz_init_set_si (chain_buf->ks_pos, 0);

          db_entry->chains_cnt++;
        }

        memset (db_entry->cur_chain_ks_poses, 0, OUT_LEN_MAX * sizeof (u64));
      }

      /**
       * calculate password candidate output length distribution
       */

      if (wl_dist_len)
      {
        int pw_len;

        for (pw_len = IN_LEN_MIN; pw_len <= pw_max; pw_len++)
        {
          if (pw_len <= IN_LEN_MAX)
          {
            db_entry_t *db_entry = &db_entries[pw_len];

            wordlen_dist[pw_len] = db_entry->elems_cnt;
          }
          else
          {
            wordlen_dist[pw_len] = 1;
          }
        }
      }
      else
      {
        int pw_len;

        for (pw_len = IN_LEN_MIN; pw_len <= pw_max; pw_len++)
        {
          if (pw_len < DEF_WORDLEN_DIST_CNT)
          {
            wordlen_dist[pw_len] = DEF_WORDLEN_DIST[pw_len];
          }
          else
          {
            wordlen_dist[pw_len] = 1;
          }
        }
      }

      /**
       * Calculate keyspace stuff
       */

      for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
      {
        db_entry_t *db_entry = &db_entries[pw_len];

        int      chains_cnt = db_entry->chains_cnt;
        chain_t *chains_buf = db_entry->chains_buf;

        mpz_set_si (tmp, 0);

        int chains_idx;

        for (chains_idx = 0; chains_idx < chains_cnt; chains_idx++)
        {
          chain_t *chain_buf = &chains_buf[chains_idx];

          chain_ks (chain_buf, db_entries, &chain_buf->ks_cnt);

          mpz_add (tmp, tmp, chain_buf->ks_cnt);
        }

        mpz_add (total_ks_cnt, total_ks_cnt, tmp);

        if (mpz_cmp_si (skip, 0))
        {
          mpz_init_set (pw_ks_cnt[pw_len], tmp);
        }
      }

      /**
       * sort chains by ks
       */

      for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
      {
        db_entry_t *db_entry = &db_entries[pw_len];

        chain_t *chains_buf = db_entry->chains_buf;

        const int chains_cnt = db_entry->chains_cnt;

        qsort (chains_buf, chains_cnt, sizeof (chain_t), sort_by_ks);
      }

      /**
       * sort global order by password length counts
       */

      int order_pos;

      for (pw_len = pw_min, order_pos = 0; pw_len <= pw_max; pw_len++, order_pos++)
      {
        db_entry_t *db_entry = &db_entries[pw_len];

        const u64 elems_cnt = db_entry->elems_cnt;

        pw_order_t *pw_order = &pw_orders[order_pos];

        pw_order->len = pw_len;
        pw_order->cnt = elems_cnt;
      }

      const int order_cnt = pw_max + 1 - pw_min;

      qsort (pw_orders, order_cnt, sizeof (pw_order_t), sort_by_cnt);

      /**
       * seek to some starting point
       */

      if (mpz_cmp_si (skip, 0))
      {
        if (mpz_cmp (skip, total_ks_cnt) >= 0)
        {
          fprintf (stderr, "Value of --words-skip must be smaller than total keyspace\n");

          free (wordlen_dist);

          return (-1);
        }
      }

      if (mpz_cmp_si (limit, 0))
      {
        if (mpz_cmp (limit, total_ks_cnt) > 0)
        {
          fprintf (stderr, "Value of --words-limit cannot be larger than total keyspace\n");

          return (-1);
        }

        mpz_add (tmp, skip, limit);

        if (mpz_cmp (tmp, total_ks_cnt) > 0)
        {
          fprintf (stderr, "Value of --words-skip + --words-limit cannot be larger than total keyspace\n");

          return (-1);
        }

        mpz_set (total_ks_cnt, tmp);
      }

      /**
       * skip to the first main loop that will output a password
       */

      if (mpz_cmp_si (skip, 0))
      {
        mpz_t skip_left;  mpz_init_set (skip_left, skip);
        mpz_t main_loops; mpz_init (main_loops);

        u64 outs_per_main_loop = 0;

        int pw_len;

        for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
        {
          mpz_init_set_si (pw_ks_pos[pw_len], 0);

          outs_per_main_loop += wordlen_dist[pw_len];
        }

        // find pw_ks_pos[]

        while (1)
        {
          mpz_fdiv_q_ui (main_loops, skip_left, outs_per_main_loop);

          if (mpz_cmp_si (main_loops, 0) == 0)
          {
            break;
          }

          // increment the main loop "main_loops" times

          int pw_len;

          for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
          {
            if (mpz_cmp (pw_ks_pos[pw_len], pw_ks_cnt[pw_len]) < 0)
            {
              mpz_mul_ui (tmp, main_loops, wordlen_dist[pw_len]);

              mpz_add (pw_ks_pos[pw_len], pw_ks_pos[pw_len], tmp);

              mpz_sub (skip_left, skip_left, tmp);

              if (mpz_cmp (pw_ks_pos[pw_len], pw_ks_cnt[pw_len]) > 0)
              {
                mpz_sub (tmp, pw_ks_pos[pw_len], pw_ks_cnt[pw_len]);

                mpz_add (skip_left, skip_left, tmp);
              }
            }
          }

          outs_per_main_loop = 0;

          for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
          {
            if (mpz_cmp (pw_ks_pos[pw_len], pw_ks_cnt[pw_len]) < 0)
            {
              outs_per_main_loop += wordlen_dist[pw_len];
            }
          }
        }

        mpz_sub (total_ks_pos, skip, skip_left);

        // set db_entries to pw_ks_pos[]

        for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
        {
          db_entry_t *db_entry = &db_entries[pw_len];

          int      chains_cnt = db_entry->chains_cnt;
          chain_t *chains_buf = db_entry->chains_buf;

          mpz_set (tmp, pw_ks_pos[pw_len]);

          int chains_idx;

          for (chains_idx = 0; chains_idx < chains_cnt; chains_idx++)
          {
            chain_t *chain_buf = &chains_buf[chains_idx];

            if (mpz_cmp (tmp, chain_buf->ks_cnt) < 0)
            {
              mpz_set (chain_buf->ks_pos, tmp);

              set_chain_ks_poses (chain_buf, db_entries, &tmp, db_entry->cur_chain_ks_poses);

              break;
            }

            mpz_sub (tmp, tmp, chain_buf->ks_cnt);

            db_entry->chains_pos++;
          }
        }

        // clean up

        for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
        {
          mpz_clear (pw_ks_cnt[pw_len]);
          mpz_clear (pw_ks_pos[pw_len]);
        }

        mpz_clear (skip_left);
        mpz_clear (main_loops);
      }

      /**
       * loop
       */

      status_info.segment_pos = 0;
      status_info.segment_cnt = 1;

      status_info.cache_start.tv_sec  = 0;
      status_info.cache_start.tv_usec = 0;

      words->cache_cnt = 0;
      words->words_cnt = 0;

      while (mpz_cmp (total_ks_pos, total_ks_cnt) < 0)
      {
        int order_pos;

        for (order_pos = 0; order_pos < order_cnt; order_pos++)
        {
          pw_order_t *pw_order = &pw_orders[order_pos];

          const int pw_len = pw_order->len;

          char pw_buf[BUFSIZ];

          db_entry_t *db_entry = &db_entries[pw_len];

          const u64 outs_cnt = wordlen_dist[pw_len];

          u64 outs_pos = 0;

          while (outs_pos < outs_cnt)
          {
            const int chains_cnt = db_entry->chains_cnt;
            const int chains_pos = db_entry->chains_pos;

            if (chains_pos == chains_cnt) break;

            chain_t *chains_buf = db_entry->chains_buf;

            chain_t *chain_buf = &chains_buf[chains_pos];

            mpz_sub (total_ks_left, total_ks_cnt, total_ks_pos);

            mpz_sub (iter_max, chain_buf->ks_cnt, chain_buf->ks_pos);

            if (mpz_cmp (total_ks_left, iter_max) < 0)
            {
              mpz_set (iter_max, total_ks_left);
            }

            const u64 outs_left = outs_cnt - outs_pos;

            mpz_set_ui (tmp, outs_left);

            if (mpz_cmp (tmp, iter_max) < 0)
            {
              mpz_set (iter_max, tmp);
            }

            const u64 iter_max_u64 = mpz_get_ui (iter_max);

            mpz_add (tmp, total_ks_pos, iter_max);

            if (mpz_cmp (tmp, skip) > 0)
            {
              u64 iter_pos_u64 = 0;

              if (mpz_cmp (total_ks_pos, skip) < 0)
              {
                mpz_sub (tmp, skip, total_ks_pos);

                iter_pos_u64 = mpz_get_ui (tmp);

                mpz_add (tmp, chain_buf->ks_pos, tmp);

                set_chain_ks_poses (chain_buf, db_entries, &tmp, db_entry->cur_chain_ks_poses);
              }

              chain_set_pwbuf_init (chain_buf, db_entries, db_entry->cur_chain_ks_poses, pw_buf);

              while (iter_pos_u64 < iter_max_u64)
              {
                const int flush = out_push (words, pw_buf, pw_len);

                if (flush)
                {
                  gettimeofday (&status_info.cache_start, NULL);

                  run_threads (engine_parameter, db, store_out, store_debug, myabort, quick_digest);

                  if (engine_parameter->hashcat_status == STATUS_QUIT) break;

                  status_info.proc_words += words->words_cnt;

                  status_info.cache_start.tv_sec  = 0;
                  status_info.cache_start.tv_usec = 0;

                  words->cache_cnt = 0;
                  words->words_cnt = 0;
                }

                chain_set_pwbuf_increment (chain_buf, db_entries, db_entry->cur_chain_ks_poses, pw_buf);

                iter_pos_u64++;

                if (engine_parameter->hashcat_status == STATUS_QUIT) break;
              }
            }
            else
            {
              mpz_add (tmp, chain_buf->ks_pos, iter_max);

              set_chain_ks_poses (chain_buf, db_entries, &tmp, db_entry->cur_chain_ks_poses);
            }

            if (engine_parameter->hashcat_status == STATUS_QUIT) break;

            outs_pos += iter_max_u64;

            mpz_add (total_ks_pos, total_ks_pos, iter_max);

            mpz_add (chain_buf->ks_pos, chain_buf->ks_pos, iter_max);

            if (mpz_cmp (chain_buf->ks_pos, chain_buf->ks_cnt) == 0)
            {
              db_entry->chains_pos++;

              memset (db_entry->cur_chain_ks_poses, 0, OUT_LEN_MAX * sizeof (u64));
            }

            if (mpz_cmp (total_ks_pos, total_ks_cnt) == 0) break;
          }

          if (engine_parameter->hashcat_status == STATUS_QUIT) break;

          if (mpz_cmp (total_ks_pos, total_ks_cnt) == 0) break;
        }

        if (engine_parameter->hashcat_status == STATUS_QUIT) break;
      }

      if (engine_parameter->hashcat_status != STATUS_QUIT)
      {
        // flush

        gettimeofday (&status_info.cache_start, NULL);

        run_threads (engine_parameter, db, store_out, store_debug, myabort, quick_digest);

        status_info.proc_words += words->words_cnt;
      }

      if (quiet == 0)
      {
        if (engine_parameter->hashcat_status != STATUS_QUIT)
        {
          log_info ("");

          status_display ();

          show_prompt ();
        }
      }

      /**
       * cleanup
       */

      mpz_clear (total_ks_cnt);
      mpz_clear (total_ks_pos);
      mpz_clear (total_ks_left);
      mpz_clear (tmp);
      mpz_clear (iter_max);

      for (pw_len = pw_min; pw_len <= pw_max; pw_len++)
      {
        db_entry_t *db_entry = &db_entries[pw_len];

        if (db_entry->chains_buf)
        {
          int      chains_cnt = db_entry->chains_cnt;
          chain_t *chains_buf = db_entry->chains_buf;

          int chains_idx;

          for (chains_idx = 0; chains_idx < chains_cnt; chains_idx++)
          {
            chain_t *chain_buf = &chains_buf[chains_idx];

            mpz_clear (chain_buf->ks_cnt);
            mpz_clear (chain_buf->ks_pos);
          }

          free (db_entry->chains_buf);
        }

        if (db_entry->elems_buf)  free (db_entry->elems_buf);
      }

      free (wordlen_dist);
      free (pw_orders);
      free (db_entries);

      // don't forget to reset the skip and limit values

      engine_parameter->words_skip  = words_skip;
      engine_parameter->words_limit = words_limit;
    }

    /*
     * finish
     */

    finalize ();
  }

  return 0;
}
