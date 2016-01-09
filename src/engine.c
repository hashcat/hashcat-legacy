/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "rp.h"
#include "engine.h"

#include "des-sse2.c"
#include "descrypt-sse2.c"
#include "md4-sse2.c"
#include "md5-sse2.c"
#include "sha1-sse2.c"
#include "sha256-sse2.c"
#include "sha256.c"
#include "sha512-sse2.c"
#include "sha512.c"
#include "keccak-sse2.c"
#include "gost-sse2.c"
#ifdef __AVX2__
#include "bcrypt-sse2.c"
#else
#include "bcrypt-raw.c"
#endif

char *strhashtype (const uint hash_mode)
{
  switch (hash_mode)
  {
    case     0: return ((char *) HT_00000); break;
    case    10: return ((char *) HT_00010); break;
    case    11: return ((char *) HT_00011); break;
    case    12: return ((char *) HT_00012); break;
    case    20: return ((char *) HT_00020); break;
    case    21: return ((char *) HT_00021); break;
    case    23: return ((char *) HT_00023); break;
    case    30: return ((char *) HT_00030); break;
    case    40: return ((char *) HT_00040); break;
    case    50: return ((char *) HT_00050); break;
    case    60: return ((char *) HT_00060); break;
    case   100: return ((char *) HT_00100); break;
    case   101: return ((char *) HT_00101); break;
    case   110: return ((char *) HT_00110); break;
    case   111: return ((char *) HT_00111); break;
    case   112: return ((char *) HT_00112); break;
    case   120: return ((char *) HT_00120); break;
    case   121: return ((char *) HT_00121); break;
    case   122: return ((char *) HT_00122); break;
    case   123: return ((char *) HT_00123); break;
    case   124: return ((char *) HT_00124); break;
    case   130: return ((char *) HT_00130); break;
    case   131: return ((char *) HT_00131); break;
    case   132: return ((char *) HT_00132); break;
    case   133: return ((char *) HT_00133); break;
    case   140: return ((char *) HT_00140); break;
    case   141: return ((char *) HT_00141); break;
    case   150: return ((char *) HT_00150); break;
    case   160: return ((char *) HT_00160); break;
    case   200: return ((char *) HT_00200); break;
    case   300: return ((char *) HT_00300); break;
    case   400: return ((char *) HT_00400); break;
    case   500: return ((char *) HT_00500); break;
    case   501: return ((char *) HT_00501); break;
    case   666: return ((char *) HT_00666); break;
    case   900: return ((char *) HT_00900); break;
    case  1000: return ((char *) HT_01000); break;
    case  1100: return ((char *) HT_01100); break;
    case  1400: return ((char *) HT_01400); break;
    case  1410: return ((char *) HT_01410); break;
    case  1420: return ((char *) HT_01420); break;
    case  1421: return ((char *) HT_01421); break;
    case  1430: return ((char *) HT_01430); break;
    case  1431: return ((char *) HT_01431); break;
    case  1440: return ((char *) HT_01440); break;
    case  1441: return ((char *) HT_01441); break;
    case  1450: return ((char *) HT_01450); break;
    case  1460: return ((char *) HT_01460); break;
    case  1500: return ((char *) HT_01500); break;
    case  1600: return ((char *) HT_01600); break;
    case  1700: return ((char *) HT_01700); break;
    case  1710: return ((char *) HT_01710); break;
    case  1711: return ((char *) HT_01711); break;
    case  1720: return ((char *) HT_01720); break;
    case  1722: return ((char *) HT_01722); break;
    case  1730: return ((char *) HT_01730); break;
    case  1731: return ((char *) HT_01731); break;
    case  1740: return ((char *) HT_01740); break;
    case  1750: return ((char *) HT_01750); break;
    case  1760: return ((char *) HT_01760); break;
    case  1800: return ((char *) HT_01800); break;
    case  2400: return ((char *) HT_02400); break;
    case  2410: return ((char *) HT_02410); break;
    case  2500: return ((char *) HT_02500); break;
    case  2600: return ((char *) HT_02600); break;
    case  2611: return ((char *) HT_02611); break;
    case  2612: return ((char *) HT_02612); break;
    case  2711: return ((char *) HT_02711); break;
    case  2811: return ((char *) HT_02811); break;
    case  3200: return ((char *) HT_03200); break;
    case  3300: return ((char *) HT_03300); break;
    case  3500: return ((char *) HT_03500); break;
    case  3610: return ((char *) HT_03610); break;
    case  3710: return ((char *) HT_03710); break;
    case  3711: return ((char *) HT_03711); break;
    case  3720: return ((char *) HT_03720); break;
    case  3721: return ((char *) HT_03721); break;
    case  3800: return ((char *) HT_03800); break;
    case  3910: return ((char *) HT_03910); break;
    case  4010: return ((char *) HT_04010); break;
    case  4110: return ((char *) HT_04110); break;
    case  4210: return ((char *) HT_04210); break;
    case  4300: return ((char *) HT_04300); break;
    case  4400: return ((char *) HT_04400); break;
    case  4500: return ((char *) HT_04500); break;
    case  4600: return ((char *) HT_04600); break;
    case  4700: return ((char *) HT_04700); break;
    case  4800: return ((char *) HT_04800); break;
    case  4900: return ((char *) HT_04900); break;
    case  5000: return ((char *) HT_05000); break;
    case  5100: return ((char *) HT_05100); break;
    case  5200: return ((char *) HT_05200); break;
    case  5300: return ((char *) HT_05300); break;
    case  5400: return ((char *) HT_05400); break;
    case  5500: return ((char *) HT_05500); break;
    case  5600: return ((char *) HT_05600); break;
    case  5700: return ((char *) HT_05700); break;
    case  5800: return ((char *) HT_05800); break;
    case  6300: return ((char *) HT_06300); break;
    case  6400: return ((char *) HT_06400); break;
    case  6500: return ((char *) HT_06500); break;
    case  6700: return ((char *) HT_06700); break;
    case  6900: return ((char *) HT_06900); break;
    case  7000: return ((char *) HT_07000); break;
    case  7100: return ((char *) HT_07100); break;
    case  7200: return ((char *) HT_07200); break;
    case  7300: return ((char *) HT_07300); break;
    case  7400: return ((char *) HT_07400); break;
    case  7600: return ((char *) HT_07600); break;
    case  7900: return ((char *) HT_07900); break;
    case  8400: return ((char *) HT_08400); break;
    case  8900: return ((char *) HT_08900); break;
    case  9200: return ((char *) HT_09200); break;
    case  9300: return ((char *) HT_09300); break;
    case  9900: return ((char *) HT_09900); break;
    case 10000: return ((char *) HT_10000); break;
    case 10200: return ((char *) HT_10200); break;
    case 10300: return ((char *) HT_10300); break;
    case 11000: return ((char *) HT_11000); break;
    case 11100: return ((char *) HT_11100); break;
    case 11200: return ((char *) HT_11200); break;
    case 11400: return ((char *) HT_11400); break;
    case 99999: return ((char *) HT_99999); break;
  }

  return ((char *) "Unknown");
}

const char BASE64A_TAB[64] =
{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '+', '/'
};

const char BASE64B_TAB[64] =
{
  '.', '/',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

static thread_parameter_t thread_parameters[MAX_THREADS] __attribute__ ((aligned (16)));

static MUTEX lock_store;

uint64_t get_thread_words_total (uint32_t num_threads)
{
  uint64_t thread_words_total = 0;

  uint32_t thread_id;

  for (thread_id = 0; thread_id < num_threads; thread_id++)
  {
    thread_words_total += thread_parameters[thread_id].thread_words_done;
  }

  return (thread_words_total);
}

uint64_t get_thread_plains_total (uint32_t num_threads)
{
  uint64_t thread_plains_total = 0;

  uint32_t thread_id;

  for (thread_id = 0; thread_id < num_threads; thread_id++)
  {
    thread_plains_total += thread_parameters[thread_id].thread_plains_done;
  }

  return (thread_plains_total);
}

char base64a_int2char (int i)
{
  return BASE64A_TAB[i & 0x3f];
}

int base64a_char2int (char c)
{
  char *p = strchr (BASE64A_TAB, c);

  if (p == NULL) return (-1);

  return (p - BASE64A_TAB);
}

char base64b_int2char (int i)
{
  return BASE64B_TAB[i & 0x3f];
}

int base64b_char2int (char c)
{
  char *p = strchr (BASE64B_TAB, c);

  if (p == NULL) return (-1);

  return (p - BASE64B_TAB);
}

char int_to_itoa64 (const char c)
{
       if (c == 0) return '.';
  else if (c == 1) return '/';
  else if (c < 12) return '0' + c - 2;
  else if (c < 38) return 'A' + c - 12;
  else if (c < 64) return 'a' + c - 38;

  return 0;
}

char int_to_base64 (const char c)
{
       if (c  < 26) return 'A' + c;
  else if (c  < 52) return 'a' + c - 26;
  else if (c  < 62) return '0' + c - 52;
  else if (c == 62) return '+';
  else if (c == 63) return '/';

  return 0;
}

char itoa64_to_int (const char c)
{
       if (c == '.') return 0;
  else if (c == '/') return 1;
  else if ((c >= '0') && (c <= '9')) return c - '0' + 2;
  else if ((c >= 'A') && (c <= 'Z')) return c - 'A' + 12;
  else if ((c >= 'a') && (c <= 'z')) return c - 'a' + 38;

  return 0;
}

char base64_to_int (const char c)
{
       if ((c >= 'A') && (c <= 'Z')) return c - 'A';
  else if ((c >= 'a') && (c <= 'z')) return c - 'a' + 26;
  else if ((c >= '0') && (c <= '9')) return c - '0' + 52;
  else if (c == '+') return 62;
  else if (c == '/') return 63;

  return 0;
}

char int_to_bf64 (const char c)
{
       if (c ==  0) return '.';
  else if (c ==  1) return '/';
  else if (c  < 28) return 'A' + c - 2;
  else if (c  < 54) return 'a' + c - 28;
  else if (c  < 64) return '0' + c - 54;

  return 0;
}

char bf64_to_int (const char c)
{
       if (c == '.') return 0;
  else if (c == '/') return 1;
  else if ((c >= 'A') && (c <= 'Z')) return c - 'A' +  2;
  else if ((c >= 'a') && (c <= 'z')) return c - 'a' + 28;
  else if ((c >= '0') && (c <= '9')) return c - '0' + 54;

  return 0;
}

int base64_decode (char (*f) (const char), char *in_buf, int in_len, char *out_buf)
{
  char *in_ptr = in_buf;

  char *out_ptr = out_buf;

  int i,out_len;

  for (i = 0; i < in_len; i += 4)
  {
    char out_val0 = f (in_ptr[0] & 0x7f);
    char out_val1 = f (in_ptr[1] & 0x7f);
    char out_val2 = f (in_ptr[2] & 0x7f);
    char out_val3 = f (in_ptr[3] & 0x7f);

    out_ptr[0] = ((out_val0 << 2) & 0xfc) | ((out_val1 >> 4) & 0x03);
    out_ptr[1] = ((out_val1 << 4) & 0xf0) | ((out_val2 >> 2) & 0x0f);
    out_ptr[2] = ((out_val2 << 6) & 0xc0) | ((out_val3 >> 0) & 0x3f);

    in_ptr  += 4;
    out_ptr += 3;
  }

  for (i = 0; i < in_len; i++)
  {
    if (in_buf[i] != '=') continue;

    in_len = i;
  }

  out_len = (in_len * 6) / 8;

  return out_len;
}

int base64_encode (char (*f) (const char), char *in_buf, int in_len, char *out_buf)
{
  char *in_ptr = in_buf;

  char *out_ptr = out_buf;

  int i,out_len;

  for (i = 0; i < in_len; i += 3)
  {
    char out_val0 = f  ((in_ptr[0] >> 2) & 0x3f);
    char out_val1 = f (((in_ptr[0] << 4) & 0x30)
                      |((in_ptr[1] >> 4) & 0x0f));
    char out_val2 = f (((in_ptr[1] << 2) & 0x3c)
                      |((in_ptr[2] >> 6) & 0x03));
    char out_val3 = f  ((in_ptr[2] >> 0) & 0x3f);

    out_ptr[0] = out_val0 & 0x7f;
    out_ptr[1] = out_val1 & 0x7f;
    out_ptr[2] = out_val2 & 0x7f;
    out_ptr[3] = out_val3 & 0x7f;

    in_ptr  += 3;
    out_ptr += 4;
  }

  out_len = (in_len * 8) / 6;

  for (i = 0; i < (3 - (in_len % 3)); i++)
  {
    out_len++;

    out_buf[out_len] = '=';
  }

  return out_len;
}

void descrypt_decode (unsigned char digest[DIGEST_SIZE_DESCRYPT], unsigned char buf[HASH_SIZE_DESCRYPT])
{
  char tmp_buf[100];
  uint tmp_digest[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (itoa64_to_int, (char*)buf, 11, tmp_buf);

  memcpy (tmp_digest, tmp_buf, 8);

  uint32_t tt;

  IP (tmp_digest[0], tmp_digest[1], tt);

  tmp_digest[0] = ROTR32 (tmp_digest[0], 31);
  tmp_digest[1] = ROTR32 (tmp_digest[1], 31);

  memcpy (digest, tmp_digest, 8);
}

void descrypt_encode (unsigned char digest[DIGEST_SIZE_DESCRYPT], unsigned char buf[HASH_SIZE_DESCRYPT])
{
  uint tmp_digest[2];
  char tmp_buf[16];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  memcpy (tmp_digest, digest, 8);

  tmp_digest[0] = ROTL32 (tmp_digest[0], 31);
  tmp_digest[1] = ROTL32 (tmp_digest[1], 31);

  uint32_t tt;

  FP (tmp_digest[1], tmp_digest[0], tt);

  memcpy (tmp_buf, &tmp_digest, 8);

  base64_encode (int_to_itoa64, tmp_buf, 8, (char*)buf);
}

void phpass_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_PHPASS])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;

  digest[15] = (l >>  0) & 0xff;
}

void phpass_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_PHPASS])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[15] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l);
}

void md5unix_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5UNIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[ 6] = (l >>  8) & 0xff;
  digest[12] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 1] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 2] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[ 9] = (l >>  8) & 0xff;
  digest[15] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[ 4] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;

  digest[11] = (l >>  0) & 0xff;
}

void md5unix_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5UNIX])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 6] << 8) | (digest[12] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[ 1] << 16) | (digest[ 7] << 8) | (digest[13] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[ 2] << 16) | (digest[ 8] << 8) | (digest[14] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[ 9] << 8) | (digest[15] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[ 4] << 16) | (digest[10] << 8) | (digest[ 5] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[11] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
}

void md5sun_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5SUN])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[ 6] = (l >>  8) & 0xff;
  digest[12] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 1] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 2] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[ 9] = (l >>  8) & 0xff;
  digest[15] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[ 4] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;

  digest[11] = (l >>  0) & 0xff;
}

void md5sun_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5SUN])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 6] << 8) | (digest[12] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[ 1] << 16) | (digest[ 7] << 8) | (digest[13] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[ 2] << 16) | (digest[ 8] << 8) | (digest[14] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[ 9] << 8) | (digest[15] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[ 4] << 16) | (digest[10] << 8) | (digest[ 5] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[11] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
}

void md5apr_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5APR])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[ 6] = (l >>  8) & 0xff;
  digest[12] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 1] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 2] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[ 9] = (l >>  8) & 0xff;
  digest[15] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[ 4] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;

  digest[11] = (l >>  0) & 0xff;
}

void md5apr_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5APR])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 6] << 8) | (digest[12] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[ 1] << 16) | (digest[ 7] << 8) | (digest[13] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[ 2] << 16) | (digest[ 8] << 8) | (digest[14] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[ 9] << 8) | (digest[15] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[ 4] << 16) | (digest[10] << 8) | (digest[ 5] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[11] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
}

void sha512unix_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512UNIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[21] = (l >>  8) & 0xff;
  digest[42] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[22] = (l >> 16) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[ 1] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[44] = (l >> 16) & 0xff;
  digest[ 2] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[24] = (l >>  8) & 0xff;
  digest[45] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[25] = (l >> 16) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[ 4] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[47] = (l >> 16) & 0xff;
  digest[ 5] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[27] = (l >>  8) & 0xff;
  digest[48] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[28] = (l >> 16) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[ 7] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[50] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[30] = (l >>  8) & 0xff;
  digest[51] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;
  l |= base64b_char2int (buf[43]) << 18;

  digest[31] = (l >> 16) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[10] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[44]) <<  0;
  l |= base64b_char2int (buf[45]) <<  6;
  l |= base64b_char2int (buf[46]) << 12;
  l |= base64b_char2int (buf[47]) << 18;

  digest[53] = (l >> 16) & 0xff;
  digest[11] = (l >>  8) & 0xff;
  digest[32] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[48]) <<  0;
  l |= base64b_char2int (buf[49]) <<  6;
  l |= base64b_char2int (buf[50]) << 12;
  l |= base64b_char2int (buf[51]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[33] = (l >>  8) & 0xff;
  digest[54] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[52]) <<  0;
  l |= base64b_char2int (buf[53]) <<  6;
  l |= base64b_char2int (buf[54]) << 12;
  l |= base64b_char2int (buf[55]) << 18;

  digest[34] = (l >> 16) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[56]) <<  0;
  l |= base64b_char2int (buf[57]) <<  6;
  l |= base64b_char2int (buf[58]) << 12;
  l |= base64b_char2int (buf[59]) << 18;

  digest[56] = (l >> 16) & 0xff;
  digest[14] = (l >>  8) & 0xff;
  digest[35] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[60]) <<  0;
  l |= base64b_char2int (buf[61]) <<  6;
  l |= base64b_char2int (buf[62]) << 12;
  l |= base64b_char2int (buf[63]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[36] = (l >>  8) & 0xff;
  digest[57] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[64]) <<  0;
  l |= base64b_char2int (buf[65]) <<  6;
  l |= base64b_char2int (buf[66]) << 12;
  l |= base64b_char2int (buf[67]) << 18;

  digest[37] = (l >> 16) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[16] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[68]) <<  0;
  l |= base64b_char2int (buf[69]) <<  6;
  l |= base64b_char2int (buf[70]) << 12;
  l |= base64b_char2int (buf[71]) << 18;

  digest[59] = (l >> 16) & 0xff;
  digest[17] = (l >>  8) & 0xff;
  digest[38] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[72]) <<  0;
  l |= base64b_char2int (buf[73]) <<  6;
  l |= base64b_char2int (buf[74]) << 12;
  l |= base64b_char2int (buf[75]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[39] = (l >>  8) & 0xff;
  digest[60] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[76]) <<  0;
  l |= base64b_char2int (buf[77]) <<  6;
  l |= base64b_char2int (buf[78]) << 12;
  l |= base64b_char2int (buf[79]) << 18;

  digest[40] = (l >> 16) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[19] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[80]) <<  0;
  l |= base64b_char2int (buf[81]) <<  6;
  l |= base64b_char2int (buf[82]) << 12;
  l |= base64b_char2int (buf[83]) << 18;

  digest[62] = (l >> 16) & 0xff;
  digest[20] = (l >>  8) & 0xff;
  digest[41] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[84]) <<  0;
  l |= base64b_char2int (buf[85]) <<  6;

  digest[63] = (l >>  0) & 0xff;
}

void sha512unix_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512UNIX])
{
  int l;

  l = (digest[ 0] << 16) | (digest[21] << 8) | (digest[42] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[22] << 16) | (digest[43] << 8) | (digest[ 1] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[44] << 16) | (digest[ 2] << 8) | (digest[23] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[24] << 8) | (digest[45] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[25] << 16) | (digest[46] << 8) | (digest[ 4] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[47] << 16) | (digest[ 5] << 8) | (digest[26] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l); l >>= 6;

  l = (digest[ 6] << 16) | (digest[27] << 8) | (digest[48] << 0);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l); l >>= 6;

  l = (digest[28] << 16) | (digest[49] << 8) | (digest[ 7] << 0);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l); l >>= 6;

  l = (digest[50] << 16) | (digest[ 8] << 8) | (digest[29] << 0);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l); l >>= 6;

  l = (digest[ 9] << 16) | (digest[30] << 8) | (digest[51] << 0);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l); l >>= 6;

  l = (digest[31] << 16) | (digest[52] << 8) | (digest[10] << 0);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l); l >>= 6;
  buf[43] = base64b_int2char (l); l >>= 6;

  l = (digest[53] << 16) | (digest[11] << 8) | (digest[32] << 0);

  buf[44] = base64b_int2char (l); l >>= 6;
  buf[45] = base64b_int2char (l); l >>= 6;
  buf[46] = base64b_int2char (l); l >>= 6;
  buf[47] = base64b_int2char (l); l >>= 6;

  l = (digest[12] << 16) | (digest[33] << 8) | (digest[54] << 0);

  buf[48] = base64b_int2char (l); l >>= 6;
  buf[49] = base64b_int2char (l); l >>= 6;
  buf[50] = base64b_int2char (l); l >>= 6;
  buf[51] = base64b_int2char (l); l >>= 6;

  l = (digest[34] << 16) | (digest[55] << 8) | (digest[13] << 0);

  buf[52] = base64b_int2char (l); l >>= 6;
  buf[53] = base64b_int2char (l); l >>= 6;
  buf[54] = base64b_int2char (l); l >>= 6;
  buf[55] = base64b_int2char (l); l >>= 6;

  l = (digest[56] << 16) | (digest[14] << 8) | (digest[35] << 0);

  buf[56] = base64b_int2char (l); l >>= 6;
  buf[57] = base64b_int2char (l); l >>= 6;
  buf[58] = base64b_int2char (l); l >>= 6;
  buf[59] = base64b_int2char (l); l >>= 6;

  l = (digest[15] << 16) | (digest[36] << 8) | (digest[57] << 0);

  buf[60] = base64b_int2char (l); l >>= 6;
  buf[61] = base64b_int2char (l); l >>= 6;
  buf[62] = base64b_int2char (l); l >>= 6;
  buf[63] = base64b_int2char (l); l >>= 6;

  l = (digest[37] << 16) | (digest[58] << 8) | (digest[16] << 0);

  buf[64] = base64b_int2char (l); l >>= 6;
  buf[65] = base64b_int2char (l); l >>= 6;
  buf[66] = base64b_int2char (l); l >>= 6;
  buf[67] = base64b_int2char (l); l >>= 6;

  l = (digest[59] << 16) | (digest[17] << 8) | (digest[38] << 0);

  buf[68] = base64b_int2char (l); l >>= 6;
  buf[69] = base64b_int2char (l); l >>= 6;
  buf[70] = base64b_int2char (l); l >>= 6;
  buf[71] = base64b_int2char (l); l >>= 6;

  l = (digest[18] << 16) | (digest[39] << 8) | (digest[60] << 0);

  buf[72] = base64b_int2char (l); l >>= 6;
  buf[73] = base64b_int2char (l); l >>= 6;
  buf[74] = base64b_int2char (l); l >>= 6;
  buf[75] = base64b_int2char (l); l >>= 6;

  l = (digest[40] << 16) | (digest[61] << 8) | (digest[19] << 0);

  buf[76] = base64b_int2char (l); l >>= 6;
  buf[77] = base64b_int2char (l); l >>= 6;
  buf[78] = base64b_int2char (l); l >>= 6;
  buf[79] = base64b_int2char (l); l >>= 6;

  l = (digest[62] << 16) | (digest[20] << 8) | (digest[41] << 0);

  buf[80] = base64b_int2char (l); l >>= 6;
  buf[81] = base64b_int2char (l); l >>= 6;
  buf[82] = base64b_int2char (l); l >>= 6;
  buf[83] = base64b_int2char (l); l >>= 6;

  l = 0 | (digest[63] << 0);

  buf[84] = base64b_int2char (l); l >>= 6;
  buf[85] = base64b_int2char (l); l >>= 6;
}

void sha1b64_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1B64])
{
  int l;

  l  = base64a_char2int (buf[ 3]) <<  0;
  l |= base64a_char2int (buf[ 2]) <<  6;
  l |= base64a_char2int (buf[ 1]) << 12;
  l |= base64a_char2int (buf[ 0]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[ 7]) <<  0;
  l |= base64a_char2int (buf[ 6]) <<  6;
  l |= base64a_char2int (buf[ 5]) << 12;
  l |= base64a_char2int (buf[ 4]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[11]) <<  0;
  l |= base64a_char2int (buf[10]) <<  6;
  l |= base64a_char2int (buf[ 9]) << 12;
  l |= base64a_char2int (buf[ 8]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[15]) <<  0;
  l |= base64a_char2int (buf[14]) <<  6;
  l |= base64a_char2int (buf[13]) << 12;
  l |= base64a_char2int (buf[12]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[19]) <<  0;
  l |= base64a_char2int (buf[18]) <<  6;
  l |= base64a_char2int (buf[17]) << 12;
  l |= base64a_char2int (buf[16]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[23]) <<  0;
  l |= base64a_char2int (buf[22]) <<  6;
  l |= base64a_char2int (buf[21]) << 12;
  l |= base64a_char2int (buf[20]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = 0;
  l |= base64a_char2int (buf[26]) <<  6;
  l |= base64a_char2int (buf[25]) << 12;
  l |= base64a_char2int (buf[24]) << 18;

  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

void sha1b64_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1B64])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 1] << 8) | (digest[ 2] << 0);

  buf[ 3] = base64a_int2char (l); l >>= 6;
  buf[ 2] = base64a_int2char (l); l >>= 6;
  buf[ 1] = base64a_int2char (l); l >>= 6;
  buf[ 0] = base64a_int2char (l);

  l = (digest[ 3] << 16) | (digest[ 4] << 8) | (digest[ 5] << 0);

  buf[ 7] = base64a_int2char (l); l >>= 6;
  buf[ 6] = base64a_int2char (l); l >>= 6;
  buf[ 5] = base64a_int2char (l); l >>= 6;
  buf[ 4] = base64a_int2char (l);

  l = (digest[ 6] << 16) | (digest[ 7] << 8) | (digest[ 8] << 0);

  buf[11] = base64a_int2char (l); l >>= 6;
  buf[10] = base64a_int2char (l); l >>= 6;
  buf[ 9] = base64a_int2char (l); l >>= 6;
  buf[ 8] = base64a_int2char (l);

  l = (digest[ 9] << 16) | (digest[10] << 8) | (digest[11] << 0);

  buf[15] = base64a_int2char (l); l >>= 6;
  buf[14] = base64a_int2char (l); l >>= 6;
  buf[13] = base64a_int2char (l); l >>= 6;
  buf[12] = base64a_int2char (l);

  l = (digest[12] << 16) | (digest[13] << 8) | (digest[14] << 0);

  buf[19] = base64a_int2char (l); l >>= 6;
  buf[18] = base64a_int2char (l); l >>= 6;
  buf[17] = base64a_int2char (l); l >>= 6;
  buf[16] = base64a_int2char (l);

  l = (digest[15] << 16) | (digest[16] << 8) | (digest[17] << 0);

  buf[23] = base64a_int2char (l); l >>= 6;
  buf[22] = base64a_int2char (l); l >>= 6;
  buf[21] = base64a_int2char (l); l >>= 6;
  buf[20] = base64a_int2char (l);

  l = (digest[18] << 16) | (digest[19] << 8);

  buf[27] = '=';                  l >>= 6;
  buf[26] = base64a_int2char (l); l >>= 6;
  buf[25] = base64a_int2char (l); l >>= 6;
  buf[24] = base64a_int2char (l);
}

void sha1b64s_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], uint32_t in_len, uint32_t *out_len, char *buf)
{
  char tmp_buf[in_len / 4 * 3];

  *out_len = base64_decode (base64_to_int, buf, in_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  memcpy (salt, tmp_buf + 20, *out_len - 20);

  // substract sha1 length from total output
  *out_len -= 20;
}

void sha1b64s_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], uint32_t salt_len, char *buf)
{
  char tmp_buf[20 + salt_len + 3];

  memcpy (tmp_buf, digest, 20);

  memcpy (tmp_buf + 20, salt, salt_len);

  memset (tmp_buf + 20 + salt_len, 0, 3);

  uint32_t out_len;

  out_len = base64_encode (int_to_base64, tmp_buf, 20 + salt_len, buf);

  buf[out_len + 1] = 0;
}

void sha256b64_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256B64])
{
  int l;

  l  = base64a_char2int (buf[ 3]) <<  0;
  l |= base64a_char2int (buf[ 2]) <<  6;
  l |= base64a_char2int (buf[ 1]) << 12;
  l |= base64a_char2int (buf[ 0]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[ 7]) <<  0;
  l |= base64a_char2int (buf[ 6]) <<  6;
  l |= base64a_char2int (buf[ 5]) << 12;
  l |= base64a_char2int (buf[ 4]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[11]) <<  0;
  l |= base64a_char2int (buf[10]) <<  6;
  l |= base64a_char2int (buf[ 9]) << 12;
  l |= base64a_char2int (buf[ 8]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[15]) <<  0;
  l |= base64a_char2int (buf[14]) <<  6;
  l |= base64a_char2int (buf[13]) << 12;
  l |= base64a_char2int (buf[12]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[19]) <<  0;
  l |= base64a_char2int (buf[18]) <<  6;
  l |= base64a_char2int (buf[17]) << 12;
  l |= base64a_char2int (buf[16]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[23]) <<  0;
  l |= base64a_char2int (buf[22]) <<  6;
  l |= base64a_char2int (buf[21]) << 12;
  l |= base64a_char2int (buf[20]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[27]) <<  0;
  l |= base64a_char2int (buf[26]) <<  6;
  l |= base64a_char2int (buf[25]) << 12;
  l |= base64a_char2int (buf[24]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[31]) <<  0;
  l |= base64a_char2int (buf[30]) <<  6;
  l |= base64a_char2int (buf[29]) << 12;
  l |= base64a_char2int (buf[28]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[35]) <<  0;
  l |= base64a_char2int (buf[34]) <<  6;
  l |= base64a_char2int (buf[33]) << 12;
  l |= base64a_char2int (buf[32]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[39]) <<  0;
  l |= base64a_char2int (buf[38]) <<  6;
  l |= base64a_char2int (buf[37]) << 12;
  l |= base64a_char2int (buf[36]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = 0;
  l |= base64a_char2int (buf[42]) <<  6;
  l |= base64a_char2int (buf[41]) << 12;
  l |= base64a_char2int (buf[40]) << 18;

  digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;
}

void sha256b64_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256B64])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 1] << 8) | (digest[ 2] << 0);

  buf[ 3] = base64a_int2char (l); l >>= 6;
  buf[ 2] = base64a_int2char (l); l >>= 6;
  buf[ 1] = base64a_int2char (l); l >>= 6;
  buf[ 0] = base64a_int2char (l);

  l = (digest[ 3] << 16) | (digest[ 4] << 8) | (digest[ 5] << 0);

  buf[ 7] = base64a_int2char (l); l >>= 6;
  buf[ 6] = base64a_int2char (l); l >>= 6;
  buf[ 5] = base64a_int2char (l); l >>= 6;
  buf[ 4] = base64a_int2char (l);

  l = (digest[ 6] << 16) | (digest[ 7] << 8) | (digest[ 8] << 0);

  buf[11] = base64a_int2char (l); l >>= 6;
  buf[10] = base64a_int2char (l); l >>= 6;
  buf[ 9] = base64a_int2char (l); l >>= 6;
  buf[ 8] = base64a_int2char (l);

  l = (digest[ 9] << 16) | (digest[10] << 8) | (digest[11] << 0);

  buf[15] = base64a_int2char (l); l >>= 6;
  buf[14] = base64a_int2char (l); l >>= 6;
  buf[13] = base64a_int2char (l); l >>= 6;
  buf[12] = base64a_int2char (l);

  l = (digest[12] << 16) | (digest[13] << 8) | (digest[14] << 0);

  buf[19] = base64a_int2char (l); l >>= 6;
  buf[18] = base64a_int2char (l); l >>= 6;
  buf[17] = base64a_int2char (l); l >>= 6;
  buf[16] = base64a_int2char (l);

  l = (digest[15] << 16) | (digest[16] << 8) | (digest[17] << 0);

  buf[23] = base64a_int2char (l); l >>= 6;
  buf[22] = base64a_int2char (l); l >>= 6;
  buf[21] = base64a_int2char (l); l >>= 6;
  buf[20] = base64a_int2char (l);

  l = (digest[18] << 16) | (digest[19] << 8) | (digest[20] << 0);

  buf[27] = base64a_int2char (l); l >>= 6;
  buf[26] = base64a_int2char (l); l >>= 6;
  buf[25] = base64a_int2char (l); l >>= 6;
  buf[24] = base64a_int2char (l);

  l = (digest[21] << 16) | (digest[22] << 8) | (digest[23] << 0);

  buf[31] = base64a_int2char (l); l >>= 6;
  buf[30] = base64a_int2char (l); l >>= 6;
  buf[29] = base64a_int2char (l); l >>= 6;
  buf[28] = base64a_int2char (l);

  l = (digest[24] << 16) | (digest[25] << 8) | (digest[26] << 0);

  buf[35] = base64a_int2char (l); l >>= 6;
  buf[34] = base64a_int2char (l); l >>= 6;
  buf[33] = base64a_int2char (l); l >>= 6;
  buf[32] = base64a_int2char (l);

  l = (digest[27] << 16) | (digest[28] << 8) | (digest[29] << 0);

  buf[39] = base64a_int2char (l); l >>= 6;
  buf[38] = base64a_int2char (l); l >>= 6;
  buf[37] = base64a_int2char (l); l >>= 6;
  buf[36] = base64a_int2char (l);

  l = (digest[30] << 16) | (digest[31] << 8) | (digest[32] << 0);

  buf[43] = '=';                  l >>= 6;
  buf[42] = base64a_int2char (l); l >>= 6;
  buf[41] = base64a_int2char (l); l >>= 6;
  buf[40] = base64a_int2char (l);
}

void sha1aix_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1AIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;

  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

void sha1aix_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1AIX])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l);

  l =                 0 | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l);
}

void sha256aix_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256AIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;

  //digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;
}

void sha256aix_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256AIX])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l);

  l =                 0 | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l);
}

void sha512aix_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512AIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;
  l |= base64b_char2int (buf[43]) << 18;

  digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[44]) <<  0;
  l |= base64b_char2int (buf[45]) <<  6;
  l |= base64b_char2int (buf[46]) << 12;
  l |= base64b_char2int (buf[47]) << 18;

  digest[35] = (l >>  0) & 0xff;
  digest[34] = (l >>  8) & 0xff;
  digest[33] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[48]) <<  0;
  l |= base64b_char2int (buf[49]) <<  6;
  l |= base64b_char2int (buf[50]) << 12;
  l |= base64b_char2int (buf[51]) << 18;

  digest[38] = (l >>  0) & 0xff;
  digest[37] = (l >>  8) & 0xff;
  digest[36] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[52]) <<  0;
  l |= base64b_char2int (buf[53]) <<  6;
  l |= base64b_char2int (buf[54]) << 12;
  l |= base64b_char2int (buf[55]) << 18;

  digest[41] = (l >>  0) & 0xff;
  digest[40] = (l >>  8) & 0xff;
  digest[39] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[56]) <<  0;
  l |= base64b_char2int (buf[57]) <<  6;
  l |= base64b_char2int (buf[58]) << 12;
  l |= base64b_char2int (buf[59]) << 18;

  digest[44] = (l >>  0) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[42] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[60]) <<  0;
  l |= base64b_char2int (buf[61]) <<  6;
  l |= base64b_char2int (buf[62]) << 12;
  l |= base64b_char2int (buf[63]) << 18;

  digest[47] = (l >>  0) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[45] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[64]) <<  0;
  l |= base64b_char2int (buf[65]) <<  6;
  l |= base64b_char2int (buf[66]) << 12;
  l |= base64b_char2int (buf[67]) << 18;

  digest[50] = (l >>  0) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[48] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[68]) <<  0;
  l |= base64b_char2int (buf[69]) <<  6;
  l |= base64b_char2int (buf[70]) << 12;
  l |= base64b_char2int (buf[71]) << 18;

  digest[53] = (l >>  0) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[51] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[72]) <<  0;
  l |= base64b_char2int (buf[73]) <<  6;
  l |= base64b_char2int (buf[74]) << 12;
  l |= base64b_char2int (buf[75]) << 18;

  digest[56] = (l >>  0) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[54] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[76]) <<  0;
  l |= base64b_char2int (buf[77]) <<  6;
  l |= base64b_char2int (buf[78]) << 12;
  l |= base64b_char2int (buf[79]) << 18;

  digest[59] = (l >>  0) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[57] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[80]) <<  0;
  l |= base64b_char2int (buf[81]) <<  6;
  l |= base64b_char2int (buf[82]) << 12;
  l |= base64b_char2int (buf[83]) << 18;

  digest[62] = (l >>  0) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[60] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[84]) <<  0;
  l |= base64b_char2int (buf[85]) <<  6;

  digest[63] = (l >> 16) & 0xff;
}

void sha512aix_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512AIX])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l);

  l = (digest[32] << 0) | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l); l >>= 6;
  buf[43] = base64b_int2char (l);

  l = (digest[35] << 0) | (digest[34] << 8) | (digest[33] << 16);

  buf[44] = base64b_int2char (l); l >>= 6;
  buf[45] = base64b_int2char (l); l >>= 6;
  buf[46] = base64b_int2char (l); l >>= 6;
  buf[47] = base64b_int2char (l);

  l = (digest[38] << 0) | (digest[37] << 8) | (digest[36] << 16);

  buf[48] = base64b_int2char (l); l >>= 6;
  buf[49] = base64b_int2char (l); l >>= 6;
  buf[50] = base64b_int2char (l); l >>= 6;
  buf[51] = base64b_int2char (l);

  l = (digest[41] << 0) | (digest[40] << 8) | (digest[39] << 16);

  buf[52] = base64b_int2char (l); l >>= 6;
  buf[53] = base64b_int2char (l); l >>= 6;
  buf[54] = base64b_int2char (l); l >>= 6;
  buf[55] = base64b_int2char (l);

  l = (digest[44] << 0) | (digest[43] << 8) | (digest[42] << 16);

  buf[56] = base64b_int2char (l); l >>= 6;
  buf[57] = base64b_int2char (l); l >>= 6;
  buf[58] = base64b_int2char (l); l >>= 6;
  buf[59] = base64b_int2char (l);

  l = (digest[47] << 0) | (digest[46] << 8) | (digest[45] << 16);

  buf[60] = base64b_int2char (l); l >>= 6;
  buf[61] = base64b_int2char (l); l >>= 6;
  buf[62] = base64b_int2char (l); l >>= 6;
  buf[63] = base64b_int2char (l);

  l = (digest[50] << 0) | (digest[49] << 8) | (digest[48] << 16);

  buf[64] = base64b_int2char (l); l >>= 6;
  buf[65] = base64b_int2char (l); l >>= 6;
  buf[66] = base64b_int2char (l); l >>= 6;
  buf[67] = base64b_int2char (l);

  l = (digest[53] << 0) | (digest[52] << 8) | (digest[51] << 16);

  buf[68] = base64b_int2char (l); l >>= 6;
  buf[69] = base64b_int2char (l); l >>= 6;
  buf[70] = base64b_int2char (l); l >>= 6;
  buf[71] = base64b_int2char (l);

  l = (digest[56] << 0) | (digest[55] << 8) | (digest[54] << 16);

  buf[72] = base64b_int2char (l); l >>= 6;
  buf[73] = base64b_int2char (l); l >>= 6;
  buf[74] = base64b_int2char (l); l >>= 6;
  buf[75] = base64b_int2char (l);

  l = (digest[59] << 0) | (digest[58] << 8) | (digest[57] << 16);

  buf[76] = base64b_int2char (l); l >>= 6;
  buf[77] = base64b_int2char (l); l >>= 6;
  buf[78] = base64b_int2char (l); l >>= 6;
  buf[79] = base64b_int2char (l);

  l = (digest[62] << 0) | (digest[61] << 8) | (digest[60] << 16);

  buf[80] = base64b_int2char (l); l >>= 6;
  buf[81] = base64b_int2char (l); l >>= 6;
  buf[82] = base64b_int2char (l); l >>= 6;
  buf[83] = base64b_int2char (l);

  l =                 0 |                 0 | (digest[63] << 16);

  buf[84] = base64b_int2char (l); l >>= 6;
  buf[85] = base64b_int2char (l); l >>= 6;
}

void sha1fortigate_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], char *buf)
{
  char tmp_buf[SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1];

  base64_decode (base64_to_int, buf, 44, tmp_buf);

  memcpy (salt, tmp_buf, SALT_SIZE_SHA1FORTIGATE);

  memcpy (digest, tmp_buf + SALT_SIZE_SHA1FORTIGATE, HASH_SIZE_SHA1);
}

void sha1fortigate_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], char *buf)
{
  char tmp_buf[SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1FORTIGATE + 3];
  /* Salt */
  memcpy (tmp_buf, salt, SALT_SIZE_SHA1FORTIGATE);

  /* Digest */
  memcpy (tmp_buf + SALT_SIZE_SHA1FORTIGATE, digest, HASH_SIZE_SHA1FORTIGATE);

  memset (tmp_buf + SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1FORTIGATE, 0, 3);

  base64_encode (int_to_base64, tmp_buf, SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1FORTIGATE, buf);
}

void md5cisco_decode (char in_buf[HASH_SIZE_MD5CISCO], uint32_t out_buf[4])
{
  char *ptr_in = in_buf;

  uint32_t *ptr_out = out_buf;

  uint32_t j;

  for (j = 0; j < HASH_SIZE_MD5CISCO; j++)
  {
    *ptr_out += base64b_char2int (*ptr_in++);//<<  0
    *ptr_out += base64b_char2int (*ptr_in++)   <<  6;
    *ptr_out += base64b_char2int (*ptr_in++)   << 12;
    *ptr_out += base64b_char2int (*ptr_in++)   << 18;
    ptr_out += 1;
  }
}

void md5cisco_encode (uint32_t in_buf[4], unsigned char *out_buf)
{
  uint32_t *ptr_in = in_buf;

  unsigned char *ptr_out = out_buf;

  uint32_t j;

  for (j = 0; j < 4; j++)
  {
    *ptr_out++ = base64b_int2char (*ptr_in);//>>  0
    *ptr_out++ = base64b_int2char (*ptr_in    >>  6);
    *ptr_out++ = base64b_int2char (*ptr_in    >> 12);
    *ptr_out++ = base64b_int2char (*ptr_in    >> 18);
    ptr_in  += 1;
  }
}

void bcrypt_encode (char digest[DIGEST_SIZE_BCRYPT], char salt[16], char *bcrypt_str)
{
  base64_encode (int_to_bf64, salt, 16, bcrypt_str);
  base64_encode (int_to_bf64, digest, DIGEST_SIZE_BCRYPT, bcrypt_str + SALT_SIZE_MIN_BCRYPT);

  bcrypt_str[SALT_SIZE_MIN_BCRYPT + HASH_SIZE_BCRYPT] = 0;
}

void bcrypt_decode (char digest[DIGEST_SIZE_BCRYPT], char salt[16], char *hash_buf, char *salt_buf)
{
  base64_decode (bf64_to_int, salt_buf, SALT_SIZE_MIN_BCRYPT, salt);
  base64_decode (bf64_to_int, hash_buf, HASH_SIZE_BCRYPT, digest);
}

void sha256unix_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256UNIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[20] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[21] = (l >> 16) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[11] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[ 2] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[24] = (l >> 16) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[27] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[17] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[ 8] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;

 //digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >>  0) & 0xff;


}

void sha256unix_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256UNIX])
{
  int l;

  l = (digest[ 0] << 16) | (digest[10] << 8) | (digest[20] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[21] << 16) | (digest[ 1] << 8) | (digest[11] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[12] << 16) | (digest[22] << 8) | (digest[ 2] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[13] << 8) | (digest[23] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[24] << 16) | (digest[ 4] << 8) | (digest[14] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[15] << 16) | (digest[25] << 8) | (digest[ 5] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l); l >>= 6;

  l = (digest[ 6] << 16) | (digest[16] << 8) | (digest[26] << 0);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l); l >>= 6;

  l = (digest[27] << 16) | (digest[ 7] << 8) | (digest[17] << 0);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l); l >>= 6;

  l = (digest[18] << 16) | (digest[28] << 8) | (digest[ 8] << 0);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l); l >>= 6;

  l = (digest[ 9] << 16) | (digest[19] << 8) | (digest[29] << 0);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l); l >>= 6;

  l =                  0 | (digest[31] << 8) | (digest[30] << 0);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l);
}

void sha512b64s_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char salt[BLOCK_SIZE], uint32_t in_len, uint32_t *out_len, char *buf)
{
  char tmp_buf[in_len / 4 * 3];

  *out_len = base64_decode (base64_to_int, buf, in_len, tmp_buf);

  memcpy (digest, tmp_buf, 64);

  memcpy (salt, tmp_buf + 64, *out_len - 64);

  *out_len -= 64;
}

void sha512b64s_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char salt[BLOCK_SIZE], uint32_t salt_len, char *buf)
{
  char tmp_buf[64 + salt_len + 3];

  memcpy (tmp_buf, digest, 64);

  memcpy (tmp_buf + 64, salt, salt_len);

  memset (tmp_buf + 64 + salt_len, 0, 3);

  uint32_t out_len;

  out_len = base64_encode (int_to_base64, tmp_buf, 64 + salt_len, buf);

  buf[out_len + 1] = 0;
}

void drupal7_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_DRUPAL7])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[15] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[17] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[18] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[20] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[21] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[23] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[24] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[26] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[27] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[29] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;

  digest[30] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
}

void drupal7_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_DRUPAL7])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[15] << 0) | (digest[16] << 8) | (digest[17] << 16);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l);

  l = (digest[18] << 0) | (digest[19] << 8) | (digest[20] << 16);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l);

  l = (digest[21] << 0) | (digest[22] << 8) | (digest[23] << 16);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l);

  l = (digest[24] << 0) | (digest[25] << 8) | (digest[26] << 16);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l);

  l = (digest[27] << 0) | (digest[28] << 8) | (digest[29] << 16);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l);

  l = (digest[30] << 0) | (digest[31] << 8) | (digest[32] << 16);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l);
}

int sort_by_pot (const void *v1, const void *v2)
{
  const pot_t *p1 = (const pot_t *) v1;
  const pot_t *p2 = (const pot_t *) v2;

  const hash_t *h1 = &p1->hash;
  const hash_t *h2 = &p2->hash;

  uint n;

  const salt_t *s1 = h1->salt;
  const salt_t *s2 = h2->salt;

  if (s1 && s2)
  {
    n = MIN (s1->salt_plain_len, s2->salt_plain_len);

    uint pos = 0;

    while (pos < n)
    {
      if (s1->salt_plain_buf[pos] > s2->salt_plain_buf[pos]) return ( 1);
      if (s1->salt_plain_buf[pos] < s2->salt_plain_buf[pos]) return (-1);

      pos++;
    }
  }

  const digest_t *d1 = &h1->digest;
  const digest_t *d2 = &h2->digest;

  n = strlen (d2->plain);

  while (n--)
  {
    if (d1->plain[n] > d2->plain[n]) return ( 1);
    if (d1->plain[n] < d2->plain[n]) return (-1);
  }

  return (0);
}

void format_plain (FILE *fp, char *plain, uint plain_len, uint32_t output_autohex)
{
  unsigned char *plain_ptr = (unsigned char*) plain;

  int needs_hexify = 0;

  if (output_autohex == 1)
  {
    uint i;

    for (i = 0; i < plain_len; i++)
    {
      if (plain_ptr[i] < 0x20)
      {
        needs_hexify = 1;

        break;
      }

      if (plain_ptr[i] > 0x7f)
      {
        needs_hexify = 1;

        break;
      }
    }
  }

  if (needs_hexify == 1)
  {
    fprintf (fp, "$HEX[");

    uint i;

    for (i = 0; i < plain_len; i++)
    {
      fprintf (fp, "%02x", plain_ptr[i]);
    }

    fprintf (fp, "]");
  }
  else
  {
    fwrite (plain_ptr, plain_len, 1, fp);
  }
}

void format_output (FILE *fp, engine_parameter_t *engine_parameter, char *out_buf, char *plain_ptr, uint plain_len, uint64_t pos)
{
  uint output_format = engine_parameter->output_format;
  char separator     = engine_parameter->separator;

  uint32_t output_autohex = engine_parameter->output_autohex;

  // hash[:salt] for --left / --show

  if (out_buf != NULL)
  {
    if (output_format % 2)
    {
      fputs (out_buf, fp);
    }
  }

  uint format = output_format;

  if ((format >= 9) && (format <= 15)) format = format - 8;

  // plain

  if (format > 1)
  {
    if (format < 4)
    {
      if (format == 3) fputc (separator, fp);

      format_plain (fp, plain_ptr, plain_len, output_autohex);
    }
    else if (format < 8)
    {
      if (format == 7) fputc (separator, fp);

      if (format == 6 || format == 7)
      {
        format_plain (fp, plain_ptr, plain_len, output_autohex);
      }

      if (format != 4) fputc (separator, fp);

      uint32_t i;

      for (i = 0; i < plain_len; i++)
      {
        fprintf (fp, "%02x", (unsigned char) plain_ptr[i]);
      }
    }
  }

  // crackpos
  if ((output_format >= 8) && (output_format <= 15))
  {
    if (output_format != 8) fputc (separator, fp);

    fprintf (fp, "%llu", (long long unsigned int) pos);
  }

  fputc ('\n', fp);
}

void handle_show_request (FILE *out_fp, engine_parameter_t *engine_parameter, pot_t *pot, char *input_buf, int input_len, char *hash_buf, char *salt_buf, uint32_t salt_len, uint user_len)
{
  if (pot == NULL || out_fp == NULL) return;

  uint pot_cnt = pot->pot_cnt;

  pot_t pot_key;

  pot_key.hash.salt = (salt_t *) mymalloc (sizeof (salt_t));
  pot_key.hash.salt->salt_plain_buf = salt_buf;
  pot_key.hash.salt->salt_plain_len = salt_len;

  pot_key.hash.digest.plain = hash_buf;

  pot_t *pot_ptr = (pot_t *) bsearch (&pot_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

  if (pot_ptr)
  {
    input_buf[input_len] = 0;

    // special case (username should be printed)

    if (engine_parameter->username)
    {
      uint i;

      for (i = 0; i < user_len; i++) fputc (input_buf[i], out_fp);

      fputc (engine_parameter->separator, out_fp);

      // advance the input buf (s.t. we do no print the username again and again)

      input_buf = input_buf + user_len + 1;
    }

    format_output (out_fp, engine_parameter, input_buf, pot_ptr->plain_buf, pot_ptr->plain_len, 0);
  }

  free (pot_key.hash.salt);
}

void handle_left_request (FILE *out_fp, engine_parameter_t *engine_parameter, pot_t *pot, char *input_buf, int input_len, char *hash_buf, char *salt_buf, uint32_t salt_len)
{
  if (out_fp == NULL) return;

  uint print = 0;

  if (pot != NULL)
  {
    uint pot_cnt = pot->pot_cnt;

    pot_t pot_key;

    pot_key.hash.salt = (salt_t *) mymalloc (sizeof (salt_t));
    pot_key.hash.salt->salt_plain_buf = salt_buf;
    pot_key.hash.salt->salt_plain_len = salt_len;

    pot_key.hash.digest.plain = hash_buf;

    pot_t *pot_ptr = (pot_t *) bsearch (&pot_key, pot, pot_cnt, sizeof (pot_t), sort_by_pot);

    free (pot_key.hash.salt);

    if (pot_ptr == NULL) print = 1;
  }
  else
  {
    print = 1;
  }

  if (print == 1)
  {
    input_buf[input_len] = 0;

    format_output (out_fp, engine_parameter, input_buf, NULL, 0, 0);
  }
}

/*
char hex_convert (char c)
{
  if ((c >= '0') && (c <= '9')) return (c - '0');
  if ((c >= 'A') && (c <= 'F')) return (c - 'A' + 10);
  if ((c >= 'a') && (c <= 'f')) return (c - 'a' + 10);

  return (-1);
}
*/

uint is_valid_hex_char (const char c)
{
  if ((c >= '0') && (c <= '9')) return 1;
  if ((c >= 'A') && (c <= 'F')) return 1;
  if ((c >= 'a') && (c <= 'f')) return 1;

  return 0;
}

char hex_convert (const char c)
{
  return (c & 15) + (c >> 6) * 9;
}

char hex_to_char (char hex[2])
{
  char v = 0;

  v |= (hex_convert (hex[1]) <<  0);
  v |= (hex_convert (hex[0]) <<  4);

  return (v);
}

uint32_t hex_to_uint (char hex[ 8])
{
  uint32_t v = 0;

  v |= ((uint32_t) hex_convert (hex[7]) <<  0);
  v |= ((uint32_t) hex_convert (hex[6]) <<  4);
  v |= ((uint32_t) hex_convert (hex[5]) <<  8);
  v |= ((uint32_t) hex_convert (hex[4]) << 12);
  v |= ((uint32_t) hex_convert (hex[3]) << 16);
  v |= ((uint32_t) hex_convert (hex[2]) << 20);
  v |= ((uint32_t) hex_convert (hex[1]) << 24);
  v |= ((uint32_t) hex_convert (hex[0]) << 28);

  return (v);
}

uint64_t hex_to_uint64 (char hex[16])
{
  uint64_t v = 0;

  v |= ((uint64_t) hex_convert (hex[15]) <<  0);
  v |= ((uint64_t) hex_convert (hex[14]) <<  4);
  v |= ((uint64_t) hex_convert (hex[13]) <<  8);
  v |= ((uint64_t) hex_convert (hex[12]) << 12);
  v |= ((uint64_t) hex_convert (hex[11]) << 16);
  v |= ((uint64_t) hex_convert (hex[10]) << 20);
  v |= ((uint64_t) hex_convert (hex[ 9]) << 24);
  v |= ((uint64_t) hex_convert (hex[ 8]) << 28);
  v |= ((uint64_t) hex_convert (hex[ 7]) << 32);
  v |= ((uint64_t) hex_convert (hex[ 6]) << 36);
  v |= ((uint64_t) hex_convert (hex[ 5]) << 40);
  v |= ((uint64_t) hex_convert (hex[ 4]) << 44);
  v |= ((uint64_t) hex_convert (hex[ 3]) << 48);
  v |= ((uint64_t) hex_convert (hex[ 2]) << 52);
  v |= ((uint64_t) hex_convert (hex[ 1]) << 56);
  v |= ((uint64_t) hex_convert (hex[ 0]) << 60);

  return (v);
}

void uint_to_hex_lower (uint32_t uint, char hex[8])
{
  hex[0] = uint >> 28 & 15;
  hex[1] = uint >> 24 & 15;
  hex[2] = uint >> 20 & 15;
  hex[3] = uint >> 16 & 15;
  hex[4] = uint >> 12 & 15;
  hex[5] = uint >>  8 & 15;
  hex[6] = uint >>  4 & 15;
  hex[7] = uint >>  0 & 15;

  uint32_t add;

  hex[0] += 6; add = ((hex[0] & 0x10) >> 4) * 39; hex[0] += 42 + add;
  hex[1] += 6; add = ((hex[1] & 0x10) >> 4) * 39; hex[1] += 42 + add;
  hex[2] += 6; add = ((hex[2] & 0x10) >> 4) * 39; hex[2] += 42 + add;
  hex[3] += 6; add = ((hex[3] & 0x10) >> 4) * 39; hex[3] += 42 + add;
  hex[4] += 6; add = ((hex[4] & 0x10) >> 4) * 39; hex[4] += 42 + add;
  hex[5] += 6; add = ((hex[5] & 0x10) >> 4) * 39; hex[5] += 42 + add;
  hex[6] += 6; add = ((hex[6] & 0x10) >> 4) * 39; hex[6] += 42 + add;
  hex[7] += 6; add = ((hex[7] & 0x10) >> 4) * 39; hex[7] += 42 + add;
}

void uint_to_hex_upper (uint32_t uint, char hex[8])
{
  hex[0] = uint >> 28 & 15;
  hex[1] = uint >> 24 & 15;
  hex[2] = uint >> 20 & 15;
  hex[3] = uint >> 16 & 15;
  hex[4] = uint >> 12 & 15;
  hex[5] = uint >>  8 & 15;
  hex[6] = uint >>  4 & 15;
  hex[7] = uint >>  0 & 15;

  uint32_t add;

  hex[0] += 6; add = ((hex[0] & 0x10) >> 4) * 7; hex[0] += 42 + add;
  hex[1] += 6; add = ((hex[1] & 0x10) >> 4) * 7; hex[1] += 42 + add;
  hex[2] += 6; add = ((hex[2] & 0x10) >> 4) * 7; hex[2] += 42 + add;
  hex[3] += 6; add = ((hex[3] & 0x10) >> 4) * 7; hex[3] += 42 + add;
  hex[4] += 6; add = ((hex[4] & 0x10) >> 4) * 7; hex[4] += 42 + add;
  hex[5] += 6; add = ((hex[5] & 0x10) >> 4) * 7; hex[5] += 42 + add;
  hex[6] += 6; add = ((hex[6] & 0x10) >> 4) * 7; hex[6] += 42 + add;
  hex[7] += 6; add = ((hex[7] & 0x10) >> 4) * 7; hex[7] += 42 + add;
}

void make_unicode (uint8_t *out, uint8_t *in, int size)
{
  while (size--)
  {
    *out++ = *in++;
    *out++ = 0;
  }
}

void make_unicode_upper (uint8_t *out, uint8_t *in, int size)
{
  while (size--)
  {
    *out++ = toupper (*in++);
    *out++ = 0;
  }
}

void plain_unicode (plain_t *in, plain_t *out)
{
  make_unicode (out[0].buf8, in[0].buf8, in[0].len);
  make_unicode (out[1].buf8, in[1].buf8, in[1].len);
  make_unicode (out[2].buf8, in[2].buf8, in[2].len);
  make_unicode (out[3].buf8, in[3].buf8, in[3].len);

  out[0].len = in[0].len * 2;
  out[1].len = in[1].len * 2;
  out[2].len = in[2].len * 2;
  out[3].len = in[3].len * 2;
}

void plain_unicode_and_upper (plain_t *in, plain_t *out)
{
  make_unicode_upper (out[0].buf8, in[0].buf8, in[0].len);
  make_unicode_upper (out[1].buf8, in[1].buf8, in[1].len);
  make_unicode_upper (out[2].buf8, in[2].buf8, in[2].len);
  make_unicode_upper (out[3].buf8, in[3].buf8, in[3].len);

  out[0].len = in[0].len * 2;
  out[1].len = in[1].len * 2;
  out[2].len = in[2].len * 2;
  out[3].len = in[3].len * 2;
}

int compare_digest_plain (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.plain, (*d2)->buf.plain, DIGEST_SIZE_PLAIN);
}

int compare_digest_md5 (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.md5, (*d2)->buf.md5, DIGEST_SIZE_MD5);
}

int compare_digest_sha1 (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.sha1, (*d2)->buf.sha1, DIGEST_SIZE_SHA1);
}

int compare_digest_mysql (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.mysql, (*d2)->buf.mysql, DIGEST_SIZE_MYSQL);
}

int compare_digest_md4 (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.md4, (*d2)->buf.md4, DIGEST_SIZE_MD4);
}

int compare_digest_sha256 (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.sha256, (*d2)->buf.sha256, DIGEST_SIZE_SHA256);
}

int compare_digest_sha512 (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.sha512, (*d2)->buf.sha512, DIGEST_SIZE_SHA512);
}

int compare_digest_descrypt (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.descrypt, (*d2)->buf.descrypt, DIGEST_SIZE_DESCRYPT);
}

int compare_digest_keccak (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.keccak, (*d2)->buf.keccak, DIGEST_SIZE_KECCAK);
}

int compare_digest_netntlmv1 (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.md4, (*d2)->buf.md4, DIGEST_SIZE_NETNTLMv1);
}

int compare_digest_gost (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.gost, (*d2)->buf.gost, DIGEST_SIZE_GOST);
}

int compare_digest_bcrypt (const void *p1, const void *p2)
{
  const digest_t **d1 = (const digest_t **) p1;
  const digest_t **d2 = (const digest_t **) p2;

  return memcmp ((*d1)->buf.bcrypt, (*d2)->buf.bcrypt, DIGEST_SIZE_BCRYPT);
}

uint32_t get_index_md5 (digest_t *digest)
{
  return (digest->buf.md5[0] >> INDEX_BITS);
}

uint32_t get_index_sha1 (digest_t *digest)
{
  return (digest->buf.sha1[0] >> INDEX_BITS);
}

uint32_t get_index_mysql (digest_t *digest)
{
  return (digest->buf.mysql[0] >> INDEX_BITS);
}

uint32_t get_index_md4 (digest_t *digest)
{
  return (digest->buf.md4[0] >> INDEX_BITS);
}

uint32_t get_index_sha256 (digest_t *digest)
{
  return (digest->buf.sha256[0] >> INDEX_BITS);
}

uint32_t get_index_sha512 (digest_t *digest)
{
  return ((uint32_t) digest->buf.sha512[0] >> INDEX_BITS);
}

uint32_t get_index_gost (digest_t *digest)
{
  return (digest->buf.gost[0] >> INDEX_BITS);
}

uint32_t get_index_plain (digest_t *digest)
{
  return (digest->buf.md5[0] >> INDEX_BITS);
}

uint32_t get_index_zero (digest_t *digest __attribute__((unused)))
{
  return (0);
}

void transpose_to_di4_sse2 (const __m128i *s0, const __m128i *s1, const __m128i *s2, const __m128i *s3, __m128i *p2)
{
  int i;
  int j;

  for (i = 0, j = 0; i < 16; i += 4, j += 1)
  {
    // const __m128i i0 = s0[j];
    // const __m128i i1 = s1[j];
    // const __m128i i2 = s2[j];
    // const __m128i i3 = s3[j];

    #define i0 s0[j]
    #define i1 s1[j]
    #define i2 s2[j]
    #define i3 s3[j]

    const __m128i t0 = _mm_unpacklo_epi32 (i0, i1);
    const __m128i t1 = _mm_unpacklo_epi32 (i2, i3);
    const __m128i t2 = _mm_unpackhi_epi32 (i0, i1);
    const __m128i t3 = _mm_unpackhi_epi32 (i2, i3);

    p2[i + 0] = _mm_unpacklo_epi64 (t0, t1);
    p2[i + 1] = _mm_unpackhi_epi64 (t0, t1);
    p2[i + 2] = _mm_unpacklo_epi64 (t2, t3);
    p2[i + 3] = _mm_unpackhi_epi64 (t2, t3);
  }
}

void plain_init (plain_t *in)
{
  in->len = 0; in++;
  in->len = 0; in++;
  in->len = 0; in++;
  in->len = 0;
}

void plain_init_64 (plain_t *in)
{
  in->len = 0; in++;
  in->len = 0;
}

// transforms

void md4_transform (plain_t *plains, digest_md4_sse2_t *digests)
{
  __m128i block[16];

  transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block);

  hashcat_md4_64 (digests->buf128, block);
}

void md5_transform (plain_t *plains, digest_md5_sse2_t *digests)
{
  __m128i block[16];

  transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block);

  hashcat_md5_64 (digests->buf128, block);
}

void sha1_transform (plain_t *plains, digest_sha1_sse2_t *digests)
{
  __m128i block[16];

  transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block);

  hashcat_sha1_64 (digests->buf128, block);
}

void sha256_transform (plain_t *plains, digest_sha256_sse2_t *digests)
{
  __m128i block[16];

  transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block);

  hashcat_sha256_64 (digests->buf128, block);
}

void sha512_transform (plain_t *plains, digest_sha512_sse2_t *digests)
{
  uint64_t block[16][2] __attribute__ ((aligned (16)));
  uint64_t digest[8][2] __attribute__ ((aligned (16)));

  int i;

  for (i = 0; i < 16; i++)
  {
    block[i][0] = plains[0].buf64[i];
    block[i][1] = plains[1].buf64[i];
  }

  for (i = 0; i < 8; i++)
  {
    digest[i][0] = digests->buf64[(i * 4) + 0];
    digest[i][1] = digests->buf64[(i * 4) + 1];
  }

  hashcat_sha512_64 ((__m128i *) digest, (__m128i *) block);

  for (i = 0; i < 8; i++)
  {
    digests->buf64[(i * 4) + 0] = digest[i][0];
    digests->buf64[(i * 4) + 1] = digest[i][1];
  }

  for (i = 0; i < 16; i++)
  {
    block[i][0] = plains[2].buf64[i];
    block[i][1] = plains[3].buf64[i];
  }

  for (i = 0; i < 8; i++)
  {
    digest[i][0] = digests->buf64[(i * 4) + 2];
    digest[i][1] = digests->buf64[(i * 4) + 3];
  }

  hashcat_sha512_64 ((__m128i *) digest, (__m128i *) block);

  for (i = 0; i < 8; i++)
  {
    digests->buf64[(i * 4) + 2] = digest[i][0];
    digests->buf64[(i * 4) + 3] = digest[i][1];
  }
}

// full featured

void md4_init_sse2 (digest_md4_sse2_t *digests)
{
  uint32_t *ptr = digests->buf32;

  *ptr++ = MD4M_A;
  *ptr++ = MD4M_A;
  *ptr++ = MD4M_A;
  *ptr++ = MD4M_A;
  *ptr++ = MD4M_B;
  *ptr++ = MD4M_B;
  *ptr++ = MD4M_B;
  *ptr++ = MD4M_B;
  *ptr++ = MD4M_C;
  *ptr++ = MD4M_C;
  *ptr++ = MD4M_C;
  *ptr++ = MD4M_C;
  *ptr++ = MD4M_D;
  *ptr++ = MD4M_D;
  *ptr++ = MD4M_D;
  *ptr   = MD4M_D;
}

void md5_init_sse2 (digest_md5_sse2_t *digests)
{
  uint32_t *ptr = digests->buf32;

  *ptr++ = MD5M_A;
  *ptr++ = MD5M_A;
  *ptr++ = MD5M_A;
  *ptr++ = MD5M_A;
  *ptr++ = MD5M_B;
  *ptr++ = MD5M_B;
  *ptr++ = MD5M_B;
  *ptr++ = MD5M_B;
  *ptr++ = MD5M_C;
  *ptr++ = MD5M_C;
  *ptr++ = MD5M_C;
  *ptr++ = MD5M_C;
  *ptr++ = MD5M_D;
  *ptr++ = MD5M_D;
  *ptr++ = MD5M_D;
  *ptr   = MD5M_D;
}

void sha1_init_sse2 (digest_sha1_sse2_t *digests)
{
  uint32_t *ptr = digests->buf32;

  *ptr++ = SHA1M_A;
  *ptr++ = SHA1M_A;
  *ptr++ = SHA1M_A;
  *ptr++ = SHA1M_A;
  *ptr++ = SHA1M_B;
  *ptr++ = SHA1M_B;
  *ptr++ = SHA1M_B;
  *ptr++ = SHA1M_B;
  *ptr++ = SHA1M_C;
  *ptr++ = SHA1M_C;
  *ptr++ = SHA1M_C;
  *ptr++ = SHA1M_C;
  *ptr++ = SHA1M_D;
  *ptr++ = SHA1M_D;
  *ptr++ = SHA1M_D;
  *ptr++ = SHA1M_D;
  *ptr++ = SHA1M_E;
  *ptr++ = SHA1M_E;
  *ptr++ = SHA1M_E;
  *ptr   = SHA1M_E;
}

void sha256_init_sse2 (digest_sha256_sse2_t *digests)
{
  uint32_t *ptr = digests->buf32;

  *ptr++ = SHA256M_A;
  *ptr++ = SHA256M_A;
  *ptr++ = SHA256M_A;
  *ptr++ = SHA256M_A;
  *ptr++ = SHA256M_B;
  *ptr++ = SHA256M_B;
  *ptr++ = SHA256M_B;
  *ptr++ = SHA256M_B;
  *ptr++ = SHA256M_C;
  *ptr++ = SHA256M_C;
  *ptr++ = SHA256M_C;
  *ptr++ = SHA256M_C;
  *ptr++ = SHA256M_D;
  *ptr++ = SHA256M_D;
  *ptr++ = SHA256M_D;
  *ptr++ = SHA256M_D;
  *ptr++ = SHA256M_E;
  *ptr++ = SHA256M_E;
  *ptr++ = SHA256M_E;
  *ptr++ = SHA256M_E;
  *ptr++ = SHA256M_F;
  *ptr++ = SHA256M_F;
  *ptr++ = SHA256M_F;
  *ptr++ = SHA256M_F;
  *ptr++ = SHA256M_G;
  *ptr++ = SHA256M_G;
  *ptr++ = SHA256M_G;
  *ptr++ = SHA256M_G;
  *ptr++ = SHA256M_H;
  *ptr++ = SHA256M_H;
  *ptr++ = SHA256M_H;
  *ptr   = SHA256M_H;
}

void sha512_init_sse2 (digest_sha512_sse2_t *digests)
{
  uint64_t *ptr = digests->buf64;

  *ptr++ = SHA512M_A;
  *ptr++ = SHA512M_A;
  *ptr++ = SHA512M_A;
  *ptr++ = SHA512M_A;
  *ptr++ = SHA512M_B;
  *ptr++ = SHA512M_B;
  *ptr++ = SHA512M_B;
  *ptr++ = SHA512M_B;
  *ptr++ = SHA512M_C;
  *ptr++ = SHA512M_C;
  *ptr++ = SHA512M_C;
  *ptr++ = SHA512M_C;
  *ptr++ = SHA512M_D;
  *ptr++ = SHA512M_D;
  *ptr++ = SHA512M_D;
  *ptr++ = SHA512M_D;
  *ptr++ = SHA512M_E;
  *ptr++ = SHA512M_E;
  *ptr++ = SHA512M_E;
  *ptr++ = SHA512M_E;
  *ptr++ = SHA512M_F;
  *ptr++ = SHA512M_F;
  *ptr++ = SHA512M_F;
  *ptr++ = SHA512M_F;
  *ptr++ = SHA512M_G;
  *ptr++ = SHA512M_G;
  *ptr++ = SHA512M_G;
  *ptr++ = SHA512M_G;
  *ptr++ = SHA512M_H;
  *ptr++ = SHA512M_H;
  *ptr++ = SHA512M_H;
  *ptr   = SHA512M_H;
}

void md4_update_sse2 (plain_t *plains_dst, digest_md4_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x3f;
  left[1] = plains_dst[1].len & 0x3f;
  left[2] = plains_dst[2].len & 0x3f;
  left[3] = plains_dst[3].len & 0x3f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 64)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 64 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_md4_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_md4_sse2_t));

  md4_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 64

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
      digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
      digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
      digests->buf32[i + 12] = digests_tmp.buf32[i + 12];

      buf[i] += 64 - left[i];
      len[i] -= 64 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void md5_update_sse2 (plain_t *plains_dst, digest_md5_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x3f;
  left[1] = plains_dst[1].len & 0x3f;
  left[2] = plains_dst[2].len & 0x3f;
  left[3] = plains_dst[3].len & 0x3f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 64)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 64 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_md5_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_md5_sse2_t));

  md5_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 64

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
      digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
      digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
      digests->buf32[i + 12] = digests_tmp.buf32[i + 12];

      buf[i] += 64 - left[i];
      len[i] -= 64 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void sha1_update_sse2 (plain_t *plains_dst, digest_sha1_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x3f;
  left[1] = plains_dst[1].len & 0x3f;
  left[2] = plains_dst[2].len & 0x3f;
  left[3] = plains_dst[3].len & 0x3f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 64)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 64 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_sha1_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_sha1_sse2_t));

  sha1_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 64

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
      digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
      digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
      digests->buf32[i + 12] = digests_tmp.buf32[i + 12];
      digests->buf32[i + 16] = digests_tmp.buf32[i + 16];

      buf[i] += 64 - left[i];
      len[i] -= 64 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void sha256_update_sse2 (plain_t *plains_dst, digest_sha256_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x3f;
  left[1] = plains_dst[1].len & 0x3f;
  left[2] = plains_dst[2].len & 0x3f;
  left[3] = plains_dst[3].len & 0x3f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 64)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 64 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_sha256_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_sha256_sse2_t));

  sha256_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 64

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
      digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
      digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
      digests->buf32[i + 12] = digests_tmp.buf32[i + 12];
      digests->buf32[i + 16] = digests_tmp.buf32[i + 16];
      digests->buf32[i + 20] = digests_tmp.buf32[i + 20];
      digests->buf32[i + 24] = digests_tmp.buf32[i + 24];
      digests->buf32[i + 28] = digests_tmp.buf32[i + 28];

      buf[i] += 64 - left[i];
      len[i] -= 64 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void sha512_update_sse2 (plain_t *plains_dst, digest_sha512_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x7f;
  left[1] = plains_dst[1].len & 0x7f;
  left[2] = plains_dst[2].len & 0x7f;
  left[3] = plains_dst[3].len & 0x7f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 128)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 128 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_sha512_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_sha512_sse2_t));

  sha512_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 128

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf64[i +  0] = digests_tmp.buf64[i +  0];
      digests->buf64[i +  4] = digests_tmp.buf64[i +  4];
      digests->buf64[i +  8] = digests_tmp.buf64[i +  8];
      digests->buf64[i + 12] = digests_tmp.buf64[i + 12];
      digests->buf64[i + 16] = digests_tmp.buf64[i + 16];
      digests->buf64[i + 20] = digests_tmp.buf64[i + 20];
      digests->buf64[i + 24] = digests_tmp.buf64[i + 24];
      digests->buf64[i + 28] = digests_tmp.buf64[i + 28];

      buf[i] += 128 - left[i];
      len[i] -= 128 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void md4_final_sse2 (plain_t *plains, digest_md4_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x3f;
  left[1] = len[1] & 0x3f;
  left[2] = len[2] & 0x3f;
  left[3] = len[3] & 0x3f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 64 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 56)
    {
      plains[i].buf[14] = len[i] * 8;
      plains[i].buf[15] = 0;

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_md4_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_md4_sse2_t));

    md4_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
        digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
        digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
        digests->buf32[i + 12] = digests_tmp.buf32[i + 12];

        memset (buf[i], 0, 64);

        plains[i].buf[14] = len[i] * 8;
      }
    }
  }

  md4_transform (plains, digests);
}

void md5_final_sse2 (plain_t *plains, digest_md5_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x3f;
  left[1] = len[1] & 0x3f;
  left[2] = len[2] & 0x3f;
  left[3] = len[3] & 0x3f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 64 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 56)
    {
      plains[i].buf[14] = len[i] * 8;
      plains[i].buf[15] = 0;

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_md5_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_md5_sse2_t));

    md5_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
        digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
        digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
        digests->buf32[i + 12] = digests_tmp.buf32[i + 12];

        memset (buf[i], 0, 64);

        plains[i].buf[14] = len[i] * 8;
      }
    }
  }

  md5_transform (plains, digests);
}

void sha1_final_sse2 (plain_t *plains, digest_sha1_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x3f;
  left[1] = len[1] & 0x3f;
  left[2] = len[2] & 0x3f;
  left[3] = len[3] & 0x3f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 64 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 56)
    {
      plains[i].buf[14] = 0;
      plains[i].buf[15] = len[i] * 8;

      BYTESWAP (plains[i].buf[15]);

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_sha1_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_sha1_sse2_t));

    sha1_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
        digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
        digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
        digests->buf32[i + 12] = digests_tmp.buf32[i + 12];
        digests->buf32[i + 16] = digests_tmp.buf32[i + 16];

        memset (buf[i], 0, 64);

        plains[i].buf[15] = len[i] * 8;

        BYTESWAP (plains[i].buf[15]);
      }
    }
  }

  sha1_transform (plains, digests);
}

void sha256_final_sse2 (plain_t *plains, digest_sha256_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x3f;
  left[1] = len[1] & 0x3f;
  left[2] = len[2] & 0x3f;
  left[3] = len[3] & 0x3f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 64 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 56)
    {
      plains[i].buf[14] = 0;
      plains[i].buf[15] = len[i] * 8;

      BYTESWAP (plains[i].buf[15]);

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_sha256_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_sha256_sse2_t));

    sha256_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
        digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
        digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
        digests->buf32[i + 12] = digests_tmp.buf32[i + 12];
        digests->buf32[i + 16] = digests_tmp.buf32[i + 16];
        digests->buf32[i + 20] = digests_tmp.buf32[i + 20];
        digests->buf32[i + 24] = digests_tmp.buf32[i + 24];
        digests->buf32[i + 28] = digests_tmp.buf32[i + 28];

        memset (buf[i], 0, 64);

        plains[i].buf[15] = len[i] * 8;

        BYTESWAP (plains[i].buf[15]);
      }
    }
  }

  sha256_transform (plains, digests);
}

void sha256_init (hc_sha256_ctx *ctx)
{
  ctx->state[0] = SHA256M_A;
  ctx->state[1] = SHA256M_B;
  ctx->state[2] = SHA256M_C;
  ctx->state[3] = SHA256M_D;
  ctx->state[4] = SHA256M_E;
  ctx->state[5] = SHA256M_F;
  ctx->state[6] = SHA256M_G;
  ctx->state[7] = SHA256M_H;

  ctx->len = 0;
}

void sha256_update (hc_sha256_ctx *ctx, const char *buf, int len)
{
  int left = ctx->len & 0x3f;

  ctx->len += len;

  if (left + len < 64)
  {
    memcpy (ctx->buf + left, buf, len);

    return;
  }

  memcpy (ctx->buf + left, buf, 64 - left);

  BYTESWAP (ctx->w[ 0]);
  BYTESWAP (ctx->w[ 1]);
  BYTESWAP (ctx->w[ 2]);
  BYTESWAP (ctx->w[ 3]);
  BYTESWAP (ctx->w[ 4]);
  BYTESWAP (ctx->w[ 5]);
  BYTESWAP (ctx->w[ 6]);
  BYTESWAP (ctx->w[ 7]);
  BYTESWAP (ctx->w[ 8]);
  BYTESWAP (ctx->w[ 9]);
  BYTESWAP (ctx->w[10]);
  BYTESWAP (ctx->w[11]);
  BYTESWAP (ctx->w[12]);
  BYTESWAP (ctx->w[13]);
  BYTESWAP (ctx->w[14]);
  BYTESWAP (ctx->w[15]);

  hashcat_sha256 (ctx->state, ctx->w);

  buf += 64 - left;
  len -= 64 - left;

  while (len >= 64)
  {

    memcpy (ctx->buf, buf, 64);

    BYTESWAP (ctx->w[ 0]);
    BYTESWAP (ctx->w[ 1]);
    BYTESWAP (ctx->w[ 2]);
    BYTESWAP (ctx->w[ 3]);
    BYTESWAP (ctx->w[ 4]);
    BYTESWAP (ctx->w[ 5]);
    BYTESWAP (ctx->w[ 6]);
    BYTESWAP (ctx->w[ 7]);
    BYTESWAP (ctx->w[ 8]);
    BYTESWAP (ctx->w[ 9]);
    BYTESWAP (ctx->w[10]);
    BYTESWAP (ctx->w[11]);
    BYTESWAP (ctx->w[12]);
    BYTESWAP (ctx->w[13]);
    BYTESWAP (ctx->w[14]);
    BYTESWAP (ctx->w[15]);

    hashcat_sha256 (ctx->state, ctx->w);

    buf += 64;
    len -= 64;
  }

  memcpy (ctx->buf, buf, len);
}

void sha256_final (hc_sha256_ctx *ctx)
{
  int left = ctx->len & 0x3f;

  memset (ctx->buf + left, 0, 64 - left);

  ctx->buf[left] = 0x80;

  BYTESWAP (ctx->w[ 0]);
  BYTESWAP (ctx->w[ 1]);
  BYTESWAP (ctx->w[ 2]);
  BYTESWAP (ctx->w[ 3]);
  BYTESWAP (ctx->w[ 4]);
  BYTESWAP (ctx->w[ 5]);
  BYTESWAP (ctx->w[ 6]);
  BYTESWAP (ctx->w[ 7]);
  BYTESWAP (ctx->w[ 8]);
  BYTESWAP (ctx->w[ 9]);
  BYTESWAP (ctx->w[10]);
  BYTESWAP (ctx->w[11]);
  BYTESWAP (ctx->w[12]);
  BYTESWAP (ctx->w[13]);

  if (left >= 56)
  {
    BYTESWAP (ctx->w[14]);
    BYTESWAP (ctx->w[15]);

    hashcat_sha256 (ctx->state, ctx->w);

    ctx->w[ 0] = 0;
    ctx->w[ 1] = 0;
    ctx->w[ 2] = 0;
    ctx->w[ 3] = 0;
    ctx->w[ 4] = 0;
    ctx->w[ 5] = 0;
    ctx->w[ 6] = 0;
    ctx->w[ 7] = 0;
    ctx->w[ 8] = 0;
    ctx->w[ 9] = 0;
    ctx->w[10] = 0;
    ctx->w[11] = 0;
    ctx->w[12] = 0;
    ctx->w[13] = 0;
  }

  ctx->w[14] = 0;
  ctx->w[15] = ctx->len * 8;

  hashcat_sha256 (ctx->state, ctx->w);

  BYTESWAP (ctx->state[0]);
  BYTESWAP (ctx->state[1]);
  BYTESWAP (ctx->state[2]);
  BYTESWAP (ctx->state[3]);
  BYTESWAP (ctx->state[4]);
  BYTESWAP (ctx->state[5]);
  BYTESWAP (ctx->state[6]);
  BYTESWAP (ctx->state[7]);
}

void sha512_final_sse2 (plain_t *plains, digest_sha512_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x7f;
  left[1] = len[1] & 0x7f;
  left[2] = len[2] & 0x7f;
  left[3] = len[3] & 0x7f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 128 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 112)
    {
      plains[i].buf64[14] = 0;
      plains[i].buf64[15] = len[i] * 8;

      BYTESWAP64 (plains[i].buf64[15]);

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_sha512_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_sha512_sse2_t));

    sha512_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf64[i +  0] = digests_tmp.buf64[i +  0];
        digests->buf64[i +  4] = digests_tmp.buf64[i +  4];
        digests->buf64[i +  8] = digests_tmp.buf64[i +  8];
        digests->buf64[i + 12] = digests_tmp.buf64[i + 12];
        digests->buf64[i + 16] = digests_tmp.buf64[i + 16];
        digests->buf64[i + 20] = digests_tmp.buf64[i + 20];
        digests->buf64[i + 24] = digests_tmp.buf64[i + 24];
        digests->buf64[i + 28] = digests_tmp.buf64[i + 28];

        memset (buf[i], 0, 128);

        plains[i].buf64[15] = len[i] * 8;

        BYTESWAP64 (plains[i].buf64[15]);
      }
    }
  }

  sha512_transform (plains, digests);
}

// ctx

void sha512_init (hc_sha512_ctx *ctx)
{
  ctx->state[0] = SHA512M_A;
  ctx->state[1] = SHA512M_B;
  ctx->state[2] = SHA512M_C;
  ctx->state[3] = SHA512M_D;
  ctx->state[4] = SHA512M_E;
  ctx->state[5] = SHA512M_F;
  ctx->state[6] = SHA512M_G;
  ctx->state[7] = SHA512M_H;

  ctx->len = 0;
}

void sha512_update (hc_sha512_ctx *ctx, const char *buf, int len)
{
  int left = ctx->len & 0x7f;

  ctx->len += len;

  if (left + len < 128)
  {
    memcpy (ctx->buf + left, buf, len);

    return;
  }

  memcpy (ctx->buf + left, buf, 128 - left);

  BYTESWAP64 (ctx->w[ 0]);
  BYTESWAP64 (ctx->w[ 1]);
  BYTESWAP64 (ctx->w[ 2]);
  BYTESWAP64 (ctx->w[ 3]);
  BYTESWAP64 (ctx->w[ 4]);
  BYTESWAP64 (ctx->w[ 5]);
  BYTESWAP64 (ctx->w[ 6]);
  BYTESWAP64 (ctx->w[ 7]);
  BYTESWAP64 (ctx->w[ 8]);
  BYTESWAP64 (ctx->w[ 9]);
  BYTESWAP64 (ctx->w[10]);
  BYTESWAP64 (ctx->w[11]);
  BYTESWAP64 (ctx->w[12]);
  BYTESWAP64 (ctx->w[13]);
  BYTESWAP64 (ctx->w[14]);
  BYTESWAP64 (ctx->w[15]);

  hashcat_sha512 (ctx->state, ctx->w);

  buf += 128 - left;
  len -= 128 - left;

  while (len >= 128)
  {
    memcpy (ctx->buf, buf, 128);

    BYTESWAP64 (ctx->w[ 0]);
    BYTESWAP64 (ctx->w[ 1]);
    BYTESWAP64 (ctx->w[ 2]);
    BYTESWAP64 (ctx->w[ 3]);
    BYTESWAP64 (ctx->w[ 4]);
    BYTESWAP64 (ctx->w[ 5]);
    BYTESWAP64 (ctx->w[ 6]);
    BYTESWAP64 (ctx->w[ 7]);
    BYTESWAP64 (ctx->w[ 8]);
    BYTESWAP64 (ctx->w[ 9]);
    BYTESWAP64 (ctx->w[10]);
    BYTESWAP64 (ctx->w[11]);
    BYTESWAP64 (ctx->w[12]);
    BYTESWAP64 (ctx->w[13]);
    BYTESWAP64 (ctx->w[14]);
    BYTESWAP64 (ctx->w[15]);

    hashcat_sha512 (ctx->state, ctx->w);

    buf += 128;
    len -= 128;
  }

  memcpy (ctx->buf, buf, len);
}

void sha512_final (hc_sha512_ctx *ctx)
{
  int left = ctx->len & 0x7f;

  memset (ctx->buf + left, 0, 128 - left);

  ctx->buf[left] = 0x80;

  BYTESWAP64 (ctx->w[ 0]);
  BYTESWAP64 (ctx->w[ 1]);
  BYTESWAP64 (ctx->w[ 2]);
  BYTESWAP64 (ctx->w[ 3]);
  BYTESWAP64 (ctx->w[ 4]);
  BYTESWAP64 (ctx->w[ 5]);
  BYTESWAP64 (ctx->w[ 6]);
  BYTESWAP64 (ctx->w[ 7]);
  BYTESWAP64 (ctx->w[ 8]);
  BYTESWAP64 (ctx->w[ 9]);
  BYTESWAP64 (ctx->w[10]);
  BYTESWAP64 (ctx->w[11]);
  BYTESWAP64 (ctx->w[12]);
  BYTESWAP64 (ctx->w[13]);

  if (left >= 112)
  {
    BYTESWAP64 (ctx->w[14]);
    BYTESWAP64 (ctx->w[15]);

    hashcat_sha512 (ctx->state, ctx->w);

    ctx->w[ 0] = 0;
    ctx->w[ 1] = 0;
    ctx->w[ 2] = 0;
    ctx->w[ 3] = 0;
    ctx->w[ 4] = 0;
    ctx->w[ 5] = 0;
    ctx->w[ 6] = 0;
    ctx->w[ 7] = 0;
    ctx->w[ 8] = 0;
    ctx->w[ 9] = 0;
    ctx->w[10] = 0;
    ctx->w[11] = 0;
    ctx->w[12] = 0;
    ctx->w[13] = 0;
  }

  ctx->w[14] = 0;
  ctx->w[15] = ctx->len * 8;

  hashcat_sha512 (ctx->state, ctx->w);

  BYTESWAP64 (ctx->state[0]);
  BYTESWAP64 (ctx->state[1]);
  BYTESWAP64 (ctx->state[2]);
  BYTESWAP64 (ctx->state[3]);
  BYTESWAP64 (ctx->state[4]);
  BYTESWAP64 (ctx->state[5]);
  BYTESWAP64 (ctx->state[6]);
  BYTESWAP64 (ctx->state[7]);
}

// max55

void md4_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *src = plains_src + i;
    plain_t *dst = plains_dst + i;

    const uint32_t len = dst->len + src->len;

    if (len >= 56) continue;

    memcpy (dst->buf8 + dst->len, src->buf8, src->len);

    dst->len = len;
  }
}

void md5_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *src = plains_src + i;
    plain_t *dst = plains_dst + i;

    const uint32_t len = dst->len + src->len;

    if (len >= 56) continue;

    memcpy (dst->buf8 + dst->len, src->buf8, src->len);

    dst->len = len;
  }
}

void sha1_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *src = plains_src + i;
    plain_t *dst = plains_dst + i;

    const uint32_t len = dst->len + src->len;

    if (len >= 56) continue;

    memcpy (dst->buf8 + dst->len, src->buf8, src->len);

    dst->len = len;
  }
}

void sha256_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *src = plains_src + i;
    plain_t *dst = plains_dst + i;

    const uint32_t len = dst->len + src->len;

    if (len >= 56) continue;

    memcpy (dst->buf8 + dst->len, src->buf8, src->len);

    dst->len = len;
  }
}

void md4_final_sse2_max55 (plain_t *plains, digest_md4_sse2_t *digests)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *ptr = plains + i;

    if (ptr->len >= 56) continue;

    memset (ptr->buf8 + ptr->len, 0, 64 - ptr->len);

    ptr->buf8[ptr->len] = 0x80;

    ptr->buf[14] = ptr->len * 8;
  }

  md4_transform (plains, digests);
}

void md5_final_sse2_max55 (plain_t *plains, digest_md5_sse2_t *digests)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *ptr = plains + i;

    if (ptr->len >= 56) continue;

    memset (ptr->buf8 + ptr->len, 0, 64 - ptr->len);

    ptr->buf8[ptr->len] = 0x80;

    ptr->buf[14] = ptr->len * 8;
  }

  md5_transform (plains, digests);
}

void sha1_final_sse2_max55 (plain_t *plains, digest_sha1_sse2_t *digests)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *ptr = plains + i;

    if (ptr->len >= 56) continue;

    memset (ptr->buf8 + ptr->len, 0, 64 - ptr->len);

    ptr->buf8[ptr->len] = 0x80;

    ptr->buf[15] = ptr->len * 8;

    BYTESWAP (ptr->buf[15]);
  }

  sha1_transform (plains, digests);
}

void sha256_final_sse2_max55 (plain_t *plains, digest_sha256_sse2_t *digests)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *ptr = plains + i;

    if (ptr->len >= 56) continue;

    memset (ptr->buf8 + ptr->len, 0, 64 - ptr->len);

    ptr->buf8[ptr->len] = 0x80;

    ptr->buf[15] = ptr->len * 8;

    BYTESWAP (ptr->buf[15]);
  }

  sha256_transform (plains, digests);
}

/**
 * old helper -- kill them with fire�����
 */

void descrypt_64 (plain_t *plains, digest_t *digests)
{
  uint32_t i, j;

  uint32_t digest[2][4] __attribute__ ((aligned (16)));
  uint32_t blocks[4][4] __attribute__ ((aligned (16)));

  for (j = 0; j < 4; j++)
  {
    for (i = 0; i < 4; i++)
    {
      blocks[i][j] = plains[j].buf[i];
    }
  }

  hashcat_descrypt_64_sse2 ((__m128i *)digest, (__m128i *)blocks);

  for (j = 0; j < 2; j++)
  {
    for (i = 0; i < 4; i++)
    {
      digests[i].buf.descrypt[j] = digest[j][i];
    }
  }
}

void sha512 (plain_t *plains, digest_t *digests)
{
  int j;

  for (j = 0; j < 4; j++)
  {
    uint64_t digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    int len = plains[j].len;

    uint64_t block[16];

    int off;

    int left;

    for (left = len, off = 0; left >= 128; left -= 128, off += 16)
    {
      int i;

      for (i = 0; i < 16; i++)
      {
        block[i] = plains[j].buf64[off + i];

        BYTESWAP64 (block[i]);
      }

      hashcat_sha512 (digest, block);
    }

    if (left >= 112)
    {
      int i;

      for (i = 0; i < 16; i++)
      {
        block[i] = plains[j].buf64[off + i];

        BYTESWAP64 (block[i]);
      }

      hashcat_sha512 (digest, block);

      for (i = 0; i < 14; i++)
      {
        block[i] = 0;
      }

      block[14] = 0;
      block[15] = len * 8;

      hashcat_sha512 (digest, block);
    }
    else
    {
      int i;

      for (i = 0; i < 14; i++)
      {
        block[i] = plains[j].buf64[off + i];

        BYTESWAP64 (block[i]);
      }

      block[14] = 0;
      block[15] = len * 8;

      hashcat_sha512 (digest, block);
    }

    digests[j].buf.sha512[0] = digest[0];
    digests[j].buf.sha512[1] = digest[1];
    digests[j].buf.sha512[2] = digest[2];
    digests[j].buf.sha512[3] = digest[3];
    digests[j].buf.sha512[4] = digest[4];
    digests[j].buf.sha512[5] = digest[5];
    digests[j].buf.sha512[6] = digest[6];
    digests[j].buf.sha512[7] = digest[7];
  }
}

void keccak (plain_t *plains, digest_t *digests)
{
  uint32_t i;
  uint32_t j;

  uint64_t digest_l[25][2] __attribute__ ((aligned (16)));
  uint64_t digest_r[25][2] __attribute__ ((aligned (16)));

  for (j = 0; j < 2; j++)
  {
    uint32_t j2 = j * 2;

    for (i = 0; i < 25; i++)
    {
      digest_l[i][j] = plains[j2 + 0].buf64[i];
      digest_r[i][j] = plains[j2 + 1].buf64[i];
    }
  }

  hashcat_keccak_64 ((__m128i *) digest_l);
  hashcat_keccak_64 ((__m128i *) digest_r);

  for (j = 0; j < 2; j++)
  {
    uint32_t j2 = j * 2;

    for (i = 0; i < 8; i++)
    {
      digests[j2 + 0].buf.keccak[i] = digest_l[i][j];
      digests[j2 + 1].buf.keccak[i] = digest_r[i][j];
    }
  }
}

void gost_64 (plain_t *plains, digest_t *digests)
{
  uint32_t digest[ 8][4] __attribute__ ((aligned (16)));
  uint32_t blocks[16][4] __attribute__ ((aligned (16)));

  uint32_t i, j;

  for (j = 0; j < 4; j++)
  {
    for (i = 0; i < 16; i++)
    {
      blocks[i][j] = plains[j].buf[i];
    }
  }

  //  SSE2
  hashcat_gost_64_sse2 ((__m128i *)digest, (__m128i *)blocks);

  //  normal
  //  hashcat_gost_64 (digest, blocks);

  for (j = 0; j < 8; j++)
  {
    for (i = 0; i < 4; i++)
    {
      digests[i].buf.gost[j] = digest[j][i];
    }
  }
}

// void bcrypt_64_sse2 (plain_t *plains, plain_t *salt, digest_bcrypt_sse2_t *digests)
// {
//   __m128i block_words[16];
//   __m128i block_salts[16];
//
//   uint32_t i;
//
//   for (i = 0; i < 4; i++) plains[i].buf[15] = plains[i].len;
//
//   transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block_words);
//   transpose_to_di4_sse2 (salt[0].buf128, salt[1].buf128, salt[2].buf128, salt[3].buf128, block_salts);
//
//   hashcat_bcrypt_64_sse2 (digests->buf128, block_words, block_salts);
// }

void bcrypt_64 (plain_t *plains, plain_t *salt, uint32_t iterations, digest_bcrypt_sse2_t *digests)
{
  #ifdef __AVX2__
  hashcat_bcrypt_64 (digests->buf128, plains, salt, iterations);
  #else
  hashcat_bcrypt_64 (digests->buf32, plains, salt, iterations);
  #endif
}

uint64_t words_step_size = 1;

void end (thread_parameter_t *thread_parameter)
{
  // update thread_words_done w/ the final number of words checked
  thread_parameter->thread_words_done += words_step_size;

  // check if we did exceed the maximum word cnt (only possible if words_step_size > 1)
  uint64_t thread_words_total = get_thread_words_total (thread_parameter->num_threads);
  words_t *words = thread_parameter->db->words;

  if (thread_words_total > words->words_cnt)
  {
    thread_parameter->thread_words_done -= thread_words_total - words->words_cnt;
  }

  thread_parameter->done ();
}

void indb_single (thread_parameter_t *thread_parameter, plain_t *plains, digest_t *digests, salt_t *salt)
{
  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    digest_t *digest_ptr = &digests[i];

    if (thread_parameter->compare_digest (&digest_ptr, &thread_parameter->quick_digest) != 0) continue;

    ACMutexLock (lock_store);

    thread_parameter->quick_digest->found = 1;

    thread_parameter->store_out (&plains[i], digest_ptr, salt);

    thread_parameter->db->salts_found++;

    end (thread_parameter);

    ACMutexUnlock (lock_store);
  }
}

void indb_multi (thread_parameter_t *thread_parameter, plain_t *plains, digest_t *digests, salt_t *salt)
{
  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    index_t *index = salt->indexes_buf[thread_parameter->get_index (&digests[i])];

    if (index == NULL) continue;

    if (index->digests_cnt == 0) continue;

    digest_t *digest_ptr = &digests[i];

    digest_t **digest;

    if ((digest = bsearch (&digest_ptr, index->digests_buf, index->digests_cnt, sizeof (digest_t *), thread_parameter->compare_digest)) != NULL)
    {
      ACMutexLock (lock_store);

      if ((*digest)->found == 0)
      {
        (*digest)->found = 1;

        thread_parameter->store_out (&plains[i], digest_ptr, salt);

        index->digests_found++;

        if (index->digests_found == index->digests_cnt) salt->indexes_found++;

        db_t *db = thread_parameter->db;

        if (salt->indexes_found == salt->indexes_cnt) db->salts_found++;

        if (db->salts_found == db->salts_cnt) end (thread_parameter);
      }

      ACMutexUnlock (lock_store);
    }
  }
}

void transpose_md5_digest (digest_md5_sse2_t *in, digest_t *out)
{
  uint32_t *ptr = in->buf32;

  out[0].buf.md5[0] = *ptr++;
  out[1].buf.md5[0] = *ptr++;
  out[2].buf.md5[0] = *ptr++;
  out[3].buf.md5[0] = *ptr++;
  out[0].buf.md5[1] = *ptr++;
  out[1].buf.md5[1] = *ptr++;
  out[2].buf.md5[1] = *ptr++;
  out[3].buf.md5[1] = *ptr++;
  out[0].buf.md5[2] = *ptr++;
  out[1].buf.md5[2] = *ptr++;
  out[2].buf.md5[2] = *ptr++;
  out[3].buf.md5[2] = *ptr++;
  out[0].buf.md5[3] = *ptr++;
  out[1].buf.md5[3] = *ptr++;
  out[2].buf.md5[3] = *ptr++;
  out[3].buf.md5[3] = *ptr;
}

void transpose_md4_digest (digest_md4_sse2_t *in, digest_t *out)
{
  uint32_t *ptr = in->buf32;

  out[0].buf.md4[0] = *ptr++;
  out[1].buf.md4[0] = *ptr++;
  out[2].buf.md4[0] = *ptr++;
  out[3].buf.md4[0] = *ptr++;
  out[0].buf.md4[1] = *ptr++;
  out[1].buf.md4[1] = *ptr++;
  out[2].buf.md4[1] = *ptr++;
  out[3].buf.md4[1] = *ptr++;
  out[0].buf.md4[2] = *ptr++;
  out[1].buf.md4[2] = *ptr++;
  out[2].buf.md4[2] = *ptr++;
  out[3].buf.md4[2] = *ptr++;
  out[0].buf.md4[3] = *ptr++;
  out[1].buf.md4[3] = *ptr++;
  out[2].buf.md4[3] = *ptr++;
  out[3].buf.md4[3] = *ptr;
}

void transpose_sha1_digest (digest_sha1_sse2_t *in, digest_t *out)
{
  uint32_t *ptr = in->buf32;

  out[0].buf.sha1[0] = *ptr++;
  out[1].buf.sha1[0] = *ptr++;
  out[2].buf.sha1[0] = *ptr++;
  out[3].buf.sha1[0] = *ptr++;
  out[0].buf.sha1[1] = *ptr++;
  out[1].buf.sha1[1] = *ptr++;
  out[2].buf.sha1[1] = *ptr++;
  out[3].buf.sha1[1] = *ptr++;
  out[0].buf.sha1[2] = *ptr++;
  out[1].buf.sha1[2] = *ptr++;
  out[2].buf.sha1[2] = *ptr++;
  out[3].buf.sha1[2] = *ptr++;
  out[0].buf.sha1[3] = *ptr++;
  out[1].buf.sha1[3] = *ptr++;
  out[2].buf.sha1[3] = *ptr++;
  out[3].buf.sha1[3] = *ptr++;
  out[0].buf.sha1[4] = *ptr++;
  out[1].buf.sha1[4] = *ptr++;
  out[2].buf.sha1[4] = *ptr++;
  out[3].buf.sha1[4] = *ptr;
}

void transpose_sha256_digest (digest_sha256_sse2_t *in, digest_t *out)
{
  uint32_t *ptr = in->buf32;

  out[0].buf.sha256[0] = *ptr++;
  out[1].buf.sha256[0] = *ptr++;
  out[2].buf.sha256[0] = *ptr++;
  out[3].buf.sha256[0] = *ptr++;
  out[0].buf.sha256[1] = *ptr++;
  out[1].buf.sha256[1] = *ptr++;
  out[2].buf.sha256[1] = *ptr++;
  out[3].buf.sha256[1] = *ptr++;
  out[0].buf.sha256[2] = *ptr++;
  out[1].buf.sha256[2] = *ptr++;
  out[2].buf.sha256[2] = *ptr++;
  out[3].buf.sha256[2] = *ptr++;
  out[0].buf.sha256[3] = *ptr++;
  out[1].buf.sha256[3] = *ptr++;
  out[2].buf.sha256[3] = *ptr++;
  out[3].buf.sha256[3] = *ptr++;
  out[0].buf.sha256[4] = *ptr++;
  out[1].buf.sha256[4] = *ptr++;
  out[2].buf.sha256[4] = *ptr++;
  out[3].buf.sha256[4] = *ptr++;
  out[0].buf.sha256[5] = *ptr++;
  out[1].buf.sha256[5] = *ptr++;
  out[2].buf.sha256[5] = *ptr++;
  out[3].buf.sha256[5] = *ptr++;
  out[0].buf.sha256[6] = *ptr++;
  out[1].buf.sha256[6] = *ptr++;
  out[2].buf.sha256[6] = *ptr++;
  out[3].buf.sha256[6] = *ptr++;
  out[0].buf.sha256[7] = *ptr++;
  out[1].buf.sha256[7] = *ptr++;
  out[2].buf.sha256[7] = *ptr++;
  out[3].buf.sha256[7] = *ptr;
}

void transpose_sha512_digest (digest_sha512_sse2_t *in, digest_t *out)
{
  uint64_t *ptr = in->buf64;

  out[0].buf.sha512[0] = *ptr++;
  out[1].buf.sha512[0] = *ptr++;
  out[2].buf.sha512[0] = *ptr++;
  out[3].buf.sha512[0] = *ptr++;
  out[0].buf.sha512[1] = *ptr++;
  out[1].buf.sha512[1] = *ptr++;
  out[2].buf.sha512[1] = *ptr++;
  out[3].buf.sha512[1] = *ptr++;
  out[0].buf.sha512[2] = *ptr++;
  out[1].buf.sha512[2] = *ptr++;
  out[2].buf.sha512[2] = *ptr++;
  out[3].buf.sha512[2] = *ptr++;
  out[0].buf.sha512[3] = *ptr++;
  out[1].buf.sha512[3] = *ptr++;
  out[2].buf.sha512[3] = *ptr++;
  out[3].buf.sha512[3] = *ptr++;
  out[0].buf.sha512[4] = *ptr++;
  out[1].buf.sha512[4] = *ptr++;
  out[2].buf.sha512[4] = *ptr++;
  out[3].buf.sha512[4] = *ptr++;
  out[0].buf.sha512[5] = *ptr++;
  out[1].buf.sha512[5] = *ptr++;
  out[2].buf.sha512[5] = *ptr++;
  out[3].buf.sha512[5] = *ptr++;
  out[0].buf.sha512[6] = *ptr++;
  out[1].buf.sha512[6] = *ptr++;
  out[2].buf.sha512[6] = *ptr++;
  out[3].buf.sha512[6] = *ptr++;
  out[0].buf.sha512[7] = *ptr++;
  out[1].buf.sha512[7] = *ptr++;
  out[2].buf.sha512[7] = *ptr++;
  out[3].buf.sha512[7] = *ptr;
}

void transpose_bcrypt_digest (digest_bcrypt_sse2_t *in, digest_t *out)
{
  uint32_t *ptr = in->buf32;

  out[0].buf.bcrypt[0] = *ptr++;
  out[1].buf.bcrypt[0] = *ptr++;
  out[2].buf.bcrypt[0] = *ptr++;
  out[3].buf.bcrypt[0] = *ptr++;
  out[0].buf.bcrypt[1] = *ptr++;
  out[1].buf.bcrypt[1] = *ptr++;
  out[2].buf.bcrypt[1] = *ptr++;
  out[3].buf.bcrypt[1] = *ptr++;
  out[0].buf.bcrypt[2] = *ptr++;
  out[1].buf.bcrypt[2] = *ptr++;
  out[2].buf.bcrypt[2] = *ptr++;
  out[3].buf.bcrypt[2] = *ptr++;
  out[0].buf.bcrypt[3] = *ptr++;
  out[1].buf.bcrypt[3] = *ptr++;
  out[2].buf.bcrypt[3] = *ptr++;
  out[3].buf.bcrypt[3] = *ptr++;
  out[0].buf.bcrypt[4] = *ptr++;
  out[1].buf.bcrypt[4] = *ptr++;
  out[2].buf.bcrypt[4] = *ptr++;
  out[3].buf.bcrypt[4] = *ptr++;
  out[0].buf.bcrypt[5] = *ptr++;
  out[1].buf.bcrypt[5] = *ptr++;
  out[2].buf.bcrypt[5] = *ptr++;
  out[3].buf.bcrypt[5] = *ptr;
}

void hashing_00000 (thread_parameter_t *thread_parameter, plain_t *in)
{
  db_t *db = thread_parameter->db;

  digest_md5_sse2_t digests;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  digest_t dgst[4];

  transpose_md5_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_00010 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_t dgst[4];

  digest_md5_sse2_t digests;

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, in);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_final_sse2_max55  (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00020 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in);

    md5_final_sse2_max55  (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00030 (thread_parameter_t *thread_parameter, plain_t *in)
{
  plain_t plains[4];

  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t in_u[4];

  plain_unicode (in, in_u);

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, in_u);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00040 (thread_parameter_t *thread_parameter, plain_t *in)
{
  plain_t plains[4];

  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t in_u[4];

  plain_unicode (in, in_u);

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in_u);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00050 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad_dgst[4][4] __attribute__ ((aligned (16)));
  uint32_t opad_dgst[4][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad_dgst[0][i] = MD5M_A;
    ipad_dgst[1][i] = MD5M_B;
    ipad_dgst[2][i] = MD5M_C;
    ipad_dgst[3][i] = MD5M_D;

    opad_dgst[0][i] = MD5M_A;
    opad_dgst[1][i] = MD5M_B;
    opad_dgst[2][i] = MD5M_C;
    opad_dgst[3][i] = MD5M_D;
  }

  hashcat_md5_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
  hashcat_md5_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    uint32_t ipad_dgst_tmp[4][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst_tmp[4][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

      memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

      ptrs_tmp[i][salt->salt_plain_len] = 0x80;

      for (j = 0; j < 14; j++)
      {
        ipad_buf[j][i] = plains_tmp[i].buf[j];
      }

      ipad_buf[14][i] = (64 + salt->salt_plain_len) * 8;
      ipad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        opad_buf[j][i] = ipad_dgst_tmp[j][i];
      }

      opad_buf[ 4][i] = 0x80;
      opad_buf[ 5][i] = 0;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = (64 + 16) * 8;
      opad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        digests[i].buf.md5[j] = opad_dgst_tmp[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_00060 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad_dgst[4][4] __attribute__ ((aligned (16)));
  uint32_t opad_dgst[4][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        ipad_dgst[j][i] = salt->ipad_prehashed_buf[j];
        opad_dgst[j][i] = salt->opad_prehashed_buf[j];
      }
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], ptrs[i], plains[i].len);

      memset (ptrs_tmp[i] + plains[i].len, 0, BLOCK_SIZE - plains[i].len);

      ptrs_tmp[i][plains[i].len] = 0x80;

      for (j = 0; j < 14; j++)
      {
        ipad_buf[j][i] = plains_tmp[i].buf[j];
      }

      ipad_buf[14][i] = (64 + plains[i].len) * 8;
      ipad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        opad_buf[j][i] = ipad_dgst[j][i];
      }

      opad_buf[ 4][i] = 0x80;
      opad_buf[ 5][i] = 0;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = (64 + 16) * 8;
      opad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        digests[i].buf.md5[j] = opad_dgst[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_00100 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  db_t *db = thread_parameter->db;

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (in, &digests);

  transpose_sha1_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_00110 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    sha1_init_sse2 (&digests);

    plain_init (plains);

    sha1_update_sse2_max55 (plains, in);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00120 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_update_sse2_max55 (plains, in);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00123 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  uint i;

  for (i = 0; i < 4; i++) in[i].len += 1;

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_update_sse2_max55 (plains, in);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00130 (thread_parameter_t *thread_parameter, plain_t *in)
{
  plain_t plains[4];

  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t in_u[4];

  plain_unicode (in, in_u);

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains, in_u);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00131 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t in_uu[4];

  plain_unicode_and_upper (in, in_uu);

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains, in_uu);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00133 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t in_u[4];

  plain_unicode (in, in_u);

  db_t *db = thread_parameter->db;

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (in_u, &digests);

  transpose_sha1_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_00140 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  plain_t in_u[4];

  plain_unicode (in, in_u);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_update_sse2_max55 (plains, in_u);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00150 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad_dgst[5][4] __attribute__ ((aligned (16)));
  uint32_t opad_dgst[5][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad_dgst[0][i] = SHA1M_A;
    ipad_dgst[1][i] = SHA1M_B;
    ipad_dgst[2][i] = SHA1M_C;
    ipad_dgst[3][i] = SHA1M_D;
    ipad_dgst[4][i] = SHA1M_E;

    opad_dgst[0][i] = SHA1M_A;
    opad_dgst[1][i] = SHA1M_B;
    opad_dgst[2][i] = SHA1M_C;
    opad_dgst[3][i] = SHA1M_D;
    opad_dgst[4][i] = SHA1M_E;
  }

  hashcat_sha1_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
  hashcat_sha1_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    uint32_t ipad_dgst_tmp[5][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst_tmp[5][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

      memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

      ptrs_tmp[i][salt->salt_plain_len] = 0x80;

      for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->salt_plain_len) * 8;

      BYTESWAP (ipad_buf[15][i]);
    }

    hashcat_sha1_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        opad_buf[j][i] = ipad_dgst_tmp[j][i];
      }

      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        digests[i].buf.sha1[j] = opad_dgst_tmp[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_00160 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad_dgst[5][4] __attribute__ ((aligned (16)));
  uint32_t opad_dgst[5][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        ipad_dgst[j][i] = salt->ipad_prehashed_buf[j];
        opad_dgst[j][i] = salt->opad_prehashed_buf[j];
      }
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], ptrs[i], plains[i].len);

      memset (ptrs_tmp[i] + plains[i].len, 0, BLOCK_SIZE - plains[i].len);

      ptrs_tmp[i][plains[i].len] = 0x80;

      for (j = 0; j < 14; j++)
      {
        ipad_buf[j][i] = plains_tmp[i].buf[j];

        BYTESWAP (ipad_buf[j][i]);
      }

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + plains[i].len) * 8;
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (ipad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        opad_buf[j][i] = ipad_dgst[j][i];
      }

      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        digests[i].buf.sha1[j] = opad_dgst[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_00200 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  unsigned char *ptrs[4];

  memset (ptrs, 0, sizeof (ptrs));

  ptrs[0] = (unsigned char *) &plains[0].buf;
  ptrs[1] = (unsigned char *) &plains[1].buf;
  ptrs[2] = (unsigned char *) &plains[2].buf;
  ptrs[3] = (unsigned char *) &plains[3].buf;

  unsigned char *ptrs_tmp[4];

  memset (ptrs_tmp, 0, sizeof (ptrs_tmp));

  ptrs_tmp[0] = (unsigned char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (unsigned char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (unsigned char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (unsigned char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    uint32_t nr0 = 0x50305735;
    uint32_t nr1 = 0x12345671;

    uint32_t add = 7;

    unsigned char *ptr = ptrs[i];

    for (; *ptr; ptr++)
    {
      nr0 ^= (((nr0 & 63) + add) * *ptr) + (nr0 << 8);
      nr1 += (nr1 << 8) ^ nr0;
      add += *ptr;
    }

    digests[i].buf.mysql[0] = nr0 & 0x7fffffff;
    digests[i].buf.mysql[1] = nr1 & 0x7fffffff;
  }

  thread_parameter->indb (thread_parameter, plains, digests, db->salts_buf[0]);
}

void hashing_00300 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    sha1_init_sse2 (&digests);

    sha1_final_sse2_max55 (in, &digests);

    transpose_sha1_digest (&digests, dgst);

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      BYTESWAP (dgst[i].buf.sha1[0]);
      BYTESWAP (dgst[i].buf.sha1[1]);
      BYTESWAP (dgst[i].buf.sha1[2]);
      BYTESWAP (dgst[i].buf.sha1[3]);
      BYTESWAP (dgst[i].buf.sha1[4]);

      plains[i].buf[0] = dgst[i].buf.sha1[0];
      plains[i].buf[1] = dgst[i].buf.sha1[1];
      plains[i].buf[2] = dgst[i].buf.sha1[2];
      plains[i].buf[3] = dgst[i].buf.sha1[3];
      plains[i].buf[4] = dgst[i].buf.sha1[4];

      plains[i].len = 20;
    }

    sha1_init_sse2 (&digests);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00400 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &in[0].buf;
  ptrs[1] = (char *) &in[1].buf;
  ptrs[2] = (char *) &in[2].buf;
  ptrs[3] = (char *) &in[3].buf;

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains[0].buf;
  ptrs_tmp[1] = (char *) &plains[1].buf;
  ptrs_tmp[2] = (char *) &plains[2].buf;
  ptrs_tmp[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      plains[i].len = 16 + in[i].len;

      memcpy (ptrs_tmp[i] + 16, ptrs[i], in[i].len);
    }

    uint32_t count;

    for (count = 0; count < salt->iterations; count++)
    {
      for (i = 0; i < 4; i++)
      {
        plains[i].buf[0] = dgst[i].buf.md5[0];
        plains[i].buf[1] = dgst[i].buf.md5[1];
        plains[i].buf[2] = dgst[i].buf.md5[2];
        plains[i].buf[3] = dgst[i].buf.md5[3];
      }

      md5_init_sse2 (&digests);

      md5_final_sse2 (plains, &digests);

      transpose_md5_digest (&digests, dgst);
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_00500 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &in[0].buf;
  ptrs[1] = (char *) &in[1].buf;
  ptrs[2] = (char *) &in[2].buf;
  ptrs[3] = (char *) &in[3].buf;

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains[0].buf;
  ptrs_tmp[1] = (char *) &plains[1].buf;
  ptrs_tmp[2] = (char *) &plains[2].buf;
  ptrs_tmp[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, in);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      if (in[i].len > 16) continue;

      plains[i].len = in[i].len + MD5UNIX_SIGN + salt->salt_plain_len;

      /* The password first, since that is what is most unknown */
      /* Then our magic string */
      /* Then the raw salt */
      /* Then just as many characters of the MD5(pw,salt,pw) */

      memcpy (ptrs_tmp[i], ptrs[i], in[i].len);
      memcpy (ptrs_tmp[i] + in[i].len, MD5UNIX_MAGIC, MD5UNIX_SIGN);
      memcpy (ptrs_tmp[i] + in[i].len + MD5UNIX_SIGN, salt->salt_plain_buf, salt->salt_plain_len);
      memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, in[i].len);

      plains[i].len += in[i].len;

      /* Then something really weird... */

      switch (in[i].len)
      {
        case 1:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          plains[i].len += 1;
          break;

        case 2:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          plains[i].len += 2;
          break;

        case 3:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          plains[i].len += 2;
          break;

        case 4:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 5:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 6:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 7:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 8:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 9:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 10:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 11:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 12:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 13:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 14:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 15:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;
      }

      /*
      int pl;

      for (pl = in[i].len; pl; pl >>= 1)
      {
        if ((plains[i].len + 1) < PLAIN_SIZE_MD5)
        {
          ptrs_tmp[i][plains[i].len] = (pl & 1) ? '\0' : ptrs[i][0];

          plains[i].len++;
        }
      }
      */
    }

    md5_init_sse2 (&digests);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    /* and now, just to make sure things don't run too fast */

    uint32_t j;

    for (j = 0; j < salt->iterations; j++)
    {
      int a1 = j & 1;
      int m3 = j % 3;
      int m7 = j % 7;

      for (i = 0; i < 4; i++)
      {
        if (in[i].len > 16) continue;

        memset (ptrs_tmp[i], 0, BLOCK_SIZE);

        plains[i].len = 0;

        if (a1)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }
        else
        {
          memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, 16);

          plains[i].len += 16;
        }

        if (m3)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, salt->salt_plain_buf, salt->salt_plain_len);

          plains[i].len += salt->salt_plain_len;
        }

        if (m7)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }

        if (a1)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, 16);

          plains[i].len += 16;
        }
        else
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }
      }

      md5_init_sse2 (&digests);

      md5_final_sse2_max55 (plains, &digests);

      transpose_md5_digest (&digests, dgst);
    }

    thread_parameter->indb (thread_parameter, in , dgst, salt);
  }
}

void hashing_00666 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  thread_parameter->fake = 1;

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  if (plains[0].len) puts (ptrs[0]);
  if (plains[1].len) puts (ptrs[1]);
  if (plains[2].len) puts (ptrs[2]);
  if (plains[3].len) puts (ptrs[3]);
}

void hashing_00900 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md4_sse2_t digests;

  digest_t dgst[4];

  db_t *db = thread_parameter->db;

  md4_init_sse2 (&digests);

  md4_final_sse2_max55 (in, &digests);

  transpose_md4_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_01000 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md4_sse2_t digests;

  digest_t dgst[4];

  plain_t in_u[4];

  db_t *db = thread_parameter->db;

  plain_unicode (in, in_u);

  md4_init_sse2 (&digests);

  md4_final_sse2_max55 (in_u, &digests);

  transpose_md4_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_01100 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md4_sse2_t digests;

  digest_t dgst[4];

  plain_t in_u[4];

  plain_t plains_tmp[4];

  db_t *db = thread_parameter->db;

  plain_unicode (in, in_u);

  md4_init_sse2 (&digests);

  md4_final_sse2_max55 (in_u, &digests);

  transpose_md4_digest (&digests, dgst);

  int i;

  for (i = 0; i < 4; i++)
  {
    memcpy (plains_tmp[i].buf8, dgst[i].buf.md4, 16);

    plains_tmp[i].len = 16;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_t plains[4];

    plain_init (plains);

    md4_init_sse2 (&digests);

    md4_update_sse2_max55 (plains, plains_tmp);

    md4_update_sse2_max55 (plains, salt->salt_plain_struct);

    md4_final_sse2_max55 (plains, &digests);

    transpose_md4_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01400 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha256_sse2_t digests;

  digest_t dgst[4];

  db_t *db = thread_parameter->db;

  sha256_init_sse2 (&digests);

  sha256_final_sse2 (in, &digests);

  transpose_sha256_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_01410 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha256_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha256_init_sse2 (&digests);

    sha256_update_sse2_max55 (plains, in);

    sha256_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha256_final_sse2_max55 (plains, &digests);

    transpose_sha256_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01420 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha256_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha256_init_sse2 (&digests);

    sha256_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha256_update_sse2_max55 (plains, in);

    sha256_final_sse2_max55 (plains, &digests);

    transpose_sha256_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01430 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha256_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t in_u[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    plain_unicode (in, in_u);

    sha256_init_sse2 (&digests);

    sha256_update_sse2_max55 (plains, in_u);

    sha256_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha256_final_sse2_max55 (plains, &digests);

    transpose_sha256_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01431 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha256_sse2_t digests;

  digest_t dgst[4];

  plain_t in_u[4];

  db_t *db = thread_parameter->db;

  plain_unicode (in, in_u);

  sha256_init_sse2 (&digests);

  sha256_final_sse2 (in_u, &digests);

  transpose_sha256_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_01440 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha256_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t in_u[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    plain_unicode (in, in_u);

    sha256_init_sse2 (&digests);

    sha256_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha256_update_sse2_max55 (plains, in_u);

    sha256_final_sse2_max55 (plains, &digests);

    transpose_sha256_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01450 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad_dgst[8][4] __attribute__ ((aligned (16)));
  uint32_t opad_dgst[8][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;
  uint32_t l;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad_dgst[0][i] = SHA256M_A;
    ipad_dgst[1][i] = SHA256M_B;
    ipad_dgst[2][i] = SHA256M_C;
    ipad_dgst[3][i] = SHA256M_D;
    ipad_dgst[4][i] = SHA256M_E;
    ipad_dgst[5][i] = SHA256M_F;
    ipad_dgst[6][i] = SHA256M_G;
    ipad_dgst[7][i] = SHA256M_H;

    opad_dgst[0][i] = SHA256M_A;
    opad_dgst[1][i] = SHA256M_B;
    opad_dgst[2][i] = SHA256M_C;
    opad_dgst[3][i] = SHA256M_D;
    opad_dgst[4][i] = SHA256M_E;
    opad_dgst[5][i] = SHA256M_F;
    opad_dgst[6][i] = SHA256M_G;
    opad_dgst[7][i] = SHA256M_H;
  }

  hashcat_sha256_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
  hashcat_sha256_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    uint32_t ipad_dgst_tmp[8][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst_tmp[8][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 8; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

      memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

      ptrs_tmp[i][salt->salt_plain_len] = 0x80;

      for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->salt_plain_len) * 8;
    }

    for (i = 14; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);

    hashcat_sha256_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 8; j++)
      {
        opad_buf[j][i] = ipad_dgst_tmp[j][i];
      }

      opad_buf[ 8][i] = 0x80000000;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 32) * 8;
    }

    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

    hashcat_sha256_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 8; j++)
      {
        digests[i].buf.sha256[j] = opad_dgst_tmp[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_01460 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad_dgst[8][4] __attribute__ ((aligned (16)));
  uint32_t opad_dgst[8][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;
  uint32_t l;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 8; j++)
      {
        ipad_dgst[j][i] = salt->ipad_prehashed_buf[j];
        opad_dgst[j][i] = salt->opad_prehashed_buf[j];
      }
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], ptrs[i], plains[i].len);

      memset (ptrs_tmp[i] + plains[i].len, 0, BLOCK_SIZE - plains[i].len);

      ptrs_tmp[i][plains[i].len] = 0x80;

      for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + plains[i].len) * 8;
    }

    for (i = 14; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);

    hashcat_sha256_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 8; j++)
      {
        opad_buf[j][i] = ipad_dgst[j][i];
      }

      opad_buf[ 8][i] = 0x80000000;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 32) * 8;
    }

    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

    hashcat_sha256_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 8; j++)
      {
        digests[i].buf.sha256[j] = opad_dgst[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_01500 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  memcpy (plains_tmp, plains, sizeof (plains_tmp));

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    const uint des_salt = itoa64_to_int (salt->salt_plain_buf[0])
                        | itoa64_to_int (salt->salt_plain_buf[1]) << 6;

    plains_tmp[0].buf[2] = des_salt;
    plains_tmp[1].buf[2] = des_salt;
    plains_tmp[2].buf[2] = des_salt;
    plains_tmp[3].buf[2] = des_salt;

    descrypt_64 (plains_tmp, digests);

    /* TODO : search for buffer overflow when plains is filled */
/*    plains[0].buf[2] = plains[0].buf[3] = plains[0].buf[4] = 0;
    plains[1].buf[2] = plains[1].buf[3] = plains[1].buf[4] = 0;
    plains[2].buf[2] = plains[2].buf[3] = plains[2].buf[4] = 0;
    plains[2].buf[2] = plains[2].buf[3] = plains[3].buf[4] = 0;
*/
    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_01600 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &in[0].buf;
  ptrs[1] = (char *) &in[1].buf;
  ptrs[2] = (char *) &in[2].buf;
  ptrs[3] = (char *) &in[3].buf;

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains[0].buf;
  ptrs_tmp[1] = (char *) &plains[1].buf;
  ptrs_tmp[2] = (char *) &plains[2].buf;
  ptrs_tmp[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, in);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      if (in[i].len > 16) continue;

      plains[i].len = in[i].len + MD5APR_SIGN + salt->salt_plain_len;

      /* The password first, since that is what is most unknown */
      /* Then our magic string */
      /* Then the raw salt */
      /* Then just as many characters of the MD5(pw,salt,pw) */

      memcpy (ptrs_tmp[i], ptrs[i], in[i].len);
      memcpy (ptrs_tmp[i] + in[i].len, MD5APR_MAGIC, MD5APR_SIGN);
      memcpy (ptrs_tmp[i] + in[i].len + MD5APR_SIGN, salt->salt_plain_buf, salt->salt_plain_len);
      memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, in[i].len);

      plains[i].len += in[i].len;

      /* Then something really weird... */

      switch (in[i].len)
      {
        case 1:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          plains[i].len += 1;
          break;

        case 2:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          plains[i].len += 2;
          break;

        case 3:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          plains[i].len += 2;
          break;

        case 4:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 5:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 6:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 7:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 8:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 9:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 10:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 11:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 12:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 13:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 14:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 15:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;
      }
    }

    md5_init_sse2 (&digests);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    /* and now, just to make sure things don't run too fast */

    uint32_t j;

    for (j = 0; j < salt->iterations; j++)
    {
      int a1 = j & 1;
      int m3 = j % 3;
      int m7 = j % 7;

      for (i = 0; i < 4; i++)
      {
        if (in[i].len > 16) continue;

        memset (ptrs_tmp[i], 0, BLOCK_SIZE);

        plains[i].len = 0;

        if (a1)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }
        else
        {
          memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, 16);

          plains[i].len += 16;
        }

        if (m3)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, salt->salt_plain_buf, salt->salt_plain_len);

          plains[i].len += salt->salt_plain_len;
        }

        if (m7)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }

        if (a1)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, 16);

          plains[i].len += 16;
        }
        else
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }
      }

      md5_init_sse2 (&digests);

      md5_final_sse2_max55 (plains, &digests);

      transpose_md5_digest (&digests, dgst);
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01700 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha512_sse2_t digests;

  digest_t dgst[4];

  db_t *db = thread_parameter->db;

  sha512_init_sse2 (&digests);

  sha512_final_sse2 (in, &digests);

  transpose_sha512_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_01710 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha512_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha512_init_sse2 (&digests);

    sha512_update_sse2 (plains, &digests, in);

    sha512_update_sse2 (plains, &digests, salt->salt_plain_struct);

    sha512_final_sse2 (plains, &digests);

    transpose_sha512_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01720 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha512_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha512_init_sse2 (&digests);

    sha512_update_sse2 (plains, &digests, salt->salt_plain_struct);

    sha512_update_sse2 (plains, &digests, in);

    sha512_final_sse2 (plains, &digests);

    transpose_sha512_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01722 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha512_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha512_init_sse2 (&digests);

    sha512_update_sse2 (plains, &digests, salt->salt_plain_struct);

    sha512_update_sse2 (plains, &digests, in);

    sha512_final_sse2 (plains, &digests);

    transpose_sha512_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01730 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha512_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t in_u[4];

  plain_unicode (in, in_u);

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha512_init_sse2 (&digests);

    sha512_update_sse2 (plains, &digests, in_u);

    sha512_update_sse2 (plains, &digests, salt->salt_plain_struct);

    sha512_final_sse2 (plains, &digests);

    transpose_sha512_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01740 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha512_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t in_u[4];

  plain_unicode (in, in_u);

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha512_init_sse2 (&digests);

    sha512_update_sse2 (plains, &digests, salt->salt_plain_struct);

    sha512_update_sse2 (plains, &digests, in_u);

    sha512_final_sse2 (plains, &digests);

    transpose_sha512_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_01750 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf64;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf64;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf64;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf64;

  uint64_t ipad_dgst[8][2] __attribute__ ((aligned (16)));
  uint64_t opad_dgst[8][2] __attribute__ ((aligned (16)));

  uint64_t ipad_buf[16][2] __attribute__ ((aligned (16)));
  uint64_t opad_buf[16][2] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  /*
   * dirty workaround
   */

  uint32_t k;

  for (k = 0; k < 4; k += 2)
  {
    uint32_t i;
    uint32_t j;

    for (i = 0; i < 2; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x3636363636363636 ^ plains[i + k].buf64[j];
        opad_buf[j][i] = 0x5c5c5c5c5c5c5c5c ^ plains[i + k].buf64[j];
      }

      ipad_dgst[0][i] = SHA512M_A;
      ipad_dgst[1][i] = SHA512M_B;
      ipad_dgst[2][i] = SHA512M_C;
      ipad_dgst[3][i] = SHA512M_D;
      ipad_dgst[4][i] = SHA512M_E;
      ipad_dgst[5][i] = SHA512M_F;
      ipad_dgst[6][i] = SHA512M_G;
      ipad_dgst[7][i] = SHA512M_H;

      opad_dgst[0][i] = SHA512M_A;
      opad_dgst[1][i] = SHA512M_B;
      opad_dgst[2][i] = SHA512M_C;
      opad_dgst[3][i] = SHA512M_D;
      opad_dgst[4][i] = SHA512M_E;
      opad_dgst[5][i] = SHA512M_F;
      opad_dgst[6][i] = SHA512M_G;
      opad_dgst[7][i] = SHA512M_H;
    }

    hashcat_sha512_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
    hashcat_sha512_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

    uint32_t salts_idx;

    for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
    {
      salt_t *salt = db->salts_buf[salts_idx];

      if (salt->indexes_found == salt->indexes_cnt) continue;

      uint64_t ipad_dgst_tmp[8][2] __attribute__ ((aligned (16)));
      uint64_t opad_dgst_tmp[8][2] __attribute__ ((aligned (16)));

      for (i = 0; i < 2; i++)
      {
        for (j = 0; j < 8; j++)
        {
          ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
          opad_dgst_tmp[j][i] = opad_dgst[j][i];
        }
      }

      for (i = 0; i < 2; i++)
      {
        memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

        memset (ptrs_tmp[i] + salt->salt_plain_len, 0, 128 - salt->salt_plain_len);

        ptrs_tmp[i][salt->salt_plain_len] = 0x80;

        for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf64[j];

        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (128 + salt->salt_plain_len) * 8;

        BYTESWAP64 (ipad_buf[15][i]);
      }

      hashcat_sha512_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

      for (i = 0; i < 2; i++)
      {
        for (j = 0; j < 8; j++)
        {
          opad_buf[j][i] = ipad_dgst_tmp[j][i];
        }

        opad_buf[ 8][i] = 0x8000000000000000;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (128 + 64) * 8;
      }

      for (i = 0; i < 2; i++) for (j = 0; j < 16; j++) BYTESWAP64 (opad_buf[j][i]);

      hashcat_sha512_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

      for (i = 0; i < 2; i++)
      {
        for (j = 0; j < 8; j++)
        {
          digests[i].buf.sha512[j] = opad_dgst_tmp[j][i];
        }
      }

      thread_parameter->indb (thread_parameter, &plains[k], digests, salt);
    }
  }
}

void hashing_01760 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf64;
  ptrs[1] = (char *) &plains[1].buf64;
  ptrs[2] = (char *) &plains[2].buf64;
  ptrs[3] = (char *) &plains[3].buf64;

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf64;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf64;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf64;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf64;

  uint64_t ipad_dgst[8][2] __attribute__ ((aligned (16)));
  uint64_t opad_dgst[8][2] __attribute__ ((aligned (16)));

  uint64_t ipad_buf[16][2] __attribute__ ((aligned (16)));
  uint64_t opad_buf[16][2] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    /*
     * dirty workaround
     */

    uint32_t k;

    for (k = 0; k < 4; k += 2)
    {
      for (i = 0; i < 2; i++)
      {
        for (j = 0; j < 8; j++)
        {
          ipad_dgst[j][i] = salt->ipad_prehashed_buf64[j];
          opad_dgst[j][i] = salt->opad_prehashed_buf64[j];
        }
      }

      for (i = 0; i < 2; i++)
      {
        memcpy (ptrs_tmp[i], ptrs[i + k], plains[i + k].len);

        memset (ptrs_tmp[i] + plains[i + k].len, 0, 128 - plains[i + k].len);

        ptrs_tmp[i][plains[i + k].len] = 0x80;

        for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf64[j];

        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (128 + plains[i + k].len) * 8;

        BYTESWAP64 (ipad_buf[15][i]);
      }

      hashcat_sha512_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);

      for (i = 0; i < 2; i++)
      {
        for (j = 0; j < 8; j++)
        {
          opad_buf[j][i] = ipad_dgst[j][i];
        }

        opad_buf[ 8][i] = 0x8000000000000000;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (128 + 64) * 8;
      }

      for (i = 0; i < 2; i++) for (j = 0; j < 16; j++) BYTESWAP64 (opad_buf[j][i]);

      hashcat_sha512_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

      for (i = 0; i < 2; i++)
      {
        for (j = 0; j < 8; j++)
        {
          digests[i].buf.sha512[j] = opad_dgst[j][i];
        }
      }

      thread_parameter->indb (thread_parameter, &plains[k], digests, salt);
    }
  }
}

void hashing_01800 (thread_parameter_t *thread_parameter, plain_t *in)
{
  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    char *salt_buf = salt->salt_plain_buf;
    int   salt_len = salt->salt_plain_len;

    char *password0_buf = (char *) in[0].buf64;
    char *password1_buf = (char *) in[1].buf64;
    char *password2_buf = (char *) in[2].buf64;
    char *password3_buf = (char *) in[3].buf64;
    int   password0_len = in[0].len;
    int   password1_len = in[1].len;
    int   password2_len = in[2].len;
    int   password3_len = in[3].len;

    hc_sha512_ctx ctx0;
    hc_sha512_ctx ctx1;
    hc_sha512_ctx ctx2;
    hc_sha512_ctx ctx3;
    hc_sha512_ctx alt_ctx0;
    hc_sha512_ctx alt_ctx1;
    hc_sha512_ctx alt_ctx2;
    hc_sha512_ctx alt_ctx3;

    hc_sha512_ctx p_bytes0;
    hc_sha512_ctx p_bytes1;
    hc_sha512_ctx p_bytes2;
    hc_sha512_ctx p_bytes3;
    hc_sha512_ctx s_bytes0;
    hc_sha512_ctx s_bytes1;
    hc_sha512_ctx s_bytes2;
    hc_sha512_ctx s_bytes3;

    /* Prepare for the real work.  */
    sha512_init (&ctx0);
    sha512_init (&ctx1);
    sha512_init (&ctx2);
    sha512_init (&ctx3);

    /* Add the key string.  */
    sha512_update (&ctx0, password0_buf, password0_len);
    sha512_update (&ctx1, password1_buf, password1_len);
    sha512_update (&ctx2, password2_buf, password2_len);
    sha512_update (&ctx3, password3_buf, password3_len);

    /* The last part is the salt string.  This must be at most 16
       characters and it ends at the first `$' character (for
       compatibility with existing implementations).  */
    sha512_update (&ctx0, salt_buf, salt_len);
    sha512_update (&ctx1, salt_buf, salt_len);
    sha512_update (&ctx2, salt_buf, salt_len);
    sha512_update (&ctx3, salt_buf, salt_len);

    /* Compute alternate SHA512 sum with input KEY, SALT, and KEY.  The
       final result will be added to the first context.  */
    sha512_init (&alt_ctx0);
    sha512_init (&alt_ctx1);
    sha512_init (&alt_ctx2);
    sha512_init (&alt_ctx3);

    /* Add key.  */
    sha512_update (&alt_ctx0, password0_buf, password0_len);
    sha512_update (&alt_ctx1, password1_buf, password1_len);
    sha512_update (&alt_ctx2, password2_buf, password2_len);
    sha512_update (&alt_ctx3, password3_buf, password3_len);

    /* Add salt.  */
    sha512_update (&alt_ctx0, salt_buf, salt_len);
    sha512_update (&alt_ctx1, salt_buf, salt_len);
    sha512_update (&alt_ctx2, salt_buf, salt_len);
    sha512_update (&alt_ctx3, salt_buf, salt_len);

    /* Add key again.  */
    sha512_update (&alt_ctx0, password0_buf, password0_len);
    sha512_update (&alt_ctx1, password1_buf, password1_len);
    sha512_update (&alt_ctx2, password2_buf, password2_len);
    sha512_update (&alt_ctx3, password3_buf, password3_len);

    /* Now get result of this (64 bytes) and add it to the other context.  */
    sha512_final (&alt_ctx0);
    sha512_final (&alt_ctx1);
    sha512_final (&alt_ctx2);
    sha512_final (&alt_ctx3);

    /* Add for any character in the key one byte of the alternate sum.  */

    sha512_update (&ctx0, (char *) alt_ctx0.state, password0_len);
    sha512_update (&ctx1, (char *) alt_ctx1.state, password1_len);
    sha512_update (&ctx2, (char *) alt_ctx2.state, password2_len);
    sha512_update (&ctx3, (char *) alt_ctx3.state, password3_len);

    /* Take the binary representation of the length of the key and for every
       1 add the alternate sum, for every 0 the key.  */

    int cnt;

    for (cnt = password0_len; cnt > 0; cnt >>= 1)
    {
      if ((cnt & 1) != 0)
        sha512_update (&ctx0, (char *) alt_ctx0.state, 64);
      else
        sha512_update (&ctx0, password0_buf, password0_len);
    }

    for (cnt = password1_len; cnt > 0; cnt >>= 1)
    {
      if ((cnt & 1) != 0)
        sha512_update (&ctx1, (char *) alt_ctx1.state, 64);
      else
        sha512_update (&ctx1, password1_buf, password1_len);
    }

    for (cnt = password2_len; cnt > 0; cnt >>= 1)
    {
      if ((cnt & 1) != 0)
        sha512_update (&ctx2, (char *) alt_ctx2.state, 64);
      else
        sha512_update (&ctx2, password2_buf, password2_len);
    }

    for (cnt = password3_len; cnt > 0; cnt >>= 1)
    {
      if ((cnt & 1) != 0)
        sha512_update (&ctx3, (char *) alt_ctx3.state, 64);
      else
        sha512_update (&ctx3, password3_buf, password3_len);
    }

    /* Create intermediate result.  */
    sha512_final (&ctx0);
    sha512_final (&ctx1);
    sha512_final (&ctx2);
    sha512_final (&ctx3);

    /* Start computation of P byte sequence.  */
    sha512_init (&p_bytes0);
    sha512_init (&p_bytes1);
    sha512_init (&p_bytes2);
    sha512_init (&p_bytes3);

    /* For every character in the password add the entire password.  */
    for (cnt = 0; cnt < password0_len; cnt++)
    {
      sha512_update (&p_bytes0, password0_buf, password0_len);
    }

    for (cnt = 0; cnt < password1_len; cnt++)
    {
      sha512_update (&p_bytes1, password1_buf, password1_len);
    }

    for (cnt = 0; cnt < password2_len; cnt++)
    {
      sha512_update (&p_bytes2, password2_buf, password2_len);
    }

    for (cnt = 0; cnt < password3_len; cnt++)
    {
      sha512_update (&p_bytes3, password3_buf, password3_len);
    }

    /* Finish the state.  */
    sha512_final (&p_bytes0);
    sha512_final (&p_bytes1);
    sha512_final (&p_bytes2);
    sha512_final (&p_bytes3);

    /* Start computation of S byte sequence.  */
    sha512_init (&s_bytes0);
    sha512_init (&s_bytes1);
    sha512_init (&s_bytes2);
    sha512_init (&s_bytes3);

    /* For every character in the password add the entire password.  */
    for (cnt = 0; cnt < 16 + ((unsigned char*) ctx0.state)[0]; cnt++)
    {
      sha512_update (&s_bytes0, salt_buf, salt_len);
    }

    for (cnt = 0; cnt < 16 + ((unsigned char*) ctx1.state)[0]; cnt++)
    {
      sha512_update (&s_bytes1, salt_buf, salt_len);
    }

    for (cnt = 0; cnt < 16 + ((unsigned char*) ctx2.state)[0]; cnt++)
    {
      sha512_update (&s_bytes2, salt_buf, salt_len);
    }

    for (cnt = 0; cnt < 16 + ((unsigned char*) ctx3.state)[0]; cnt++)
    {
      sha512_update (&s_bytes3, salt_buf, salt_len);
    }

    /* Finish the state.  */
    sha512_final (&s_bytes0);
    sha512_final (&s_bytes1);
    sha512_final (&s_bytes2);
    sha512_final (&s_bytes3);

    /* sse2 specific */

    plain_t plain_alt_ctx[4];

    plain_alt_ctx[0].buf64[0] = ctx0.state[0];
    plain_alt_ctx[0].buf64[1] = ctx0.state[1];
    plain_alt_ctx[0].buf64[2] = ctx0.state[2];
    plain_alt_ctx[0].buf64[3] = ctx0.state[3];
    plain_alt_ctx[0].buf64[4] = ctx0.state[4];
    plain_alt_ctx[0].buf64[5] = ctx0.state[5];
    plain_alt_ctx[0].buf64[6] = ctx0.state[6];
    plain_alt_ctx[0].buf64[7] = ctx0.state[7];
    plain_alt_ctx[1].buf64[0] = ctx1.state[0];
    plain_alt_ctx[1].buf64[1] = ctx1.state[1];
    plain_alt_ctx[1].buf64[2] = ctx1.state[2];
    plain_alt_ctx[1].buf64[3] = ctx1.state[3];
    plain_alt_ctx[1].buf64[4] = ctx1.state[4];
    plain_alt_ctx[1].buf64[5] = ctx1.state[5];
    plain_alt_ctx[1].buf64[6] = ctx1.state[6];
    plain_alt_ctx[1].buf64[7] = ctx1.state[7];
    plain_alt_ctx[2].buf64[0] = ctx2.state[0];
    plain_alt_ctx[2].buf64[1] = ctx2.state[1];
    plain_alt_ctx[2].buf64[2] = ctx2.state[2];
    plain_alt_ctx[2].buf64[3] = ctx2.state[3];
    plain_alt_ctx[2].buf64[4] = ctx2.state[4];
    plain_alt_ctx[2].buf64[5] = ctx2.state[5];
    plain_alt_ctx[2].buf64[6] = ctx2.state[6];
    plain_alt_ctx[2].buf64[7] = ctx2.state[7];
    plain_alt_ctx[3].buf64[0] = ctx3.state[0];
    plain_alt_ctx[3].buf64[1] = ctx3.state[1];
    plain_alt_ctx[3].buf64[2] = ctx3.state[2];
    plain_alt_ctx[3].buf64[3] = ctx3.state[3];
    plain_alt_ctx[3].buf64[4] = ctx3.state[4];
    plain_alt_ctx[3].buf64[5] = ctx3.state[5];
    plain_alt_ctx[3].buf64[6] = ctx3.state[6];
    plain_alt_ctx[3].buf64[7] = ctx3.state[7];

    plain_alt_ctx[0].len = 64;
    plain_alt_ctx[1].len = 64;
    plain_alt_ctx[2].len = 64;
    plain_alt_ctx[3].len = 64;

    plain_t plain_p_bytes[4];

    plain_p_bytes[0].buf64[0] = p_bytes0.state[0];
    plain_p_bytes[0].buf64[1] = p_bytes0.state[1];
    plain_p_bytes[0].buf64[2] = p_bytes0.state[2];
    plain_p_bytes[0].buf64[3] = p_bytes0.state[3];
    plain_p_bytes[0].buf64[4] = p_bytes0.state[4];
    plain_p_bytes[0].buf64[5] = p_bytes0.state[5];
    plain_p_bytes[0].buf64[6] = p_bytes0.state[6];
    plain_p_bytes[0].buf64[7] = p_bytes0.state[7];
    plain_p_bytes[1].buf64[0] = p_bytes1.state[0];
    plain_p_bytes[1].buf64[1] = p_bytes1.state[1];
    plain_p_bytes[1].buf64[2] = p_bytes1.state[2];
    plain_p_bytes[1].buf64[3] = p_bytes1.state[3];
    plain_p_bytes[1].buf64[4] = p_bytes1.state[4];
    plain_p_bytes[1].buf64[5] = p_bytes1.state[5];
    plain_p_bytes[1].buf64[6] = p_bytes1.state[6];
    plain_p_bytes[1].buf64[7] = p_bytes1.state[7];
    plain_p_bytes[2].buf64[0] = p_bytes2.state[0];
    plain_p_bytes[2].buf64[1] = p_bytes2.state[1];
    plain_p_bytes[2].buf64[2] = p_bytes2.state[2];
    plain_p_bytes[2].buf64[3] = p_bytes2.state[3];
    plain_p_bytes[2].buf64[4] = p_bytes2.state[4];
    plain_p_bytes[2].buf64[5] = p_bytes2.state[5];
    plain_p_bytes[2].buf64[6] = p_bytes2.state[6];
    plain_p_bytes[2].buf64[7] = p_bytes2.state[7];
    plain_p_bytes[3].buf64[0] = p_bytes3.state[0];
    plain_p_bytes[3].buf64[1] = p_bytes3.state[1];
    plain_p_bytes[3].buf64[2] = p_bytes3.state[2];
    plain_p_bytes[3].buf64[3] = p_bytes3.state[3];
    plain_p_bytes[3].buf64[4] = p_bytes3.state[4];
    plain_p_bytes[3].buf64[5] = p_bytes3.state[5];
    plain_p_bytes[3].buf64[6] = p_bytes3.state[6];
    plain_p_bytes[3].buf64[7] = p_bytes3.state[7];

    plain_p_bytes[0].len = password0_len;
    plain_p_bytes[1].len = password1_len;
    plain_p_bytes[2].len = password2_len;
    plain_p_bytes[3].len = password3_len;

    plain_t plain_s_bytes[4];

    plain_s_bytes[0].buf64[0] = s_bytes0.state[0];
    plain_s_bytes[0].buf64[1] = s_bytes0.state[1];
    plain_s_bytes[0].buf64[2] = s_bytes0.state[2];
    plain_s_bytes[0].buf64[3] = s_bytes0.state[3];
    plain_s_bytes[0].buf64[4] = s_bytes0.state[4];
    plain_s_bytes[0].buf64[5] = s_bytes0.state[5];
    plain_s_bytes[0].buf64[6] = s_bytes0.state[6];
    plain_s_bytes[0].buf64[7] = s_bytes0.state[7];
    plain_s_bytes[1].buf64[0] = s_bytes1.state[0];
    plain_s_bytes[1].buf64[1] = s_bytes1.state[1];
    plain_s_bytes[1].buf64[2] = s_bytes1.state[2];
    plain_s_bytes[1].buf64[3] = s_bytes1.state[3];
    plain_s_bytes[1].buf64[4] = s_bytes1.state[4];
    plain_s_bytes[1].buf64[5] = s_bytes1.state[5];
    plain_s_bytes[1].buf64[6] = s_bytes1.state[6];
    plain_s_bytes[1].buf64[7] = s_bytes1.state[7];
    plain_s_bytes[2].buf64[0] = s_bytes2.state[0];
    plain_s_bytes[2].buf64[1] = s_bytes2.state[1];
    plain_s_bytes[2].buf64[2] = s_bytes2.state[2];
    plain_s_bytes[2].buf64[3] = s_bytes2.state[3];
    plain_s_bytes[2].buf64[4] = s_bytes2.state[4];
    plain_s_bytes[2].buf64[5] = s_bytes2.state[5];
    plain_s_bytes[2].buf64[6] = s_bytes2.state[6];
    plain_s_bytes[2].buf64[7] = s_bytes2.state[7];
    plain_s_bytes[3].buf64[0] = s_bytes3.state[0];
    plain_s_bytes[3].buf64[1] = s_bytes3.state[1];
    plain_s_bytes[3].buf64[2] = s_bytes3.state[2];
    plain_s_bytes[3].buf64[3] = s_bytes3.state[3];
    plain_s_bytes[3].buf64[4] = s_bytes3.state[4];
    plain_s_bytes[3].buf64[5] = s_bytes3.state[5];
    plain_s_bytes[3].buf64[6] = s_bytes3.state[6];
    plain_s_bytes[3].buf64[7] = s_bytes3.state[7];

    plain_s_bytes[0].len = salt_len;
    plain_s_bytes[1].len = salt_len;
    plain_s_bytes[2].len = salt_len;
    plain_s_bytes[3].len = salt_len;

    /* Repeatedly run the collected hash value through SHA512 to
       burn CPU cycles.  */

    for (cnt = 0; cnt < (int) salt->iterations; cnt++)
    {
      /* New context.  */

      digest_sha512_sse2_t sse2_ctx;

      sha512_init_sse2 (&sse2_ctx);

      plain_t sse2_plain[4];

      plain_init (sse2_plain);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha512_update_sse2 (sse2_plain, &sse2_ctx, plain_p_bytes);
      else
        sha512_update_sse2 (sse2_plain, &sse2_ctx, plain_alt_ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sha512_update_sse2 (sse2_plain, &sse2_ctx, plain_s_bytes);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sha512_update_sse2 (sse2_plain, &sse2_ctx, plain_p_bytes);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha512_update_sse2 (sse2_plain, &sse2_ctx, plain_alt_ctx);
      else
        sha512_update_sse2 (sse2_plain, &sse2_ctx, plain_p_bytes);

      /* Create intermediate [SIC] result.  */
      sha512_final_sse2 (sse2_plain, &sse2_ctx);

      plain_alt_ctx[0].buf64[0] = sse2_ctx.buf64[ 0];
      plain_alt_ctx[1].buf64[0] = sse2_ctx.buf64[ 1];
      plain_alt_ctx[2].buf64[0] = sse2_ctx.buf64[ 2];
      plain_alt_ctx[3].buf64[0] = sse2_ctx.buf64[ 3];
      plain_alt_ctx[0].buf64[1] = sse2_ctx.buf64[ 4];
      plain_alt_ctx[1].buf64[1] = sse2_ctx.buf64[ 5];
      plain_alt_ctx[2].buf64[1] = sse2_ctx.buf64[ 6];
      plain_alt_ctx[3].buf64[1] = sse2_ctx.buf64[ 7];
      plain_alt_ctx[0].buf64[2] = sse2_ctx.buf64[ 8];
      plain_alt_ctx[1].buf64[2] = sse2_ctx.buf64[ 9];
      plain_alt_ctx[2].buf64[2] = sse2_ctx.buf64[10];
      plain_alt_ctx[3].buf64[2] = sse2_ctx.buf64[11];
      plain_alt_ctx[0].buf64[3] = sse2_ctx.buf64[12];
      plain_alt_ctx[1].buf64[3] = sse2_ctx.buf64[13];
      plain_alt_ctx[2].buf64[3] = sse2_ctx.buf64[14];
      plain_alt_ctx[3].buf64[3] = sse2_ctx.buf64[15];
      plain_alt_ctx[0].buf64[4] = sse2_ctx.buf64[16];
      plain_alt_ctx[1].buf64[4] = sse2_ctx.buf64[17];
      plain_alt_ctx[2].buf64[4] = sse2_ctx.buf64[18];
      plain_alt_ctx[3].buf64[4] = sse2_ctx.buf64[19];
      plain_alt_ctx[0].buf64[5] = sse2_ctx.buf64[20];
      plain_alt_ctx[1].buf64[5] = sse2_ctx.buf64[21];
      plain_alt_ctx[2].buf64[5] = sse2_ctx.buf64[22];
      plain_alt_ctx[3].buf64[5] = sse2_ctx.buf64[23];
      plain_alt_ctx[0].buf64[6] = sse2_ctx.buf64[24];
      plain_alt_ctx[1].buf64[6] = sse2_ctx.buf64[25];
      plain_alt_ctx[2].buf64[6] = sse2_ctx.buf64[26];
      plain_alt_ctx[3].buf64[6] = sse2_ctx.buf64[27];
      plain_alt_ctx[0].buf64[7] = sse2_ctx.buf64[28];
      plain_alt_ctx[1].buf64[7] = sse2_ctx.buf64[29];
      plain_alt_ctx[2].buf64[7] = sse2_ctx.buf64[30];
      plain_alt_ctx[3].buf64[7] = sse2_ctx.buf64[31];

      BYTESWAP64 (plain_alt_ctx[0].buf64[0]);
      BYTESWAP64 (plain_alt_ctx[0].buf64[1]);
      BYTESWAP64 (plain_alt_ctx[0].buf64[2]);
      BYTESWAP64 (plain_alt_ctx[0].buf64[3]);
      BYTESWAP64 (plain_alt_ctx[0].buf64[4]);
      BYTESWAP64 (plain_alt_ctx[0].buf64[5]);
      BYTESWAP64 (plain_alt_ctx[0].buf64[6]);
      BYTESWAP64 (plain_alt_ctx[0].buf64[7]);
      BYTESWAP64 (plain_alt_ctx[1].buf64[0]);
      BYTESWAP64 (plain_alt_ctx[1].buf64[1]);
      BYTESWAP64 (plain_alt_ctx[1].buf64[2]);
      BYTESWAP64 (plain_alt_ctx[1].buf64[3]);
      BYTESWAP64 (plain_alt_ctx[1].buf64[4]);
      BYTESWAP64 (plain_alt_ctx[1].buf64[5]);
      BYTESWAP64 (plain_alt_ctx[1].buf64[6]);
      BYTESWAP64 (plain_alt_ctx[1].buf64[7]);
      BYTESWAP64 (plain_alt_ctx[2].buf64[0]);
      BYTESWAP64 (plain_alt_ctx[2].buf64[1]);
      BYTESWAP64 (plain_alt_ctx[2].buf64[2]);
      BYTESWAP64 (plain_alt_ctx[2].buf64[3]);
      BYTESWAP64 (plain_alt_ctx[2].buf64[4]);
      BYTESWAP64 (plain_alt_ctx[2].buf64[5]);
      BYTESWAP64 (plain_alt_ctx[2].buf64[6]);
      BYTESWAP64 (plain_alt_ctx[2].buf64[7]);
      BYTESWAP64 (plain_alt_ctx[3].buf64[0]);
      BYTESWAP64 (plain_alt_ctx[3].buf64[1]);
      BYTESWAP64 (plain_alt_ctx[3].buf64[2]);
      BYTESWAP64 (plain_alt_ctx[3].buf64[3]);
      BYTESWAP64 (plain_alt_ctx[3].buf64[4]);
      BYTESWAP64 (plain_alt_ctx[3].buf64[5]);
      BYTESWAP64 (plain_alt_ctx[3].buf64[6]);
      BYTESWAP64 (plain_alt_ctx[3].buf64[7]);
    }

    digest_t digest[4];

    digest[0].buf.sha512[0] = plain_alt_ctx[0].buf64[0];
    digest[0].buf.sha512[1] = plain_alt_ctx[0].buf64[1];
    digest[0].buf.sha512[2] = plain_alt_ctx[0].buf64[2];
    digest[0].buf.sha512[3] = plain_alt_ctx[0].buf64[3];
    digest[0].buf.sha512[4] = plain_alt_ctx[0].buf64[4];
    digest[0].buf.sha512[5] = plain_alt_ctx[0].buf64[5];
    digest[0].buf.sha512[6] = plain_alt_ctx[0].buf64[6];
    digest[0].buf.sha512[7] = plain_alt_ctx[0].buf64[7];
    digest[1].buf.sha512[0] = plain_alt_ctx[1].buf64[0];
    digest[1].buf.sha512[1] = plain_alt_ctx[1].buf64[1];
    digest[1].buf.sha512[2] = plain_alt_ctx[1].buf64[2];
    digest[1].buf.sha512[3] = plain_alt_ctx[1].buf64[3];
    digest[1].buf.sha512[4] = plain_alt_ctx[1].buf64[4];
    digest[1].buf.sha512[5] = plain_alt_ctx[1].buf64[5];
    digest[1].buf.sha512[6] = plain_alt_ctx[1].buf64[6];
    digest[1].buf.sha512[7] = plain_alt_ctx[1].buf64[7];
    digest[2].buf.sha512[0] = plain_alt_ctx[2].buf64[0];
    digest[2].buf.sha512[1] = plain_alt_ctx[2].buf64[1];
    digest[2].buf.sha512[2] = plain_alt_ctx[2].buf64[2];
    digest[2].buf.sha512[3] = plain_alt_ctx[2].buf64[3];
    digest[2].buf.sha512[4] = plain_alt_ctx[2].buf64[4];
    digest[2].buf.sha512[5] = plain_alt_ctx[2].buf64[5];
    digest[2].buf.sha512[6] = plain_alt_ctx[2].buf64[6];
    digest[2].buf.sha512[7] = plain_alt_ctx[2].buf64[7];
    digest[3].buf.sha512[0] = plain_alt_ctx[3].buf64[0];
    digest[3].buf.sha512[1] = plain_alt_ctx[3].buf64[1];
    digest[3].buf.sha512[2] = plain_alt_ctx[3].buf64[2];
    digest[3].buf.sha512[3] = plain_alt_ctx[3].buf64[3];
    digest[3].buf.sha512[4] = plain_alt_ctx[3].buf64[4];
    digest[3].buf.sha512[5] = plain_alt_ctx[3].buf64[5];
    digest[3].buf.sha512[6] = plain_alt_ctx[3].buf64[6];
    digest[3].buf.sha512[7] = plain_alt_ctx[3].buf64[7];

    thread_parameter->indb (thread_parameter, in, digest, salt);
  }
}

void hashing_02400 (thread_parameter_t *thread_parameter, plain_t *in)
{
  db_t *db = thread_parameter->db;

  plain_t plains_tmp[4];

  memcpy (plains_tmp, in, 4 * sizeof (plain_t));

  plains_tmp[0].len = 16;
  plains_tmp[1].len = 16;
  plains_tmp[2].len = 16;
  plains_tmp[3].len = 16;

  digest_md5_sse2_t digests;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (plains_tmp, &digests);

  digest_t dgst[4];

  transpose_md5_digest (&digests, dgst);

  dgst[0].buf.md5[0] &= 0xffffff;
  dgst[0].buf.md5[1] &= 0xffffff;
  dgst[0].buf.md5[2] &= 0xffffff;
  dgst[0].buf.md5[3] &= 0xffffff;
  dgst[1].buf.md5[0] &= 0xffffff;
  dgst[1].buf.md5[1] &= 0xffffff;
  dgst[1].buf.md5[2] &= 0xffffff;
  dgst[1].buf.md5[3] &= 0xffffff;
  dgst[2].buf.md5[0] &= 0xffffff;
  dgst[2].buf.md5[1] &= 0xffffff;
  dgst[2].buf.md5[2] &= 0xffffff;
  dgst[2].buf.md5[3] &= 0xffffff;
  dgst[3].buf.md5[0] &= 0xffffff;
  dgst[3].buf.md5[1] &= 0xffffff;
  dgst[3].buf.md5[2] &= 0xffffff;
  dgst[3].buf.md5[3] &= 0xffffff;

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_02410 (thread_parameter_t *thread_parameter, plain_t *in)
{
  db_t *db = thread_parameter->db;

  plain_t plains[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains[0].buf;
  ptrs_tmp[1] = (char *) &plains[1].buf;
  ptrs_tmp[2] = (char *) &plains[2].buf;
  ptrs_tmp[3] = (char *) &plains[3].buf;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      memset (ptrs_tmp[i], 0, 16);

      memcpy (ptrs_tmp[i], in[i].buf, in[i].len);

      // not a bug, salt_prehashed_len is the one we need to use here, truncated/max length is 4:
      memcpy (ptrs_tmp[i] + in[i].len, salt->salt_plain_buf, salt->salt_prehashed_len);

      plains[i].len = 16;
    }

    digest_md5_sse2_t digests;

    md5_init_sse2 (&digests);

    md5_final_sse2_max55 (plains, &digests);

    digest_t dgst[4];

    transpose_md5_digest (&digests, dgst);

    dgst[0].buf.md5[0] &= 0xffffff;
    dgst[0].buf.md5[1] &= 0xffffff;
    dgst[0].buf.md5[2] &= 0xffffff;
    dgst[0].buf.md5[3] &= 0xffffff;
    dgst[1].buf.md5[0] &= 0xffffff;
    dgst[1].buf.md5[1] &= 0xffffff;
    dgst[1].buf.md5[2] &= 0xffffff;
    dgst[1].buf.md5[3] &= 0xffffff;
    dgst[2].buf.md5[0] &= 0xffffff;
    dgst[2].buf.md5[1] &= 0xffffff;
    dgst[2].buf.md5[2] &= 0xffffff;
    dgst[2].buf.md5[3] &= 0xffffff;
    dgst[3].buf.md5[0] &= 0xffffff;
    dgst[3].buf.md5[1] &= 0xffffff;
    dgst[3].buf.md5[2] &= 0xffffff;
    dgst[3].buf.md5[3] &= 0xffffff;

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_02500 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad[5][4] __attribute__ ((aligned (16)));
  uint32_t opad[5][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;
  uint32_t l;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad[0][i] = SHA1M_A;
    ipad[1][i] = SHA1M_B;
    ipad[2][i] = SHA1M_C;
    ipad[3][i] = SHA1M_D;
    ipad[4][i] = SHA1M_E;

    opad[0][i] = SHA1M_A;
    opad[1][i] = SHA1M_B;
    opad[2][i] = SHA1M_C;
    opad[3][i] = SHA1M_D;
    opad[4][i] = SHA1M_E;
  }

  hashcat_sha1_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
  hashcat_sha1_64 ((__m128i *) opad, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    /**
     * init hmac0
     */

    uint32_t tmp0[5][4] __attribute__ ((aligned (16)));
    uint32_t out0[5][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      tmp0[0][i] = ipad[0][i];
      tmp0[1][i] = ipad[1][i];
      tmp0[2][i] = ipad[2][i];
      tmp0[3][i] = ipad[3][i];
      tmp0[4][i] = ipad[4][i];
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

      memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

      ptrs_tmp[i][salt->salt_plain_len + 3] = 0x01;
      ptrs_tmp[i][salt->salt_plain_len + 4] = 0x80;

      for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->salt_plain_len + 4) * 8;

      BYTESWAP (ipad_buf[15][i]);
    }

    hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      opad_buf[ 0][i] = tmp0[0][i];
      opad_buf[ 1][i] = tmp0[1][i];
      opad_buf[ 2][i] = tmp0[2][i];
      opad_buf[ 3][i] = tmp0[3][i];
      opad_buf[ 4][i] = tmp0[4][i];
      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 4; i++)
    {
      tmp0[0][i] = opad[0][i];
      tmp0[1][i] = opad[1][i];
      tmp0[2][i] = opad[2][i];
      tmp0[3][i] = opad[3][i];
      tmp0[4][i] = opad[4][i];
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      out0[0][i] = tmp0[0][i];
      out0[1][i] = tmp0[1][i];
      out0[2][i] = tmp0[2][i];
      out0[3][i] = tmp0[3][i];
      out0[4][i] = tmp0[4][i];
    }

    /**
     * init hmac1
     */

    uint32_t tmp1[5][4] __attribute__ ((aligned (16)));
    uint32_t out1[5][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      tmp1[0][i] = ipad[0][i];
      tmp1[1][i] = ipad[1][i];
      tmp1[2][i] = ipad[2][i];
      tmp1[3][i] = ipad[3][i];
      tmp1[4][i] = ipad[4][i];
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

      memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

      ptrs_tmp[i][salt->salt_plain_len + 3] = 0x02;
      ptrs_tmp[i][salt->salt_plain_len + 4] = 0x80;

      for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->salt_plain_len + 4) * 8;

      BYTESWAP (ipad_buf[15][i]);
    }

    hashcat_sha1_64 ((__m128i *) tmp1, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      opad_buf[ 0][i] = tmp1[0][i];
      opad_buf[ 1][i] = tmp1[1][i];
      opad_buf[ 2][i] = tmp1[2][i];
      opad_buf[ 3][i] = tmp1[3][i];
      opad_buf[ 4][i] = tmp1[4][i];
      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 4; i++)
    {
      tmp1[0][i] = opad[0][i];
      tmp1[1][i] = opad[1][i];
      tmp1[2][i] = opad[2][i];
      tmp1[3][i] = opad[3][i];
      tmp1[4][i] = opad[4][i];
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) tmp1, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      out1[0][i] = tmp1[0][i];
      out1[1][i] = tmp1[1][i];
      out1[2][i] = tmp1[2][i];
      out1[3][i] = tmp1[3][i];
      out1[4][i] = tmp1[4][i];
    }

    /**
     * loop hmac0
     */

    for (j = 0; j < 4096 - 1; j++)
    {
      for (i = 0; i < 4; i++)
      {
        ipad_buf[ 0][i] = tmp0[0][i];
        ipad_buf[ 1][i] = tmp0[1][i];
        ipad_buf[ 2][i] = tmp0[2][i];
        ipad_buf[ 3][i] = tmp0[3][i];
        ipad_buf[ 4][i] = tmp0[4][i];
        ipad_buf[ 5][i] = 0x80000000;
        ipad_buf[ 6][i] = 0;
        ipad_buf[ 7][i] = 0;
        ipad_buf[ 8][i] = 0;
        ipad_buf[ 9][i] = 0;
        ipad_buf[10][i] = 0;
        ipad_buf[11][i] = 0;
        ipad_buf[12][i] = 0;
        ipad_buf[13][i] = 0;
        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (64 + 20) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp0[0][i] = ipad[0][i];
        tmp0[1][i] = ipad[1][i];
        tmp0[2][i] = ipad[2][i];
        tmp0[3][i] = ipad[3][i];
        tmp0[4][i] = ipad[4][i];
      }

      for (i = 0; i < 4; i++) for (l = 0; l < 16; l++) BYTESWAP (ipad_buf[l][i]);

      hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) ipad_buf);

      for (i = 0; i < 4; i++)
      {
        opad_buf[ 0][i] = tmp0[0][i];
        opad_buf[ 1][i] = tmp0[1][i];
        opad_buf[ 2][i] = tmp0[2][i];
        opad_buf[ 3][i] = tmp0[3][i];
        opad_buf[ 4][i] = tmp0[4][i];
        opad_buf[ 5][i] = 0x80000000;
        opad_buf[ 6][i] = 0;
        opad_buf[ 7][i] = 0;
        opad_buf[ 8][i] = 0;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (64 + 20) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp0[0][i] = opad[0][i];
        tmp0[1][i] = opad[1][i];
        tmp0[2][i] = opad[2][i];
        tmp0[3][i] = opad[3][i];
        tmp0[4][i] = opad[4][i];
      }

      for (i = 0; i < 4; i++) for (l = 0; l < 16; l++) BYTESWAP (opad_buf[l][i]);

      hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) opad_buf);

      for (i = 0; i < 4; i++)
      {
        out0[0][i] ^= tmp0[0][i];
        out0[1][i] ^= tmp0[1][i];
        out0[2][i] ^= tmp0[2][i];
        out0[3][i] ^= tmp0[3][i];
        out0[4][i] ^= tmp0[4][i];
      }
    }

    /**
     * loop hmac1
     */

    for (j = 0; j < 4096 - 1; j++)
    {
      for (i = 0; i < 4; i++)
      {
        ipad_buf[ 0][i] = tmp1[0][i];
        ipad_buf[ 1][i] = tmp1[1][i];
        ipad_buf[ 2][i] = tmp1[2][i];
        ipad_buf[ 3][i] = tmp1[3][i];
        ipad_buf[ 4][i] = tmp1[4][i];
        ipad_buf[ 5][i] = 0x80000000;
        ipad_buf[ 6][i] = 0;
        ipad_buf[ 7][i] = 0;
        ipad_buf[ 8][i] = 0;
        ipad_buf[ 9][i] = 0;
        ipad_buf[10][i] = 0;
        ipad_buf[11][i] = 0;
        ipad_buf[12][i] = 0;
        ipad_buf[13][i] = 0;
        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (64 + 20) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp1[0][i] = ipad[0][i];
        tmp1[1][i] = ipad[1][i];
        tmp1[2][i] = ipad[2][i];
        tmp1[3][i] = ipad[3][i];
        tmp1[4][i] = ipad[4][i];
      }

      for (i = 0; i < 4; i++) for (l = 0; l < 16; l++) BYTESWAP (ipad_buf[l][i]);

      hashcat_sha1_64 ((__m128i *) tmp1, (__m128i *) ipad_buf);

      for (i = 0; i < 4; i++)
      {
        opad_buf[ 0][i] = tmp1[0][i];
        opad_buf[ 1][i] = tmp1[1][i];
        opad_buf[ 2][i] = tmp1[2][i];
        opad_buf[ 3][i] = tmp1[3][i];
        opad_buf[ 4][i] = tmp1[4][i];
        opad_buf[ 5][i] = 0x80000000;
        opad_buf[ 6][i] = 0;
        opad_buf[ 7][i] = 0;
        opad_buf[ 8][i] = 0;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (64 + 20) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp1[0][i] = opad[0][i];
        tmp1[1][i] = opad[1][i];
        tmp1[2][i] = opad[2][i];
        tmp1[3][i] = opad[3][i];
        tmp1[4][i] = opad[4][i];
      }

      for (i = 0; i < 4; i++) for (l = 0; l < 16; l++) BYTESWAP (opad_buf[l][i]);

      hashcat_sha1_64 ((__m128i *) tmp1, (__m128i *) opad_buf);

      for (i = 0; i < 4; i++)
      {
        out1[0][i] ^= tmp1[0][i];
        out1[1][i] ^= tmp1[1][i];
        out1[2][i] ^= tmp1[2][i];
        out1[3][i] ^= tmp1[3][i];
        out1[4][i] ^= tmp1[4][i];
      }
    }

    /**
     * finalize
     */

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x36363636;
        opad_buf[j][i] = 0x5c5c5c5c;
      }

      ipad_buf[0][i] ^= out0[0][i];
      ipad_buf[1][i] ^= out0[1][i];
      ipad_buf[2][i] ^= out0[2][i];
      ipad_buf[3][i] ^= out0[3][i];
      ipad_buf[4][i] ^= out0[4][i];
      ipad_buf[5][i] ^= out1[0][i];
      ipad_buf[6][i] ^= out1[1][i];
      ipad_buf[7][i] ^= out1[2][i];

      opad_buf[0][i] ^= out0[0][i];
      opad_buf[1][i] ^= out0[1][i];
      opad_buf[2][i] ^= out0[2][i];
      opad_buf[3][i] ^= out0[3][i];
      opad_buf[4][i] ^= out0[4][i];
      opad_buf[5][i] ^= out1[0][i];
      opad_buf[6][i] ^= out1[1][i];
      opad_buf[7][i] ^= out1[2][i];

      ipad[0][i] = SHA1M_A;
      ipad[1][i] = SHA1M_B;
      ipad[2][i] = SHA1M_C;
      ipad[3][i] = SHA1M_D;
      ipad[4][i] = SHA1M_E;

      opad[0][i] = SHA1M_A;
      opad[1][i] = SHA1M_B;
      opad[2][i] = SHA1M_C;
      opad[3][i] = SHA1M_D;
      opad[4][i] = SHA1M_E;
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (ipad_buf[j][i]);
    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
    hashcat_sha1_64 ((__m128i *) opad, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      tmp0[0][i] = ipad[0][i];
      tmp0[1][i] = ipad[1][i];
      tmp0[2][i] = ipad[2][i];
      tmp0[3][i] = ipad[3][i];
      tmp0[4][i] = ipad[4][i];
    }

    for (i = 0; i < 4; i++)
    {
      ipad_buf[ 0][i] = salt->wpa->pke[ 0];
      ipad_buf[ 1][i] = salt->wpa->pke[ 1];
      ipad_buf[ 2][i] = salt->wpa->pke[ 2];
      ipad_buf[ 3][i] = salt->wpa->pke[ 3];
      ipad_buf[ 4][i] = salt->wpa->pke[ 4];
      ipad_buf[ 5][i] = salt->wpa->pke[ 5];
      ipad_buf[ 6][i] = salt->wpa->pke[ 6];
      ipad_buf[ 7][i] = salt->wpa->pke[ 7];
      ipad_buf[ 8][i] = salt->wpa->pke[ 8];
      ipad_buf[ 9][i] = salt->wpa->pke[ 9];
      ipad_buf[10][i] = salt->wpa->pke[10];
      ipad_buf[11][i] = salt->wpa->pke[11];
      ipad_buf[12][i] = salt->wpa->pke[12];
      ipad_buf[13][i] = salt->wpa->pke[13];
      ipad_buf[14][i] = salt->wpa->pke[14];
      ipad_buf[15][i] = salt->wpa->pke[15];
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (ipad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      ipad_buf[ 0][i] = salt->wpa->pke[16];
      ipad_buf[ 1][i] = salt->wpa->pke[17];
      ipad_buf[ 2][i] = salt->wpa->pke[18];
      ipad_buf[ 3][i] = salt->wpa->pke[19];
      ipad_buf[ 4][i] = salt->wpa->pke[20];
      ipad_buf[ 5][i] = salt->wpa->pke[21];
      ipad_buf[ 6][i] = salt->wpa->pke[22];
      ipad_buf[ 7][i] = salt->wpa->pke[23];
      ipad_buf[ 8][i] = salt->wpa->pke[24];
      ipad_buf[ 9][i] = 0x80000000;
      ipad_buf[10][i] = 0;
      ipad_buf[11][i] = 0;
      ipad_buf[12][i] = 0;
      ipad_buf[13][i] = 0;
      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + 100) * 8;
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (ipad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      opad_buf[ 0][i] = tmp0[0][i];
      opad_buf[ 1][i] = tmp0[1][i];
      opad_buf[ 2][i] = tmp0[2][i];
      opad_buf[ 3][i] = tmp0[3][i];
      opad_buf[ 4][i] = tmp0[4][i];
      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 4; i++)
    {
      tmp0[0][i] = opad[0][i];
      tmp0[1][i] = opad[1][i];
      tmp0[2][i] = opad[2][i];
      tmp0[3][i] = opad[3][i];
      tmp0[4][i] = opad[4][i];
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) opad_buf);

    if (salt->wpa->keyver == 1)
    {
      /**
       * md5
       */

      for (i = 0; i < 4; i++)
      {
        BYTESWAP (tmp0[0][i]);
        BYTESWAP (tmp0[1][i]);
        BYTESWAP (tmp0[2][i]);
        BYTESWAP (tmp0[3][i]);
      }

      for (i = 0; i < 4; i++)
      {
        for (j = 0; j < 16; j++)
        {
          ipad_buf[j][i] = 0x36363636;
          opad_buf[j][i] = 0x5c5c5c5c;
        }

        ipad_buf[0][i] ^= tmp0[0][i];
        ipad_buf[1][i] ^= tmp0[1][i];
        ipad_buf[2][i] ^= tmp0[2][i];
        ipad_buf[3][i] ^= tmp0[3][i];

        opad_buf[0][i] ^= tmp0[0][i];
        opad_buf[1][i] ^= tmp0[1][i];
        opad_buf[2][i] ^= tmp0[2][i];
        opad_buf[3][i] ^= tmp0[3][i];

        ipad[0][i] = MD5M_A;
        ipad[1][i] = MD5M_B;
        ipad[2][i] = MD5M_C;
        ipad[3][i] = MD5M_D;

        opad[0][i] = MD5M_A;
        opad[1][i] = MD5M_B;
        opad[2][i] = MD5M_C;
        opad[3][i] = MD5M_D;
      }

      hashcat_md5_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
      hashcat_md5_64 ((__m128i *) opad, (__m128i *) opad_buf);

      for (i = 0; i < 4; i++)
      {
        tmp0[0][i] = ipad[0][i];
        tmp0[1][i] = ipad[1][i];
        tmp0[2][i] = ipad[2][i];
        tmp0[3][i] = ipad[3][i];
      }

      int eapol_size = salt->wpa->eapol_size;

      int eapol_left;
      int eapol_off;

      for (eapol_left = eapol_size, eapol_off = 0; eapol_left >= 56; eapol_left -= 64, eapol_off += 16)
      {
        for (i = 0; i < 4; i++)
        {
          ipad_buf[ 0][i] = salt->wpa->eapol[eapol_off +  0];
          ipad_buf[ 1][i] = salt->wpa->eapol[eapol_off +  1];
          ipad_buf[ 2][i] = salt->wpa->eapol[eapol_off +  2];
          ipad_buf[ 3][i] = salt->wpa->eapol[eapol_off +  3];
          ipad_buf[ 4][i] = salt->wpa->eapol[eapol_off +  4];
          ipad_buf[ 5][i] = salt->wpa->eapol[eapol_off +  5];
          ipad_buf[ 6][i] = salt->wpa->eapol[eapol_off +  6];
          ipad_buf[ 7][i] = salt->wpa->eapol[eapol_off +  7];
          ipad_buf[ 8][i] = salt->wpa->eapol[eapol_off +  8];
          ipad_buf[ 9][i] = salt->wpa->eapol[eapol_off +  9];
          ipad_buf[10][i] = salt->wpa->eapol[eapol_off + 10];
          ipad_buf[11][i] = salt->wpa->eapol[eapol_off + 11];
          ipad_buf[12][i] = salt->wpa->eapol[eapol_off + 12];
          ipad_buf[13][i] = salt->wpa->eapol[eapol_off + 13];
          ipad_buf[14][i] = salt->wpa->eapol[eapol_off + 14];
          ipad_buf[15][i] = salt->wpa->eapol[eapol_off + 15];
        }

        hashcat_md5_64 ((__m128i *) tmp0, (__m128i *) ipad_buf);
      }

      for (i = 0; i < 4; i++)
      {
        ipad_buf[ 0][i] = salt->wpa->eapol[eapol_off +  0];
        ipad_buf[ 1][i] = salt->wpa->eapol[eapol_off +  1];
        ipad_buf[ 2][i] = salt->wpa->eapol[eapol_off +  2];
        ipad_buf[ 3][i] = salt->wpa->eapol[eapol_off +  3];
        ipad_buf[ 4][i] = salt->wpa->eapol[eapol_off +  4];
        ipad_buf[ 5][i] = salt->wpa->eapol[eapol_off +  5];
        ipad_buf[ 6][i] = salt->wpa->eapol[eapol_off +  6];
        ipad_buf[ 7][i] = salt->wpa->eapol[eapol_off +  7];
        ipad_buf[ 8][i] = salt->wpa->eapol[eapol_off +  8];
        ipad_buf[ 9][i] = salt->wpa->eapol[eapol_off +  9];
        ipad_buf[10][i] = salt->wpa->eapol[eapol_off + 10];
        ipad_buf[11][i] = salt->wpa->eapol[eapol_off + 11];
        ipad_buf[12][i] = salt->wpa->eapol[eapol_off + 12];
        ipad_buf[13][i] = salt->wpa->eapol[eapol_off + 13];
        ipad_buf[14][i] = (64 + eapol_size) * 8;
        ipad_buf[15][i] = 0;
      }

      hashcat_md5_64 ((__m128i *) tmp0, (__m128i *) ipad_buf);

      for (i = 0; i < 4; i++)
      {
        opad_buf[ 0][i] = tmp0[0][i];
        opad_buf[ 1][i] = tmp0[1][i];
        opad_buf[ 2][i] = tmp0[2][i];
        opad_buf[ 3][i] = tmp0[3][i];
        opad_buf[ 4][i] = 0x80;
        opad_buf[ 5][i] = 0;
        opad_buf[ 6][i] = 0;
        opad_buf[ 7][i] = 0;
        opad_buf[ 8][i] = 0;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = (64 + 16) * 8;
        opad_buf[15][i] = 0;
      }

      for (i = 0; i < 4; i++)
      {
        tmp0[0][i] = opad[0][i];
        tmp0[1][i] = opad[1][i];
        tmp0[2][i] = opad[2][i];
        tmp0[3][i] = opad[3][i];
      }

      hashcat_md5_64 ((__m128i *) tmp0, (__m128i *) opad_buf);
    }
    else
    {
      /**
       * sha1
       */

      for (i = 0; i < 4; i++)
      {
        for (j = 0; j < 16; j++)
        {
          ipad_buf[j][i] = 0x36363636;
          opad_buf[j][i] = 0x5c5c5c5c;
        }

        ipad_buf[0][i] ^= tmp0[0][i];
        ipad_buf[1][i] ^= tmp0[1][i];
        ipad_buf[2][i] ^= tmp0[2][i];
        ipad_buf[3][i] ^= tmp0[3][i];

        opad_buf[0][i] ^= tmp0[0][i];
        opad_buf[1][i] ^= tmp0[1][i];
        opad_buf[2][i] ^= tmp0[2][i];
        opad_buf[3][i] ^= tmp0[3][i];

        ipad[0][i] = SHA1M_A;
        ipad[1][i] = SHA1M_B;
        ipad[2][i] = SHA1M_C;
        ipad[3][i] = SHA1M_D;
        ipad[4][i] = SHA1M_E;

        opad[0][i] = SHA1M_A;
        opad[1][i] = SHA1M_B;
        opad[2][i] = SHA1M_C;
        opad[3][i] = SHA1M_D;
        opad[4][i] = SHA1M_E;
      }

      for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (ipad_buf[j][i]);
      for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

      hashcat_sha1_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
      hashcat_sha1_64 ((__m128i *) opad, (__m128i *) opad_buf);

      for (i = 0; i < 4; i++)
      {
        tmp0[0][i] = ipad[0][i];
        tmp0[1][i] = ipad[1][i];
        tmp0[2][i] = ipad[2][i];
        tmp0[3][i] = ipad[3][i];
        tmp0[4][i] = ipad[4][i];
      }

      int eapol_size = salt->wpa->eapol_size;

      int eapol_left;
      int eapol_off;

      for (eapol_left = eapol_size, eapol_off = 0; eapol_left >= 56; eapol_left -= 64, eapol_off += 16)
      {
        for (i = 0; i < 4; i++)
        {
          ipad_buf[ 0][i] = salt->wpa->eapol[eapol_off +  0];
          ipad_buf[ 1][i] = salt->wpa->eapol[eapol_off +  1];
          ipad_buf[ 2][i] = salt->wpa->eapol[eapol_off +  2];
          ipad_buf[ 3][i] = salt->wpa->eapol[eapol_off +  3];
          ipad_buf[ 4][i] = salt->wpa->eapol[eapol_off +  4];
          ipad_buf[ 5][i] = salt->wpa->eapol[eapol_off +  5];
          ipad_buf[ 6][i] = salt->wpa->eapol[eapol_off +  6];
          ipad_buf[ 7][i] = salt->wpa->eapol[eapol_off +  7];
          ipad_buf[ 8][i] = salt->wpa->eapol[eapol_off +  8];
          ipad_buf[ 9][i] = salt->wpa->eapol[eapol_off +  9];
          ipad_buf[10][i] = salt->wpa->eapol[eapol_off + 10];
          ipad_buf[11][i] = salt->wpa->eapol[eapol_off + 11];
          ipad_buf[12][i] = salt->wpa->eapol[eapol_off + 12];
          ipad_buf[13][i] = salt->wpa->eapol[eapol_off + 13];
          ipad_buf[14][i] = salt->wpa->eapol[eapol_off + 14];
          ipad_buf[15][i] = salt->wpa->eapol[eapol_off + 15];
        }

        for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (ipad_buf[j][i]);

        hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) ipad_buf);
      }

      for (i = 0; i < 4; i++)
      {
        ipad_buf[ 0][i] = salt->wpa->eapol[eapol_off +  0];
        ipad_buf[ 1][i] = salt->wpa->eapol[eapol_off +  1];
        ipad_buf[ 2][i] = salt->wpa->eapol[eapol_off +  2];
        ipad_buf[ 3][i] = salt->wpa->eapol[eapol_off +  3];
        ipad_buf[ 4][i] = salt->wpa->eapol[eapol_off +  4];
        ipad_buf[ 5][i] = salt->wpa->eapol[eapol_off +  5];
        ipad_buf[ 6][i] = salt->wpa->eapol[eapol_off +  6];
        ipad_buf[ 7][i] = salt->wpa->eapol[eapol_off +  7];
        ipad_buf[ 8][i] = salt->wpa->eapol[eapol_off +  8];
        ipad_buf[ 9][i] = salt->wpa->eapol[eapol_off +  9];
        ipad_buf[10][i] = salt->wpa->eapol[eapol_off + 10];
        ipad_buf[11][i] = salt->wpa->eapol[eapol_off + 11];
        ipad_buf[12][i] = salt->wpa->eapol[eapol_off + 12];
        ipad_buf[13][i] = salt->wpa->eapol[eapol_off + 13];
        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (64 + eapol_size) * 8;
      }

      for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (ipad_buf[j][i]);

      hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) ipad_buf);

      for (i = 0; i < 4; i++)
      {
        opad_buf[ 0][i] = tmp0[0][i];
        opad_buf[ 1][i] = tmp0[1][i];
        opad_buf[ 2][i] = tmp0[2][i];
        opad_buf[ 3][i] = tmp0[3][i];
        opad_buf[ 4][i] = tmp0[4][i];
        opad_buf[ 5][i] = 0x80000000;
        opad_buf[ 6][i] = 0;
        opad_buf[ 7][i] = 0;
        opad_buf[ 8][i] = 0;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (64 + 20) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp0[0][i] = opad[0][i];
        tmp0[1][i] = opad[1][i];
        tmp0[2][i] = opad[2][i];
        tmp0[3][i] = opad[3][i];
        tmp0[4][i] = opad[4][i];
      }

      for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

      hashcat_sha1_64 ((__m128i *) tmp0, (__m128i *) opad_buf);
    }

    for (i = 0; i < 4; i++)
    {
      digests[i].buf.md5[0] = tmp0[0][i];
      digests[i].buf.md5[1] = tmp0[1][i];
      digests[i].buf.md5[2] = tmp0[2][i];
      digests[i].buf.md5[3] = tmp0[3][i];
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_02600 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains[0].buf;
  ptrs_tmp[1] = (char *) &plains[1].buf;
  ptrs_tmp[2] = (char *) &plains[2].buf;
  ptrs_tmp[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs_tmp[i][0]);
    uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs_tmp[i][8]);
    uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs_tmp[i][16]);
    uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs_tmp[i][24]);

    plains[i].len = 32;
  }

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (plains, &digests);

  transpose_md5_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_02611 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains[0].buf;
  ptrs_tmp[1] = (char *) &plains[1].buf;
  ptrs_tmp[2] = (char *) &plains[2].buf;
  ptrs_tmp[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs_tmp[i][0]);
    uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs_tmp[i][8]);
    uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs_tmp[i][16]);
    uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs_tmp[i][24]);
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    for (i = 0; i < 4; i++)
    {
      plains[i].len = 32 + salt->salt_plain_len;

      memcpy (ptrs_tmp[i] + 32, salt->salt_plain_buf, salt->salt_plain_len);
    }

    md5_init_sse2 (&digests);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_02711 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs_tmp[i][0]);
    uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs_tmp[i][8]);
    uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs_tmp[i][16]);
    uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs_tmp[i][24]);

    plains_tmp[i].len = 32;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2 (plains, &digests, plains_tmp);

    md5_update_sse2 (plains, &digests, salt->salt_plain_struct);

    md5_final_sse2 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_02811 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], ptrs_tmp[i] +  0);
    uint_to_hex_lower (dgst[i].buf.md5[1], ptrs_tmp[i] +  8);
    uint_to_hex_lower (dgst[i].buf.md5[2], ptrs_tmp[i] + 16);
    uint_to_hex_lower (dgst[i].buf.md5[3], ptrs_tmp[i] + 24);

    plains_tmp[i].len = 32;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2 (plains, &digests, salt->salt_plain_struct);

    md5_update_sse2 (plains, &digests, plains_tmp);

    md5_final_sse2 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

int md5bit (uint8_t *digest, int bit_num)
{
  int byte_off;
  int bit_off;

  bit_num %= 128; /* keep this bounded for convenience */
  byte_off = bit_num / 8;
  bit_off  = bit_num % 8;

  /* return the value of bit N from the digest */
  return ((digest[byte_off] & (1 << bit_off)) ? 1 : 0);
}

void hashing_03200 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_bcrypt_sse2_t digest;

  digest_t dgst[4];

  db_t *db = thread_parameter->db;

  // prepare plain for bcrypt

  plain_t bf[4];

  plain_init (bf);

  int i;

  for (i = 0; i < 4; i++)
  {
    if (in[i].len == 0) continue;

    #define BFSZ (18 * 4)

    while (bf[i].len < BFSZ)
    {
      const uint left = BFSZ - bf[i].len;

      const uint sz = MIN (in[i].len, left);

      memcpy (bf[i].buf8 + bf[i].len, in[i].buf8, sz);

      bf[i].len += sz;

      bf[i].buf8[bf[i].len] = 0;

      bf[i].len++;
    }

    int j;

    for (j = 0; j < 18; j++)
    {
      BYTESWAP (bf[i].buf[j]);
    }
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    bcrypt_64 (bf, salt->salt_plain_struct, salt->iterations, &digest);

    transpose_bcrypt_digest (&digest, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

#include "md5.h"

void hashing_03300 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains_tmp[4];

  uint8_t *ptrs_dgst[4];

  ptrs_dgst[0] = (uint8_t *) dgst[0].buf.md5;
  ptrs_dgst[1] = (uint8_t *) dgst[1].buf.md5;
  ptrs_dgst[2] = (uint8_t *) dgst[2].buf.md5;
  ptrs_dgst[3] = (uint8_t *) dgst[3].buf.md5;

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains_tmp);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains_tmp, in);

    md5_update_sse2_max55 (plains_tmp, salt->salt_plain_struct);

    md5_final_sse2_max55 (plains_tmp, &digests);

    transpose_md5_digest (&digests, dgst);

    /*
     * now to delay high-speed md5 implementations that have stuff
     * like code inlining, loops unrolled and table lookup
     */

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      /* the xor a coin-toss section makes vector datatypes impossible :( */

      uint W[16 + 1 + 1];

      char *W_ptr = (char *) W;

      int round;

      for (round = 0; round < (int) salt->iterations; round++)
      {
        int shift_a = md5bit (ptrs_dgst[i], round +  0);
        int shift_b = md5bit (ptrs_dgst[i], round + 64);

        /* populate the shift schedules for use later */

        int shift_4[16];  /* shift schedule, vals 0..4 */
        int shift_7[16];  /* shift schedule, vals 0..1 */

        int k;

        for (k = 0; k < 16; k++)
        {
          int s7shift = ptrs_dgst[i][k] % 8;

          /* offset 3 -> occasionally span more than 1 int32 fetch */

          int l = (k + 3) % 16;

          shift_4[k] = ptrs_dgst[i][l] % 5;

          shift_7[k] = (ptrs_dgst[i][l] >> s7shift) & 1;
        }

        /* populate indirect_4 with 4bit values extracted from digest */

        int indirect_4[16]; /* extracted array of 4bit values */

        for (k = 0; k < 16; k++)
        {
          /* shift the digest byte and extract four bits */

          indirect_4[k] = (ptrs_dgst[i][k] >> shift_4[k]) & 0xf;
        }

        /*
         * populate indirect_7 with 7bit values from digest
         * indexed via indirect_4
         */

        int indirect_7[16]; /* extracted array of 7bit values */

        for (k = 0; k < 16; k++)
        {
          /* shift the digest byte and extract seven bits */

          indirect_7[k] = (ptrs_dgst[i][indirect_4[k]] >> shift_7[k]) & 0x7f;
        }

        /*
         * use the 7bit values to indirect into digest,
         * and create two 8bit values from the results.
         */

        int indirect_a = 0;
        int indirect_b = 0;

        for (k = 0; k < 8; k++)
        {
          indirect_a |= md5bit (ptrs_dgst[i], indirect_7[k + 0]) << k;
          indirect_b |= md5bit (ptrs_dgst[i], indirect_7[k + 8]) << k;
        }

        /* shall we utilise the top or bottom 7 bits? */

        indirect_a = (indirect_a >> shift_a) & 0x7f;
        indirect_b = (indirect_b >> shift_b) & 0x7f;

        /* extract two data.digest bits */

        int bit_a = md5bit (ptrs_dgst[i], indirect_a);
        int bit_b = md5bit (ptrs_dgst[i], indirect_b);

        /* update with the previous digest */

        memcpy (W_ptr, ptrs_dgst[i], 16);

        uint pos = 16;

        uint total = pos;

        /* re-initialise the context */

        dgst[i].buf.md5[0] = MAGIC_A;
        dgst[i].buf.md5[1] = MAGIC_B;
        dgst[i].buf.md5[2] = MAGIC_C;
        dgst[i].buf.md5[3] = MAGIC_D;

        /* xor a coin-toss; if true, mix-in the constant phrase */

        if (bit_a ^ bit_b)
        {
          memcpy (W_ptr + 16, constant_phrase, 48);

          total += 48;

          md5_64H (W, dgst[i].buf.md5);

          uint constant_off;
          uint constant_len = sizeof (constant_phrase);

          for (constant_off = 48; constant_off < constant_len - 64; constant_off += 64)
          {
            memcpy (W_ptr, constant_phrase + constant_off, 64);

            total += 64;

            md5_64H (W, dgst[i].buf.md5);
          }

          pos = constant_len - constant_off;

          total += pos;

          memcpy (W_ptr, constant_phrase + constant_off, pos);
        }

        /* digest a decimal sprintf of the current roundcount */

        uint a_len = 0;

        uint a_buf[2] = { 0, 0 };

        uint tmp = round;

        do
        {
          uint round_div = tmp / 10;
          uint round_mod = tmp % 10;

          tmp = round_div;

          a_buf[a_len / 4] = (a_buf[a_len / 4] << 8) | (round_mod + 0x30);

          a_len++;

        } while (tmp);

        memcpy (W_ptr + pos, a_buf, a_len);

        pos += a_len;

        total += a_len;

        memset (W_ptr + pos, 0, sizeof (W) - pos);

        W_ptr[pos] = 0x80;

        if (pos >= 56)
        {
          md5_64H (W, dgst[i].buf.md5);

          W[0] = W[16];
          W[1] = W[17];

          memset (W_ptr + 8, 0, sizeof (W) - 8);
        }

        W[14] = total * 8;

        md5_64H (W, dgst[i].buf.md5);
      }
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_03500 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains[0].buf;
  ptrs_tmp[1] = (char *) &plains[1].buf;
  ptrs_tmp[2] = (char *) &plains[2].buf;
  ptrs_tmp[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs_tmp[i][0]);
    uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs_tmp[i][8]);
    uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs_tmp[i][16]);
    uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs_tmp[i][24]);

    plains[i].len = 32;
  }

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (plains, &digests);

  transpose_md5_digest (&digests, dgst);

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs_tmp[i][0]);
    uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs_tmp[i][8]);
    uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs_tmp[i][16]);
    uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs_tmp[i][24]);
  }

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (plains, &digests);

  transpose_md5_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_03610 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_03710 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs_tmp[i][0]);
    uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs_tmp[i][8]);
    uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs_tmp[i][16]);
    uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs_tmp[i][24]);

    plains_tmp[i].len = 32;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, plains_tmp);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_03720 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, in);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_03800 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_03910 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], ptrs_tmp[i] + 0);
    uint_to_hex_lower (dgst[i].buf.md5[1], ptrs_tmp[i] + 8);
    uint_to_hex_lower (dgst[i].buf.md5[2], ptrs_tmp[i] + 16);
    uint_to_hex_lower (dgst[i].buf.md5[3], ptrs_tmp[i] + 24);

    plains_tmp[i].len  = 32;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2 (plains, &digests, plains_tmp);

    md5_update_sse2 (plains, &digests, salt->salt_plain_struct);

    md5_final_sse2 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_04010 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  memset (ptrs_tmp, 0, sizeof (ptrs_tmp));

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t i;

  for (i = 0; i < 4; i++) plains_tmp[i].len = 32;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    for (i = 0; i < 4; i++)
    {
      BYTESWAP (dgst[i].buf.md5[0]);
      BYTESWAP (dgst[i].buf.md5[1]);
      BYTESWAP (dgst[i].buf.md5[2]);
      BYTESWAP (dgst[i].buf.md5[3]);

      uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs_tmp[i][0]);
      uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs_tmp[i][8]);
      uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs_tmp[i][16]);
      uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs_tmp[i][24]);
    }

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, plains_tmp);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_04110 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  memset (ptrs_tmp, 0, sizeof (ptrs_tmp));

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t i;

  for (i = 0; i < 4; i++) plains_tmp[i].len = 32;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, in);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    for (i = 0; i < 4; i++)
    {
      BYTESWAP (dgst[i].buf.md5[0]);
      BYTESWAP (dgst[i].buf.md5[1]);
      BYTESWAP (dgst[i].buf.md5[2]);
      BYTESWAP (dgst[i].buf.md5[3]);

      uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs_tmp[i][0]);
      uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs_tmp[i][8]);
      uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs_tmp[i][16]);
      uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs_tmp[i][24]);
    }

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, plains_tmp);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_04210 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t i;

  for (i = 0; i < 4; i++) {
    ptrs_tmp[i][0] = 0;

    plains_tmp[i].len = 1;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, plains_tmp);

    md5_update_sse2_max55 (plains, in);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_04300 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_upper (dgst[i].buf.md5[0], &ptrs[i][0]);
    uint_to_hex_upper (dgst[i].buf.md5[1], &ptrs[i][8]);
    uint_to_hex_upper (dgst[i].buf.md5[2], &ptrs[i][16]);
    uint_to_hex_upper (dgst[i].buf.md5[3], &ptrs[i][24]);

    plains[i].len = 32;
  }

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (plains, &digests);

  transpose_md5_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_04400 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests_sha1;

  digest_md5_sse2_t digests_md5;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  sha1_init_sse2 (&digests_sha1);

  sha1_final_sse2_max55 (in, &digests_sha1);

  transpose_sha1_digest (&digests_sha1, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    uint_to_hex_lower (dgst[i].buf.sha1[0], &ptrs[i][0]);
    uint_to_hex_lower (dgst[i].buf.sha1[1], &ptrs[i][8]);
    uint_to_hex_lower (dgst[i].buf.sha1[2], &ptrs[i][16]);
    uint_to_hex_lower (dgst[i].buf.sha1[3], &ptrs[i][24]);
    uint_to_hex_lower (dgst[i].buf.sha1[4], &ptrs[i][32]);

    plains[i].len = 40;
  }

  md5_init_sse2 (&digests_md5);

  md5_final_sse2_max55 (plains, &digests_md5);

  transpose_md5_digest (&digests_md5, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_04500 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (in, &digests);

  transpose_sha1_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    uint_to_hex_lower (dgst[i].buf.sha1[0], &ptrs[i][0]);
    uint_to_hex_lower (dgst[i].buf.sha1[1], &ptrs[i][8]);
    uint_to_hex_lower (dgst[i].buf.sha1[2], &ptrs[i][16]);
    uint_to_hex_lower (dgst[i].buf.sha1[3], &ptrs[i][24]);
    uint_to_hex_lower (dgst[i].buf.sha1[4], &ptrs[i][32]);

    plains[i].len = 40;
  }

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (plains, &digests);

  transpose_sha1_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_04600 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (in, &digests);

  transpose_sha1_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    uint_to_hex_lower (dgst[i].buf.sha1[0], &ptrs[i][0]);
    uint_to_hex_lower (dgst[i].buf.sha1[1], &ptrs[i][8]);
    uint_to_hex_lower (dgst[i].buf.sha1[2], &ptrs[i][16]);
    uint_to_hex_lower (dgst[i].buf.sha1[3], &ptrs[i][24]);
    uint_to_hex_lower (dgst[i].buf.sha1[4], &ptrs[i][32]);

    plains[i].len = 40;
  }

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (plains, &digests);

  transpose_sha1_digest (&digests, dgst);

  for (i = 0; i < 4; i++)
  {
    uint_to_hex_lower (dgst[i].buf.sha1[0], &ptrs[i][0]);
    uint_to_hex_lower (dgst[i].buf.sha1[1], &ptrs[i][8]);
    uint_to_hex_lower (dgst[i].buf.sha1[2], &ptrs[i][16]);
    uint_to_hex_lower (dgst[i].buf.sha1[3], &ptrs[i][24]);
    uint_to_hex_lower (dgst[i].buf.sha1[4], &ptrs[i][32]);

    plains[i].len = 40;
  }

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (plains, &digests);

  transpose_sha1_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_04700 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests_sha1;

  digest_md5_sse2_t digests_md5;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf;
  ptrs[1] = (char *) &plains[1].buf;
  ptrs[2] = (char *) &plains[2].buf;
  ptrs[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests_md5);

  md5_final_sse2_max55 (in, &digests_md5);

  transpose_md5_digest (&digests_md5, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.md5[0]);
    BYTESWAP (dgst[i].buf.md5[1]);
    BYTESWAP (dgst[i].buf.md5[2]);
    BYTESWAP (dgst[i].buf.md5[3]);

    uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs[i][0]);
    uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs[i][8]);
    uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs[i][16]);
    uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs[i][24]);

    plains[i].len = 32;
  }

  sha1_init_sse2 (&digests_sha1);

  sha1_final_sse2_max55 (plains, &digests_sha1);

  transpose_sha1_digest (&digests_sha1, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_04800 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t i;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    for (i = 0; i < 4; i++)
    {
      ptrs_tmp[i][0] = salt->md5chap_idbyte;

      plains_tmp[i].len = 1;
    }

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, plains_tmp);

    md5_update_sse2_max55 (plains, in);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_04900 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_update_sse2_max55 (plains, in);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_05000 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains[0].buf64;
  ptrs[1] = (char *) &plains[1].buf64;
  ptrs[2] = (char *) &plains[2].buf64;
  ptrs[3] = (char *) &plains[3].buf64;

  db_t *db = thread_parameter->db;

  uint32_t rsiz  = db->salts_buf[0]->keccak_rsiz;
  uint32_t mdlen = db->salts_buf[0]->keccak_mdlen;

  uint32_t i;
  uint32_t j;

  for (i = 0; i < 4; i++)
  {
    ptrs[i][plains[i].len] = 1;

    memset (ptrs[i] + plains[i].len + 1, 0, rsiz - (plains[i].len + 1));

    ptrs[i][rsiz - 1] |= 0x80;
  }

  keccak (plains, digests);

  for (i = 0; i < 4; i++)
  {
    for (j = mdlen / 8; j < 25; j++)
    {
      digests[i].buf.keccak[j] = 0;
    }
  }

  thread_parameter->indb (thread_parameter, plains, digests, db->salts_buf[0]);
}

void hashing_05100 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  db_t *db = thread_parameter->db;

  md5_init_sse2 (&digests);

  md5_final_sse2_max55 (in, &digests);

  transpose_md5_digest (&digests, dgst);

  uint32_t b[4];

  b[0] = dgst[0].buf.md5[1];
  b[1] = dgst[1].buf.md5[1];
  b[2] = dgst[2].buf.md5[1];
  b[3] = dgst[3].buf.md5[1];

  uint32_t c[4];

  c[0] = dgst[0].buf.md5[2];
  c[1] = dgst[1].buf.md5[2];
  c[2] = dgst[2].buf.md5[2];
  c[3] = dgst[3].buf.md5[2];

  uint32_t d[4];

  d[0] = dgst[0].buf.md5[3];
  d[1] = dgst[1].buf.md5[3];
  d[2] = dgst[2].buf.md5[3];
  d[3] = dgst[3].buf.md5[3];

  dgst[0].buf.md5[2] = 0;
  dgst[0].buf.md5[3] = 0;
  dgst[1].buf.md5[2] = 0;
  dgst[1].buf.md5[3] = 0;
  dgst[2].buf.md5[2] = 0;
  dgst[2].buf.md5[3] = 0;
  dgst[3].buf.md5[2] = 0;
  dgst[3].buf.md5[3] = 0;

  // beginning

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);

  // middle

  dgst[0].buf.md5[0] = b[0];
  dgst[0].buf.md5[1] = c[0];
  dgst[1].buf.md5[0] = b[1];
  dgst[1].buf.md5[1] = c[1];
  dgst[2].buf.md5[0] = b[2];
  dgst[2].buf.md5[1] = c[2];
  dgst[3].buf.md5[0] = b[3];
  dgst[3].buf.md5[1] = c[3];

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);

  // end

  dgst[0].buf.md5[0] = c[0];
  dgst[0].buf.md5[1] = d[0];
  dgst[1].buf.md5[0] = c[1];
  dgst[1].buf.md5[1] = d[1];
  dgst[2].buf.md5[0] = c[2];
  dgst[2].buf.md5[1] = d[2];
  dgst[3].buf.md5[0] = c[3];
  dgst[3].buf.md5[1] = d[3];

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_05200 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha256_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha256_init_sse2 (&digests);

    sha256_update_sse2_max55 (plains, in);

    sha256_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha256_final_sse2_max55 (plains, &digests);

    transpose_sha256_digest (&digests, dgst);

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      BYTESWAP (dgst[i].buf.sha256[0]);
      BYTESWAP (dgst[i].buf.sha256[1]);
      BYTESWAP (dgst[i].buf.sha256[2]);
      BYTESWAP (dgst[i].buf.sha256[3]);
      BYTESWAP (dgst[i].buf.sha256[4]);
      BYTESWAP (dgst[i].buf.sha256[5]);
      BYTESWAP (dgst[i].buf.sha256[6]);
      BYTESWAP (dgst[i].buf.sha256[7]);
    }

    uint32_t iter;

    for (iter = 0; iter < salt->iterations + 1; iter++)
    {
      for (i = 0; i < 4; i++)
      {
        plains[i].buf[ 0] = dgst[i].buf.sha256[0];
        plains[i].buf[ 1] = dgst[i].buf.sha256[1];
        plains[i].buf[ 2] = dgst[i].buf.sha256[2];
        plains[i].buf[ 3] = dgst[i].buf.sha256[3];
        plains[i].buf[ 4] = dgst[i].buf.sha256[4];
        plains[i].buf[ 5] = dgst[i].buf.sha256[5];
        plains[i].buf[ 6] = dgst[i].buf.sha256[6];
        plains[i].buf[ 7] = dgst[i].buf.sha256[7];

        plains[i].len = 32;
      }

      sha256_init_sse2 (&digests);

      sha256_final_sse2_max55 (plains, &digests);

      transpose_sha256_digest (&digests, dgst);

      for (i = 0; i < 4; i++)
      {
        BYTESWAP (dgst[i].buf.sha256[0]);
        BYTESWAP (dgst[i].buf.sha256[1]);
        BYTESWAP (dgst[i].buf.sha256[2]);
        BYTESWAP (dgst[i].buf.sha256[3]);
        BYTESWAP (dgst[i].buf.sha256[4]);
        BYTESWAP (dgst[i].buf.sha256[5]);
        BYTESWAP (dgst[i].buf.sha256[6]);
        BYTESWAP (dgst[i].buf.sha256[7]);
      }
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_05300 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    uint32_t ipad_dgst[4][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst[4][4] __attribute__ ((aligned (16)));

    uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
    uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

    uint32_t ipad_dgst_tmp[4][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst_tmp[4][4] __attribute__ ((aligned (16)));

    /**
     * NR part
     */

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
        opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
      }

      ipad_dgst[0][i] = MD5M_A;
      ipad_dgst[1][i] = MD5M_B;
      ipad_dgst[2][i] = MD5M_C;
      ipad_dgst[3][i] = MD5M_D;

      opad_dgst[0][i] = MD5M_A;
      opad_dgst[1][i] = MD5M_B;
      opad_dgst[2][i] = MD5M_C;
      opad_dgst[3][i] = MD5M_D;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
    hashcat_md5_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 14; j++)
      {
        ipad_buf[j][i] = salt->ikepsk->nr_buf[j];
      }

      ipad_buf[14][i] = (64 + salt->ikepsk->nr_len) * 8;
      ipad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        opad_buf[j][i] = ipad_dgst_tmp[j][i];
      }

      opad_buf[ 4][i] = 0x80;
      opad_buf[ 5][i] = 0;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = (64 + 16) * 8;
      opad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        digests[i].buf.md5[j] = opad_dgst_tmp[j][i];
      }
    }

    /**
     * MSG part
     */

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x36363636;
        opad_buf[j][i] = 0x5c5c5c5c;
      }

      ipad_buf[0][i] ^= digests[i].buf.md5[0];
      ipad_buf[1][i] ^= digests[i].buf.md5[1];
      ipad_buf[2][i] ^= digests[i].buf.md5[2];
      ipad_buf[3][i] ^= digests[i].buf.md5[3];

      opad_buf[0][i] ^= digests[i].buf.md5[0];
      opad_buf[1][i] ^= digests[i].buf.md5[1];
      opad_buf[2][i] ^= digests[i].buf.md5[2];
      opad_buf[3][i] ^= digests[i].buf.md5[3];

      ipad_dgst[0][i] = MD5M_A;
      ipad_dgst[1][i] = MD5M_B;
      ipad_dgst[2][i] = MD5M_C;
      ipad_dgst[3][i] = MD5M_D;

      opad_dgst[0][i] = MD5M_A;
      opad_dgst[1][i] = MD5M_B;
      opad_dgst[2][i] = MD5M_C;
      opad_dgst[3][i] = MD5M_D;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
    hashcat_md5_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    int left;
    int off;

    for (left = salt->ikepsk->msg_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      for (i = 0; i < 4; i++)
      {
        for (j = 0; j < 16; j++)
        {
          ipad_buf[j][i] = salt->ikepsk->msg_buf[off + j];
        }
      }

      hashcat_md5_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);
    }

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 14; j++)
      {
        ipad_buf[j][i] = salt->ikepsk->msg_buf[off + j];
      }

      ipad_buf[14][i] = (64 + salt->ikepsk->msg_len) * 8;
      ipad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        opad_buf[j][i] = ipad_dgst_tmp[j][i];
      }

      opad_buf[ 4][i] = 0x80;
      opad_buf[ 5][i] = 0;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = (64 + 16) * 8;
      opad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        digests[i].buf.md5[j] = opad_dgst_tmp[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_05400 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;
  uint32_t l;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    uint32_t ipad_dgst[5][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst[5][4] __attribute__ ((aligned (16)));

    uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
    uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

    uint32_t ipad_dgst_tmp[5][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst_tmp[5][4] __attribute__ ((aligned (16)));

    /**
     * NR part
     */

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
        opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
      }

      ipad_dgst[0][i] = SHA1M_A;
      ipad_dgst[1][i] = SHA1M_B;
      ipad_dgst[2][i] = SHA1M_C;
      ipad_dgst[3][i] = SHA1M_D;
      ipad_dgst[4][i] = SHA1M_E;

      opad_dgst[0][i] = SHA1M_A;
      opad_dgst[1][i] = SHA1M_B;
      opad_dgst[2][i] = SHA1M_C;
      opad_dgst[3][i] = SHA1M_D;
      opad_dgst[4][i] = SHA1M_E;
    }

    hashcat_sha1_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
    hashcat_sha1_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 14; j++) ipad_buf[j][i] = salt->ikepsk->nr_buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->ikepsk->nr_len) * 8;
    }

    for (i = 14; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);

    hashcat_sha1_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++) opad_buf[j][i] = ipad_dgst_tmp[j][i];

      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

    hashcat_sha1_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        digests[i].buf.sha1[j] = opad_dgst_tmp[j][i];
      }
    }

    /**
     * MSG part
     */

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x36363636;
        opad_buf[j][i] = 0x5c5c5c5c;

        BYTESWAP (ipad_buf[j][i]);
        BYTESWAP (opad_buf[j][i]);
      }

      ipad_buf[0][i] ^= digests[i].buf.sha1[0];
      ipad_buf[1][i] ^= digests[i].buf.sha1[1];
      ipad_buf[2][i] ^= digests[i].buf.sha1[2];
      ipad_buf[3][i] ^= digests[i].buf.sha1[3];
      ipad_buf[4][i] ^= digests[i].buf.sha1[4];

      opad_buf[0][i] ^= digests[i].buf.sha1[0];
      opad_buf[1][i] ^= digests[i].buf.sha1[1];
      opad_buf[2][i] ^= digests[i].buf.sha1[2];
      opad_buf[3][i] ^= digests[i].buf.sha1[3];
      opad_buf[4][i] ^= digests[i].buf.sha1[4];

      ipad_dgst[0][i] = SHA1M_A;
      ipad_dgst[1][i] = SHA1M_B;
      ipad_dgst[2][i] = SHA1M_C;
      ipad_dgst[3][i] = SHA1M_D;
      ipad_dgst[4][i] = SHA1M_E;

      opad_dgst[0][i] = SHA1M_A;
      opad_dgst[1][i] = SHA1M_B;
      opad_dgst[2][i] = SHA1M_C;
      opad_dgst[3][i] = SHA1M_D;
      opad_dgst[4][i] = SHA1M_E;
    }

    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);
    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

    hashcat_sha1_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
    hashcat_sha1_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    int left;
    int off;

    for (left = salt->ikepsk->msg_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      for (i = 0; i < 4; i++)
      {
        for (j = 0; j < 16; j++)
        {
          ipad_buf[j][i] = salt->ikepsk->msg_buf[off + j];
        }
      }

      hashcat_sha1_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);
    }

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 14; j++) ipad_buf[j][i] = salt->ikepsk->msg_buf[off + j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->ikepsk->msg_len) * 8;
    }

    for (i = 14; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);

    hashcat_sha1_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++) opad_buf[j][i] = ipad_dgst_tmp[j][i];

      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

    hashcat_sha1_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        digests[i].buf.sha1[j] = opad_dgst_tmp[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_05500 (thread_parameter_t *thread_parameter, plain_t *in)
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

  digest_md4_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  plain_unicode (in, plains);

  md4_init_sse2 (&digests);

  md4_final_sse2_max55 (plains, &digests);

  transpose_md4_digest (&digests, dgst);

  uint32_t i;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    for (i = 0; i < 4; i++)
    {
      if (salt->netntlmv1_pc != (dgst[i].buf.md4[3] >> 16)) continue;

      uint32_t *salt_ptr = (uint32_t *) salt->salt_plain_buf;

      uint32_t data1[2];
      uint32_t data2[2];
      uint32_t data3[2];

      data1[0] = salt_ptr[0];
      data1[1] = salt_ptr[1];
      data2[0] = salt_ptr[0];
      data2[1] = salt_ptr[1];
      data3[0] = salt_ptr[0];
      data3[1] = salt_ptr[1];

      uint8_t key_des[8];

      uint32_t Kc[16];
      uint32_t Kd[16];

      // DES ROUND 1

      uint8_t *key_md4 = (uint8_t *) dgst[i].buf.md4;

      transform_netntlmv1_key (key_md4 + 0, key_des);

      _des_keysetup ((uint32_t *) key_des, Kc, Kd, c_skb);

      _des_encrypt (data1, Kc, Kd, c_SPtrans);

      // DES ROUND 2

      transform_netntlmv1_key (key_md4 + 7, key_des);

      _des_keysetup ((uint32_t *) key_des, Kc, Kd, c_skb);

      _des_encrypt (data2, Kc, Kd, c_SPtrans);

      // DES ROUND 3

      //transform_netntlmv1_key (key_md4 + 14, key_des);

      //_des_keysetup ((uint32_t *) key_des, Kc, Kd, c_skb);

      //_des_encrypt (data3, Kc, Kd, c_SPtrans);

      memcpy (data3, salt->salt_prehashed_buf, 8);

      // STORE

      dgst[i].buf.md4[0] = data1[0];
      dgst[i].buf.md4[1] = data1[1];
      dgst[i].buf.md4[2] = data2[0];
      dgst[i].buf.md4[3] = data2[1];
      dgst[i].buf.md4[4] = data3[0];
      dgst[i].buf.md4[5] = data3[1];
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_05600 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md4_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  uint32_t ipad_dgst[4][4] __attribute__ ((aligned (16)));
  uint32_t opad_dgst[4][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  // unicode password (ntlm)

  plain_unicode (in, plains);

  md4_init_sse2 (&digests);

  md4_final_sse2_max55 (plains, &digests);

  transpose_md4_digest (&digests, dgst);

  // 1st hmac

  uint32_t i;
  uint32_t j;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636;
      opad_buf[j][i] = 0x5c5c5c5c;
    }

    ipad_buf[0][i] ^= dgst[i].buf.md4[0];
    ipad_buf[1][i] ^= dgst[i].buf.md4[1];
    ipad_buf[2][i] ^= dgst[i].buf.md4[2];
    ipad_buf[3][i] ^= dgst[i].buf.md4[3];

    opad_buf[0][i] ^= dgst[i].buf.md4[0];
    opad_buf[1][i] ^= dgst[i].buf.md4[1];
    opad_buf[2][i] ^= dgst[i].buf.md4[2];
    opad_buf[3][i] ^= dgst[i].buf.md4[3];

    ipad_dgst[0][i] = MD5M_A;
    ipad_dgst[1][i] = MD5M_B;
    ipad_dgst[2][i] = MD5M_C;
    ipad_dgst[3][i] = MD5M_D;

    opad_dgst[0][i] = MD5M_A;
    opad_dgst[1][i] = MD5M_B;
    opad_dgst[2][i] = MD5M_C;
    opad_dgst[3][i] = MD5M_D;
  }

  hashcat_md5_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
  hashcat_md5_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    netntlm_t *netntlm = salt->netntlm;

    const uint32_t userdomain_len = netntlm->user_len
                                  + netntlm->domain_len;

    const uint32_t chall_len      = netntlm->srvchall_len
                                  + netntlm->clichall_len;

    uint32_t ipad_dgst_tmp[4][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst_tmp[4][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 14; j++)
      {
        ipad_buf[j][i] = netntlm->userdomain_buf[j];
      }

      ipad_buf[14][i] = (64 + userdomain_len) * 8;
      ipad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        opad_buf[j][i] = ipad_dgst_tmp[j][i];
      }

      opad_buf[ 4][i] = 0x80;
      opad_buf[ 5][i] = 0;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = (64 + 16) * 8;
      opad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    // 2nd hmac based on 1st hmac result

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x36363636;
        opad_buf[j][i] = 0x5c5c5c5c;
      }

      ipad_buf[0][i] ^= opad_dgst_tmp[0][i];
      ipad_buf[1][i] ^= opad_dgst_tmp[1][i];
      ipad_buf[2][i] ^= opad_dgst_tmp[2][i];
      ipad_buf[3][i] ^= opad_dgst_tmp[3][i];

      opad_buf[0][i] ^= opad_dgst_tmp[0][i];
      opad_buf[1][i] ^= opad_dgst_tmp[1][i];
      opad_buf[2][i] ^= opad_dgst_tmp[2][i];
      opad_buf[3][i] ^= opad_dgst_tmp[3][i];

      ipad_dgst_tmp[0][i] = MD5M_A;
      ipad_dgst_tmp[1][i] = MD5M_B;
      ipad_dgst_tmp[2][i] = MD5M_C;
      ipad_dgst_tmp[3][i] = MD5M_D;

      opad_dgst_tmp[0][i] = MD5M_A;
      opad_dgst_tmp[1][i] = MD5M_B;
      opad_dgst_tmp[2][i] = MD5M_C;
      opad_dgst_tmp[3][i] = MD5M_D;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);
    hashcat_md5_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    int left;
    int off;

    for (left = chall_len, off = 0; left >= 56; left -= 64, off += 16)
    {
      for (i = 0; i < 4; i++)
      {
        for (j = 0; j < 16; j++)
        {
          ipad_buf[j][i] = netntlm->chall_buf[off + j];
        }
      }

      hashcat_md5_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);
    }

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 14; j++)
      {
        ipad_buf[j][i] = netntlm->chall_buf[off + j];
      }

      ipad_buf[14][i] = (64 + chall_len) * 8;
      ipad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        opad_buf[j][i] = ipad_dgst_tmp[j][i];
      }

      opad_buf[ 4][i] = 0x80;
      opad_buf[ 5][i] = 0;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = (64 + 16) * 8;
      opad_buf[15][i] = 0;
    }

    hashcat_md5_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 4; j++)
      {
        dgst[i].buf.md5[j] = opad_dgst_tmp[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_05800 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  extern plain_t **plains_iteration;

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  uint32_t i;

  for (i = 0; i < 4; i++) plains_tmp[i].len = 20;

  uint32_t j;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    j = 0;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2 (plains, &digests, plains_iteration[j]);

    sha1_update_sse2 (plains, &digests, in);

    sha1_update_sse2 (plains, &digests, salt->salt_plain_struct);

    sha1_final_sse2 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    for (j = 1; j < 1024; j++)
    {
      for (i = 0; i < 4; i++)
      {
        BYTESWAP (dgst[i].buf.sha1[0]);
        BYTESWAP (dgst[i].buf.sha1[1]);
        BYTESWAP (dgst[i].buf.sha1[2]);
        BYTESWAP (dgst[i].buf.sha1[3]);
        BYTESWAP (dgst[i].buf.sha1[4]);

        plains_tmp[i].buf[0] = dgst[i].buf.sha1[0];
        plains_tmp[i].buf[1] = dgst[i].buf.sha1[1];
        plains_tmp[i].buf[2] = dgst[i].buf.sha1[2];
        plains_tmp[i].buf[3] = dgst[i].buf.sha1[3];
        plains_tmp[i].buf[4] = dgst[i].buf.sha1[4];
      }

      plain_init (plains);

      sha1_init_sse2 (&digests);

      sha1_update_sse2 (plains, &digests, plains_tmp);

      sha1_update_sse2 (plains, &digests, plains_iteration[j]);

      sha1_update_sse2 (plains, &digests, in);

      sha1_update_sse2 (plains, &digests, salt->salt_plain_struct);

      sha1_final_sse2 (plains, &digests);

      transpose_sha1_digest (&digests, dgst);
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_06300 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  char *ptrs[4];

  ptrs[0] = (char *) &in[0].buf;
  ptrs[1] = (char *) &in[1].buf;
  ptrs[2] = (char *) &in[2].buf;
  ptrs[3] = (char *) &in[3].buf;

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains[0].buf;
  ptrs_tmp[1] = (char *) &plains[1].buf;
  ptrs_tmp[2] = (char *) &plains[2].buf;
  ptrs_tmp[3] = (char *) &plains[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains, in);

    md5_update_sse2_max55 (plains, salt->salt_plain_struct);

    md5_update_sse2_max55 (plains, in);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      if (in[i].len > 16) continue;

      plains[i].len = in[i].len + salt->salt_plain_len;

      /* The password first, since that is what is most unknown */
      /* Then our magic string */
      /* Then the raw salt */
      /* Then just as many characters of the MD5(pw,salt,pw) */

      memcpy (ptrs_tmp[i], ptrs[i], in[i].len);
      memcpy (ptrs_tmp[i] + in[i].len, salt->salt_plain_buf, salt->salt_plain_len);
      memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, in[i].len);

      plains[i].len += in[i].len;

      /* Then something really weird... */

      switch (in[i].len)
      {
        case 1:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          plains[i].len += 1;
          break;

        case 2:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          plains[i].len += 2;
          break;

        case 3:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          plains[i].len += 2;
          break;

        case 4:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 5:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 6:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 7:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          plains[i].len += 3;
          break;

        case 8:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 9:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 10:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 11:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 12:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 13:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 14:
          ptrs_tmp[i][plains[i].len + 0] = ptrs[i][0];
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;

        case 15:
          ptrs_tmp[i][plains[i].len + 0] = 0;
          ptrs_tmp[i][plains[i].len + 1] = 0;
          ptrs_tmp[i][plains[i].len + 2] = 0;
          ptrs_tmp[i][plains[i].len + 3] = 0;
          plains[i].len += 4;
          break;
      }

      /*
      int pl;

      for (pl = in[i].len; pl; pl >>= 1)
      {
        if ((plains[i].len + 1) < PLAIN_SIZE_MD5)
        {
          ptrs_tmp[i][plains[i].len] = (pl & 1) ? '\0' : ptrs[i][0];

          plains[i].len++;
        }
      }
      */
    }

    md5_init_sse2 (&digests);

    md5_final_sse2_max55 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    /* and now, just to make sure things don't run too fast */

    uint32_t j;

    for (j = 0; j < 1000; j++)
    {
      int a1 = j & 1;
      int m3 = j % 3;
      int m7 = j % 7;

      for (i = 0; i < 4; i++)
      {
        if (in[i].len > 16) continue;

        memset (ptrs_tmp[i], 0, BLOCK_SIZE);

        plains[i].len = 0;

        if (a1)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }
        else
        {
          memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, 16);

          plains[i].len += 16;
        }

        if (m3)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, salt->salt_plain_buf, salt->salt_plain_len);

          plains[i].len += salt->salt_plain_len;
        }

        if (m7)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }

        if (a1)
        {
          memcpy (ptrs_tmp[i] + plains[i].len, dgst[i].buf.md5, 16);

          plains[i].len += 16;
        }
        else
        {
          memcpy (ptrs_tmp[i] + plains[i].len, ptrs[i], in[i].len);

          plains[i].len += in[i].len;
        }
      }

      md5_init_sse2 (&digests);

      md5_final_sse2_max55 (plains, &digests);

      transpose_md5_digest (&digests, dgst);
    }

    thread_parameter->indb (thread_parameter, in , dgst, salt);
  }
}

void hashing_06400 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad[8][4] __attribute__ ((aligned (16)));
  uint32_t opad[8][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;
  uint32_t l;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad[0][i] = SHA256M_A;
    ipad[1][i] = SHA256M_B;
    ipad[2][i] = SHA256M_C;
    ipad[3][i] = SHA256M_D;
    ipad[4][i] = SHA256M_E;
    ipad[5][i] = SHA256M_F;
    ipad[6][i] = SHA256M_G;
    ipad[7][i] = SHA256M_H;

    opad[0][i] = SHA256M_A;
    opad[1][i] = SHA256M_B;
    opad[2][i] = SHA256M_C;
    opad[3][i] = SHA256M_D;
    opad[4][i] = SHA256M_E;
    opad[5][i] = SHA256M_F;
    opad[6][i] = SHA256M_G;
    opad[7][i] = SHA256M_H;
  }

  hashcat_sha256_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
  hashcat_sha256_64 ((__m128i *) opad, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    /**
     * init hmac
     */

    uint32_t tmp[8][4] __attribute__ ((aligned (16)));
    uint32_t out[8][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      tmp[0][i] = ipad[0][i];
      tmp[1][i] = ipad[1][i];
      tmp[2][i] = ipad[2][i];
      tmp[3][i] = ipad[3][i];
      tmp[4][i] = ipad[4][i];
      tmp[5][i] = ipad[5][i];
      tmp[6][i] = ipad[6][i];
      tmp[7][i] = ipad[7][i];
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

      memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

      ptrs_tmp[i][salt->salt_plain_len + 3] = 0x01;
      ptrs_tmp[i][salt->salt_plain_len + 4] = 0x80;

      for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->salt_plain_len + 4) * 8;
    }

    for (i = 14; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);

    hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      opad_buf[ 0][i] = tmp[0][i];
      opad_buf[ 1][i] = tmp[1][i];
      opad_buf[ 2][i] = tmp[2][i];
      opad_buf[ 3][i] = tmp[3][i];
      opad_buf[ 4][i] = tmp[4][i];
      opad_buf[ 5][i] = tmp[5][i];
      opad_buf[ 6][i] = tmp[6][i];
      opad_buf[ 7][i] = tmp[7][i];
      opad_buf[ 8][i] = 0x80000000;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 32) * 8;
    }

    for (i = 0; i < 4; i++)
    {
      tmp[0][i] = opad[0][i];
      tmp[1][i] = opad[1][i];
      tmp[2][i] = opad[2][i];
      tmp[3][i] = opad[3][i];
      tmp[4][i] = opad[4][i];
      tmp[5][i] = opad[5][i];
      tmp[6][i] = opad[6][i];
      tmp[7][i] = opad[7][i];
    }

    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

    hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      out[0][i] = tmp[0][i];
      out[1][i] = tmp[1][i];
      out[2][i] = tmp[2][i];
      out[3][i] = tmp[3][i];
      out[4][i] = tmp[4][i];
      out[5][i] = tmp[5][i];
      out[6][i] = tmp[6][i];
      out[7][i] = tmp[7][i];
    }

    /**
     * loop hmac
     */

    for (j = 0; j < salt->iterations - 1; j++)
    {
      for (i = 0; i < 4; i++)
      {
        ipad_buf[ 0][i] = tmp[0][i];
        ipad_buf[ 1][i] = tmp[1][i];
        ipad_buf[ 2][i] = tmp[2][i];
        ipad_buf[ 3][i] = tmp[3][i];
        ipad_buf[ 4][i] = tmp[4][i];
        ipad_buf[ 5][i] = tmp[5][i];
        ipad_buf[ 6][i] = tmp[6][i];
        ipad_buf[ 7][i] = tmp[7][i];
        ipad_buf[ 8][i] = 0x80000000;
        ipad_buf[ 9][i] = 0;
        ipad_buf[10][i] = 0;
        ipad_buf[11][i] = 0;
        ipad_buf[12][i] = 0;
        ipad_buf[13][i] = 0;
        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (64 + 32) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp[0][i] = ipad[0][i];
        tmp[1][i] = ipad[1][i];
        tmp[2][i] = ipad[2][i];
        tmp[3][i] = ipad[3][i];
        tmp[4][i] = ipad[4][i];
        tmp[5][i] = ipad[5][i];
        tmp[6][i] = ipad[6][i];
        tmp[7][i] = ipad[7][i];
      }

      for (i = 0; i < 4; i++) for (l = 0; l < 16; l++) BYTESWAP (ipad_buf[l][i]);

      hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

      for (i = 0; i < 4; i++)
      {
        opad_buf[ 0][i] = tmp[0][i];
        opad_buf[ 1][i] = tmp[1][i];
        opad_buf[ 2][i] = tmp[2][i];
        opad_buf[ 3][i] = tmp[3][i];
        opad_buf[ 4][i] = tmp[4][i];
        opad_buf[ 5][i] = tmp[5][i];
        opad_buf[ 6][i] = tmp[6][i];
        opad_buf[ 7][i] = tmp[7][i];
        opad_buf[ 8][i] = 0x80000000;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (64 + 32) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp[0][i] = opad[0][i];
        tmp[1][i] = opad[1][i];
        tmp[2][i] = opad[2][i];
        tmp[3][i] = opad[3][i];
        tmp[4][i] = opad[4][i];
        tmp[5][i] = opad[5][i];
        tmp[6][i] = opad[6][i];
        tmp[7][i] = opad[7][i];
      }

      for (i = 0; i < 4; i++) for (l = 0; l < 16; l++) BYTESWAP (opad_buf[l][i]);

      hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) opad_buf);

      for (i = 0; i < 4; i++)
      {
        out[0][i] ^= tmp[0][i];
        out[1][i] ^= tmp[1][i];
        out[2][i] ^= tmp[2][i];
        out[3][i] ^= tmp[3][i];
        out[4][i] ^= tmp[4][i];
        out[5][i] ^= tmp[5][i];
        out[6][i] ^= tmp[6][i];
        out[7][i] ^= tmp[7][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      digests[i].buf.sha256[0] = out[0][i];
      digests[i].buf.sha256[1] = out[1][i];
      digests[i].buf.sha256[2] = out[2][i];
      digests[i].buf.sha256[3] = out[3][i];
      digests[i].buf.sha256[4] = out[4][i];
      digests[i].buf.sha256[5] = out[5][i];
      digests[i].buf.sha256[6] = out[6][i];
      digests[i].buf.sha256[7] = out[7][i] & 0xffff03ff;
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_06500 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf64;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf64;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf64;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf64;

  uint64_t ipad[8][2] __attribute__ ((aligned (16)));
  uint64_t opad[8][2] __attribute__ ((aligned (16)));

  uint64_t ipad_buf[16][2] __attribute__ ((aligned (16)));
  uint64_t opad_buf[16][2] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  /*
   * dirty workaround
   */

  uint32_t k;

  for (k = 0; k < 4; k += 2)
  {
    uint32_t i;
    uint32_t j;
    uint32_t l;

    for (i = 0; i < 2; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x3636363636363636 ^ plains[i + k].buf64[j];
        opad_buf[j][i] = 0x5c5c5c5c5c5c5c5c ^ plains[i + k].buf64[j];
      }

      ipad[0][i] = SHA512M_A;
      ipad[1][i] = SHA512M_B;
      ipad[2][i] = SHA512M_C;
      ipad[3][i] = SHA512M_D;
      ipad[4][i] = SHA512M_E;
      ipad[5][i] = SHA512M_F;
      ipad[6][i] = SHA512M_G;
      ipad[7][i] = SHA512M_H;

      opad[0][i] = SHA512M_A;
      opad[1][i] = SHA512M_B;
      opad[2][i] = SHA512M_C;
      opad[3][i] = SHA512M_D;
      opad[4][i] = SHA512M_E;
      opad[5][i] = SHA512M_F;
      opad[6][i] = SHA512M_G;
      opad[7][i] = SHA512M_H;
    }

    hashcat_sha512_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
    hashcat_sha512_64 ((__m128i *) opad, (__m128i *) opad_buf);

    uint32_t salts_idx;

    for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
    {
      salt_t *salt = db->salts_buf[salts_idx];

      if (salt->indexes_found == salt->indexes_cnt) continue;

      /**
       * init hmac
       */

      uint64_t tmp[8][2] __attribute__ ((aligned (16)));
      uint64_t out[8][2] __attribute__ ((aligned (16)));

      for (i = 0; i < 2; i++)
      {
        tmp[0][i] = ipad[0][i];
        tmp[1][i] = ipad[1][i];
        tmp[2][i] = ipad[2][i];
        tmp[3][i] = ipad[3][i];
        tmp[4][i] = ipad[4][i];
        tmp[5][i] = ipad[5][i];
        tmp[6][i] = ipad[6][i];
        tmp[7][i] = ipad[7][i];
      }

      for (i = 0; i < 2; i++)
      {
        memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

        memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

        ptrs_tmp[i][salt->salt_plain_len + 3] = 0x01;
        ptrs_tmp[i][salt->salt_plain_len + 4] = 0x80;

        for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf64[j];

        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (128 + salt->salt_plain_len + 4) * 8;

        BYTESWAP64 (ipad_buf[15][i]);
      }

      hashcat_sha512_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

      for (i = 0; i < 2; i++)
      {
        opad_buf[ 0][i] = tmp[0][i];
        opad_buf[ 1][i] = tmp[1][i];
        opad_buf[ 2][i] = tmp[2][i];
        opad_buf[ 3][i] = tmp[3][i];
        opad_buf[ 4][i] = tmp[4][i];
        opad_buf[ 5][i] = tmp[5][i];
        opad_buf[ 6][i] = tmp[6][i];
        opad_buf[ 7][i] = tmp[7][i];
        opad_buf[ 8][i] = 0x8000000000000000;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (128 + 64) * 8;
      }

      for (i = 0; i < 2; i++)
      {
        tmp[0][i] = opad[0][i];
        tmp[1][i] = opad[1][i];
        tmp[2][i] = opad[2][i];
        tmp[3][i] = opad[3][i];
        tmp[4][i] = opad[4][i];
        tmp[5][i] = opad[5][i];
        tmp[6][i] = opad[6][i];
        tmp[7][i] = opad[7][i];
      }

      for (j = 0; j < 2; j++) for (l = 0; l < 16; l++) BYTESWAP64 (opad_buf[l][j]);

      hashcat_sha512_64 ((__m128i *) tmp, (__m128i *) opad_buf);

      for (i = 0; i < 2; i++)
      {
        out[0][i] = tmp[0][i];
        out[1][i] = tmp[1][i];
        out[2][i] = tmp[2][i];
        out[3][i] = tmp[3][i];
        out[4][i] = tmp[4][i];
        out[5][i] = tmp[5][i];
        out[6][i] = tmp[6][i];
        out[7][i] = tmp[7][i];
      }

      /**
       * loop hmac
       */

      for (j = 0; j < salt->iterations - 1; j++)
      {
        for (i = 0; i < 2; i++)
        {
          ipad_buf[ 0][i] = tmp[0][i];
          ipad_buf[ 1][i] = tmp[1][i];
          ipad_buf[ 2][i] = tmp[2][i];
          ipad_buf[ 3][i] = tmp[3][i];
          ipad_buf[ 4][i] = tmp[4][i];
          ipad_buf[ 5][i] = tmp[5][i];
          ipad_buf[ 6][i] = tmp[6][i];
          ipad_buf[ 7][i] = tmp[7][i];
          ipad_buf[ 8][i] = 0x8000000000000000;
          ipad_buf[ 9][i] = 0;
          ipad_buf[10][i] = 0;
          ipad_buf[11][i] = 0;
          ipad_buf[12][i] = 0;
          ipad_buf[13][i] = 0;
          ipad_buf[14][i] = 0;
          ipad_buf[15][i] = (128 + 64) * 8;
        }

        for (i = 0; i < 2; i++)
        {
          tmp[0][i] = ipad[0][i];
          tmp[1][i] = ipad[1][i];
          tmp[2][i] = ipad[2][i];
          tmp[3][i] = ipad[3][i];
          tmp[4][i] = ipad[4][i];
          tmp[5][i] = ipad[5][i];
          tmp[6][i] = ipad[6][i];
          tmp[7][i] = ipad[7][i];
        }

        for (i = 0; i < 2; i++) for (l = 0; l < 16; l++) BYTESWAP64 (ipad_buf[l][i]);

        hashcat_sha512_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

        for (i = 0; i < 2; i++)
        {
          opad_buf[ 0][i] = tmp[0][i];
          opad_buf[ 1][i] = tmp[1][i];
          opad_buf[ 2][i] = tmp[2][i];
          opad_buf[ 3][i] = tmp[3][i];
          opad_buf[ 4][i] = tmp[4][i];
          opad_buf[ 5][i] = tmp[5][i];
          opad_buf[ 6][i] = tmp[6][i];
          opad_buf[ 7][i] = tmp[7][i];
          opad_buf[ 8][i] = 0x8000000000000000;
          opad_buf[ 9][i] = 0;
          opad_buf[10][i] = 0;
          opad_buf[11][i] = 0;
          opad_buf[12][i] = 0;
          opad_buf[13][i] = 0;
          opad_buf[14][i] = 0;
          opad_buf[15][i] = (128 + 64) * 8;
        }

        for (i = 0; i < 2; i++)
        {
          tmp[0][i] = opad[0][i];
          tmp[1][i] = opad[1][i];
          tmp[2][i] = opad[2][i];
          tmp[3][i] = opad[3][i];
          tmp[4][i] = opad[4][i];
          tmp[5][i] = opad[5][i];
          tmp[6][i] = opad[6][i];
          tmp[7][i] = opad[7][i];
        }

        for (i = 0; i < 2; i++) for (l = 0; l < 16; l++) BYTESWAP64 (opad_buf[l][i]);

        hashcat_sha512_64 ((__m128i *) tmp, (__m128i *) opad_buf);

        for (i = 0; i < 2; i++)
        {
          out[0][i] ^= tmp[0][i];
          out[1][i] ^= tmp[1][i];
          out[2][i] ^= tmp[2][i];
          out[3][i] ^= tmp[3][i];
          out[4][i] ^= tmp[4][i];
          out[5][i] ^= tmp[5][i];
          out[6][i] ^= tmp[6][i];
          out[7][i] ^= tmp[7][i];
        }
      }

      for (i = 0; i < 2; i++)
      {
        digests[i + k].buf.sha512[0] = out[0][i];
        digests[i + k].buf.sha512[1] = out[1][i];
        digests[i + k].buf.sha512[2] = out[2][i];
        digests[i + k].buf.sha512[3] = out[3][i];
        digests[i + k].buf.sha512[4] = out[4][i];
        digests[i + k].buf.sha512[5] = out[5][i];
        digests[i + k].buf.sha512[6] = out[6][i];
        digests[i + k].buf.sha512[7] = out[7][i] & 0xffffffffffffff00;
      }

      thread_parameter->indb (thread_parameter, plains, digests, salt);
    }
  }
}

void hashing_06700 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad[5][4] __attribute__ ((aligned (16)));
  uint32_t opad[5][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;
  uint32_t l;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad[0][i] = SHA1M_A;
    ipad[1][i] = SHA1M_B;
    ipad[2][i] = SHA1M_C;
    ipad[3][i] = SHA1M_D;
    ipad[4][i] = SHA1M_E;

    opad[0][i] = SHA1M_A;
    opad[1][i] = SHA1M_B;
    opad[2][i] = SHA1M_C;
    opad[3][i] = SHA1M_D;
    opad[4][i] = SHA1M_E;
  }

  hashcat_sha1_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
  hashcat_sha1_64 ((__m128i *) opad, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    /**
     * init hmac
     */

    uint32_t tmp[5][4] __attribute__ ((aligned (16)));
    uint32_t out[5][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      tmp[0][i] = ipad[0][i];
      tmp[1][i] = ipad[1][i];
      tmp[2][i] = ipad[2][i];
      tmp[3][i] = ipad[3][i];
      tmp[4][i] = ipad[4][i];
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

      memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

      ptrs_tmp[i][salt->salt_plain_len + 3] = 0x01;
      ptrs_tmp[i][salt->salt_plain_len + 4] = 0x80;

      for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->salt_plain_len + 4) * 8;
    }

    for (i = 14; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);

    hashcat_sha1_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      opad_buf[ 0][i] = tmp[0][i];
      opad_buf[ 1][i] = tmp[1][i];
      opad_buf[ 2][i] = tmp[2][i];
      opad_buf[ 3][i] = tmp[3][i];
      opad_buf[ 4][i] = tmp[4][i];
      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 4; i++)
    {
      tmp[0][i] = opad[0][i];
      tmp[1][i] = opad[1][i];
      tmp[2][i] = opad[2][i];
      tmp[3][i] = opad[3][i];
      tmp[4][i] = opad[4][i];
    }

    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

    hashcat_sha1_64 ((__m128i *) tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      out[0][i] = tmp[0][i];
      out[1][i] = tmp[1][i];
      out[2][i] = tmp[2][i];
      out[3][i] = tmp[3][i];
      out[4][i] = tmp[4][i];
    }

    /**
     * loop hmac
     */

    for (j = 0; j < salt->iterations - 1; j++)
    {
      for (i = 0; i < 4; i++)
      {
        ipad_buf[ 0][i] = tmp[0][i];
        ipad_buf[ 1][i] = tmp[1][i];
        ipad_buf[ 2][i] = tmp[2][i];
        ipad_buf[ 3][i] = tmp[3][i];
        ipad_buf[ 4][i] = tmp[4][i];
        ipad_buf[ 5][i] = 0x80000000;
        ipad_buf[ 6][i] = 0;
        ipad_buf[ 7][i] = 0;
        ipad_buf[ 8][i] = 0;
        ipad_buf[ 9][i] = 0;
        ipad_buf[10][i] = 0;
        ipad_buf[11][i] = 0;
        ipad_buf[12][i] = 0;
        ipad_buf[13][i] = 0;
        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (64 + 20) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp[0][i] = ipad[0][i];
        tmp[1][i] = ipad[1][i];
        tmp[2][i] = ipad[2][i];
        tmp[3][i] = ipad[3][i];
        tmp[4][i] = ipad[4][i];
      }

      for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);

      hashcat_sha1_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

      for (i = 0; i < 4; i++)
      {
        opad_buf[ 0][i] = tmp[0][i];
        opad_buf[ 1][i] = tmp[1][i];
        opad_buf[ 2][i] = tmp[2][i];
        opad_buf[ 3][i] = tmp[3][i];
        opad_buf[ 4][i] = tmp[4][i];
        opad_buf[ 5][i] = 0x80000000;
        opad_buf[ 6][i] = 0;
        opad_buf[ 7][i] = 0;
        opad_buf[ 8][i] = 0;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (64 + 20) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp[0][i] = opad[0][i];
        tmp[1][i] = opad[1][i];
        tmp[2][i] = opad[2][i];
        tmp[3][i] = opad[3][i];
        tmp[4][i] = opad[4][i];
      }

      for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

      hashcat_sha1_64 ((__m128i *) tmp, (__m128i *) opad_buf);

      for (i = 0; i < 4; i++)
      {
        out[0][i] ^= tmp[0][i];
        out[1][i] ^= tmp[1][i];
        out[2][i] ^= tmp[2][i];
        out[3][i] ^= tmp[3][i];
        out[4][i] ^= tmp[4][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      digests[i].buf.sha1[0] = out[0][i];
      digests[i].buf.sha1[1] = out[1][i];
      digests[i].buf.sha1[2] = out[2][i];
      digests[i].buf.sha1[3] = out[3][i];
      digests[i].buf.sha1[4] = out[4][i] & 0xffff03ff;
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_06900 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  db_t *db = thread_parameter->db;

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    plains[i].buf[15] = plains[i].len * 8;
  }

  gost_64 (plains, digests);

  thread_parameter->indb (thread_parameter, plains, digests, db->salts_buf[0]);
}

void hashing_07000 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_update_sse2_max55 (plains, in);

    sha1_update_sse2_max55 (plains, salt->additional_plain_struct);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_07100 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf64;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf64;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf64;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf64;

  uint64_t ipad[8][2] __attribute__ ((aligned (16)));
  uint64_t opad[8][2] __attribute__ ((aligned (16)));

  uint64_t ipad_buf[16][2] __attribute__ ((aligned (16)));
  uint64_t opad_buf[16][2] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t k;

  for (k = 0; k < 4; k += 2)
  {
    uint32_t i;
    uint32_t j;
    uint32_t l;

    for (i = 0; i < 2; i++)
    {
      for (j = 0; j < 16; j++)
      {
        ipad_buf[j][i] = 0x3636363636363636 ^ plains[i + k].buf64[j];
        opad_buf[j][i] = 0x5c5c5c5c5c5c5c5c ^ plains[i + k].buf64[j];
      }

      ipad[0][i] = SHA512M_A;
      ipad[1][i] = SHA512M_B;
      ipad[2][i] = SHA512M_C;
      ipad[3][i] = SHA512M_D;
      ipad[4][i] = SHA512M_E;
      ipad[5][i] = SHA512M_F;
      ipad[6][i] = SHA512M_G;
      ipad[7][i] = SHA512M_H;

      opad[0][i] = SHA512M_A;
      opad[1][i] = SHA512M_B;
      opad[2][i] = SHA512M_C;
      opad[3][i] = SHA512M_D;
      opad[4][i] = SHA512M_E;
      opad[5][i] = SHA512M_F;
      opad[6][i] = SHA512M_G;
      opad[7][i] = SHA512M_H;
    }

    hashcat_sha512_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
    hashcat_sha512_64 ((__m128i *) opad, (__m128i *) opad_buf);

    uint32_t salts_idx;

    for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
    {
      salt_t *salt = db->salts_buf[salts_idx];

      if (salt->indexes_found == salt->indexes_cnt) continue;

      /**
       * init hmac
       */

      uint64_t tmp[8][2] __attribute__ ((aligned (16)));
      uint64_t out[8][2] __attribute__ ((aligned (16)));

      for (i = 0; i < 2; i++)
      {
        tmp[0][i] = ipad[0][i];
        tmp[1][i] = ipad[1][i];
        tmp[2][i] = ipad[2][i];
        tmp[3][i] = ipad[3][i];
        tmp[4][i] = ipad[4][i];
        tmp[5][i] = ipad[5][i];
        tmp[6][i] = ipad[6][i];
        tmp[7][i] = ipad[7][i];
      }

      for (i = 0; i < 2; i++)
      {
        memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

        memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

        ptrs_tmp[i][salt->salt_plain_len + 3] = 0x01;
        ptrs_tmp[i][salt->salt_plain_len + 4] = 0x80;

        for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf64[j];

        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (128 + salt->salt_plain_len + 4) * 8;

        BYTESWAP64 (ipad_buf[15][i]);
      }

      hashcat_sha512_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

      for (i = 0; i < 2; i++)
      {
        opad_buf[ 0][i] = tmp[0][i];
        opad_buf[ 1][i] = tmp[1][i];
        opad_buf[ 2][i] = tmp[2][i];
        opad_buf[ 3][i] = tmp[3][i];
        opad_buf[ 4][i] = tmp[4][i];
        opad_buf[ 5][i] = tmp[5][i];
        opad_buf[ 6][i] = tmp[6][i];
        opad_buf[ 7][i] = tmp[7][i];
        opad_buf[ 8][i] = 0x8000000000000000;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (128 + 64) * 8;
      }

      for (i = 0; i < 2; i++)
      {
        tmp[0][i] = opad[0][i];
        tmp[1][i] = opad[1][i];
        tmp[2][i] = opad[2][i];
        tmp[3][i] = opad[3][i];
        tmp[4][i] = opad[4][i];
        tmp[5][i] = opad[5][i];
        tmp[6][i] = opad[6][i];
        tmp[7][i] = opad[7][i];
      }

      for (i = 0; i < 2; i++) for (j = 0; j < 16; j++) BYTESWAP64 (opad_buf[j][i]);

      hashcat_sha512_64 ((__m128i *) tmp, (__m128i *) opad_buf);

      for (i = 0; i < 2; i++)
      {
        out[0][i] = tmp[0][i];
        out[1][i] = tmp[1][i];
        out[2][i] = tmp[2][i];
        out[3][i] = tmp[3][i];
        out[4][i] = tmp[4][i];
        out[5][i] = tmp[5][i];
        out[6][i] = tmp[6][i];
        out[7][i] = tmp[7][i];
      }

      /**
       * loop hmac
       */

      for (j = 0; j < salt->iterations - 1; j++)
      {
        for (i = 0; i < 2; i++)
        {
          ipad_buf[ 0][i] = tmp[0][i];
          ipad_buf[ 1][i] = tmp[1][i];
          ipad_buf[ 2][i] = tmp[2][i];
          ipad_buf[ 3][i] = tmp[3][i];
          ipad_buf[ 4][i] = tmp[4][i];
          ipad_buf[ 5][i] = tmp[5][i];
          ipad_buf[ 6][i] = tmp[6][i];
          ipad_buf[ 7][i] = tmp[7][i];
          ipad_buf[ 8][i] = 0x8000000000000000;
          ipad_buf[ 9][i] = 0;
          ipad_buf[10][i] = 0;
          ipad_buf[11][i] = 0;
          ipad_buf[12][i] = 0;
          ipad_buf[13][i] = 0;
          ipad_buf[14][i] = 0;
          ipad_buf[15][i] = (128 + 64) * 8;
        }

        for (i = 0; i < 2; i++)
        {
          tmp[0][i] = ipad[0][i];
          tmp[1][i] = ipad[1][i];
          tmp[2][i] = ipad[2][i];
          tmp[3][i] = ipad[3][i];
          tmp[4][i] = ipad[4][i];
          tmp[5][i] = ipad[5][i];
          tmp[6][i] = ipad[6][i];
          tmp[7][i] = ipad[7][i];
        }

        for (i = 0; i < 2; i++) for (l = 0; l < 16; l++) BYTESWAP64 (ipad_buf[l][i]);

        hashcat_sha512_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

        for (i = 0; i < 2; i++)
        {
          opad_buf[ 0][i] = tmp[0][i];
          opad_buf[ 1][i] = tmp[1][i];
          opad_buf[ 2][i] = tmp[2][i];
          opad_buf[ 3][i] = tmp[3][i];
          opad_buf[ 4][i] = tmp[4][i];
          opad_buf[ 5][i] = tmp[5][i];
          opad_buf[ 6][i] = tmp[6][i];
          opad_buf[ 7][i] = tmp[7][i];
          opad_buf[ 8][i] = 0x8000000000000000;
          opad_buf[ 9][i] = 0;
          opad_buf[10][i] = 0;
          opad_buf[11][i] = 0;
          opad_buf[12][i] = 0;
          opad_buf[13][i] = 0;
          opad_buf[14][i] = 0;
          opad_buf[15][i] = (128 + 64) * 8;
        }

        for (i = 0; i < 2; i++)
        {
          tmp[0][i] = opad[0][i];
          tmp[1][i] = opad[1][i];
          tmp[2][i] = opad[2][i];
          tmp[3][i] = opad[3][i];
          tmp[4][i] = opad[4][i];
          tmp[5][i] = opad[5][i];
          tmp[6][i] = opad[6][i];
          tmp[7][i] = opad[7][i];
        }

        for (i = 0; i < 2; i++) for (l = 0; l < 16; l++) BYTESWAP64 (opad_buf[l][i]);

        hashcat_sha512_64 ((__m128i *) tmp, (__m128i *) opad_buf);

        for (i = 0; i < 2; i++)
        {
          out[0][i] ^= tmp[0][i];
          out[1][i] ^= tmp[1][i];
          out[2][i] ^= tmp[2][i];
          out[3][i] ^= tmp[3][i];
          out[4][i] ^= tmp[4][i];
          out[5][i] ^= tmp[5][i];
          out[6][i] ^= tmp[6][i];
          out[7][i] ^= tmp[7][i];
        }
      }

      for (i = 0; i < 2; i++)
      {
        digests[i + k].buf.sha512[0] = out[0][i];
        digests[i + k].buf.sha512[1] = out[1][i];
        digests[i + k].buf.sha512[2] = out[2][i];
        digests[i + k].buf.sha512[3] = out[3][i];
        digests[i + k].buf.sha512[4] = out[4][i];
        digests[i + k].buf.sha512[5] = out[5][i];
        digests[i + k].buf.sha512[6] = out[6][i];
        digests[i + k].buf.sha512[7] = out[7][i];
      }

      thread_parameter->indb (thread_parameter, plains, digests, salt);
    }
  }
}

void hashing_07300 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  uint32_t ipad_dgst[5][4] __attribute__ ((aligned (16)));
  uint32_t opad_dgst[5][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad_dgst[0][i] = SHA1M_A;
    ipad_dgst[1][i] = SHA1M_B;
    ipad_dgst[2][i] = SHA1M_C;
    ipad_dgst[3][i] = SHA1M_D;
    ipad_dgst[4][i] = SHA1M_E;

    opad_dgst[0][i] = SHA1M_A;
    opad_dgst[1][i] = SHA1M_B;
    opad_dgst[2][i] = SHA1M_C;
    opad_dgst[3][i] = SHA1M_D;
    opad_dgst[4][i] = SHA1M_E;
  }

  hashcat_sha1_64 ((__m128i *) ipad_dgst, (__m128i *) ipad_buf);
  hashcat_sha1_64 ((__m128i *) opad_dgst, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    uint32_t ipad_dgst_tmp[5][4] __attribute__ ((aligned (16)));
    uint32_t opad_dgst_tmp[5][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        ipad_dgst_tmp[j][i] = ipad_dgst[j][i];
        opad_dgst_tmp[j][i] = opad_dgst[j][i];
      }
    }

    uint32_t *salt_ptr = (uint32_t *) salt->salt_plain_buf;

    int size = salt->salt_plain_len;

    int left;
    int off;

    for (left = size, off = 0; left >= 56; left -= 64, off += 16)
    {
      for (i = 0; i < 4; i++)
      {
        for (j = 0; j < 16; j++)
        {
          ipad_buf[j][i] = salt_ptr[off + j];
        }
      }

      hashcat_sha1_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);
    }

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 14; j++)
      {
        ipad_buf[j][i] = salt_ptr[off + j];
      }

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->salt_plain_len) * 8;

      BYTESWAP (ipad_buf[15][i]);
    }


    hashcat_sha1_64 ((__m128i *) ipad_dgst_tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        opad_buf[j][i] = ipad_dgst_tmp[j][i];
      }

      opad_buf[ 5][i] = 0x80000000;
      opad_buf[ 6][i] = 0;
      opad_buf[ 7][i] = 0;
      opad_buf[ 8][i] = 0;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 20) * 8;
    }

    for (i = 0; i < 4; i++) for (j = 0; j < 16; j++) BYTESWAP (opad_buf[j][i]);

    hashcat_sha1_64 ((__m128i *) opad_dgst_tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      for (j = 0; j < 5; j++)
      {
        digests[i].buf.sha1[j] = opad_dgst_tmp[j][i];
      }
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_07400 (thread_parameter_t *thread_parameter, plain_t *in)
{
  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    char *salt_buf = salt->salt_plain_buf;
    int   salt_len = salt->salt_plain_len;

    char *password0_buf = (char *) in[0].buf;
    char *password1_buf = (char *) in[1].buf;
    char *password2_buf = (char *) in[2].buf;
    char *password3_buf = (char *) in[3].buf;
    int   password0_len = in[0].len;
    int   password1_len = in[1].len;
    int   password2_len = in[2].len;
    int   password3_len = in[3].len;

    hc_sha256_ctx ctx0;
    hc_sha256_ctx ctx1;
    hc_sha256_ctx ctx2;
    hc_sha256_ctx ctx3;
    hc_sha256_ctx alt_ctx0;
    hc_sha256_ctx alt_ctx1;
    hc_sha256_ctx alt_ctx2;
    hc_sha256_ctx alt_ctx3;

    hc_sha256_ctx p_bytes0;
    hc_sha256_ctx p_bytes1;
    hc_sha256_ctx p_bytes2;
    hc_sha256_ctx p_bytes3;
    hc_sha256_ctx s_bytes0;
    hc_sha256_ctx s_bytes1;
    hc_sha256_ctx s_bytes2;
    hc_sha256_ctx s_bytes3;

    /* Prepare for the real work.  */
    sha256_init (&ctx0);
    sha256_init (&ctx1);
    sha256_init (&ctx2);
    sha256_init (&ctx3);

    /* Add the key string.  */
    sha256_update (&ctx0, password0_buf, password0_len);
    sha256_update (&ctx1, password1_buf, password1_len);
    sha256_update (&ctx2, password2_buf, password2_len);
    sha256_update (&ctx3, password3_buf, password3_len);

    /* The last part is the salt string.  This must be at most 16
       characters and it ends at the first `$' character (for
       compatibility with existing implementations).  */
    sha256_update (&ctx0, salt_buf, salt_len);
    sha256_update (&ctx1, salt_buf, salt_len);
    sha256_update (&ctx2, salt_buf, salt_len);
    sha256_update (&ctx3, salt_buf, salt_len);

    /* Compute alternate sha256 sum with input KEY, SALT, and KEY.  The
       final result will be added to the first context.  */
    sha256_init (&alt_ctx0);
    sha256_init (&alt_ctx1);
    sha256_init (&alt_ctx2);
    sha256_init (&alt_ctx3);

    /* Add key.  */
    sha256_update (&alt_ctx0, password0_buf, password0_len);
    sha256_update (&alt_ctx1, password1_buf, password1_len);
    sha256_update (&alt_ctx2, password2_buf, password2_len);
    sha256_update (&alt_ctx3, password3_buf, password3_len);

    /* Add salt.  */
    sha256_update (&alt_ctx0, salt_buf, salt_len);
    sha256_update (&alt_ctx1, salt_buf, salt_len);
    sha256_update (&alt_ctx2, salt_buf, salt_len);
    sha256_update (&alt_ctx3, salt_buf, salt_len);

    /* Add key again.  */
    sha256_update (&alt_ctx0, password0_buf, password0_len);
    sha256_update (&alt_ctx1, password1_buf, password1_len);
    sha256_update (&alt_ctx2, password2_buf, password2_len);
    sha256_update (&alt_ctx3, password3_buf, password3_len);

    /* Now get result of this (32 bytes) and add it to the other context.  */
    sha256_final (&alt_ctx0);
    sha256_final (&alt_ctx1);
    sha256_final (&alt_ctx2);
    sha256_final (&alt_ctx3);

    /* Add for any character in the key one byte of the alternate sum.  */

    sha256_update (&ctx0, (char *) alt_ctx0.state, password0_len);
    sha256_update (&ctx1, (char *) alt_ctx1.state, password1_len);
    sha256_update (&ctx2, (char *) alt_ctx2.state, password2_len);
    sha256_update (&ctx3, (char *) alt_ctx3.state, password3_len);

    /* Take the binary representation of the length of the key and for every
       1 add the alternate sum, for every 0 the key.  */

    int cnt;

    for (cnt = password0_len; cnt > 0; cnt >>= 1)
    {
      if ((cnt & 1) != 0)
        sha256_update (&ctx0, (char *) alt_ctx0.state, 32);
      else
        sha256_update (&ctx0, password0_buf, password0_len);
    }

    for (cnt = password1_len; cnt > 0; cnt >>= 1)
    {
      if ((cnt & 1) != 0)
        sha256_update (&ctx1, (char *) alt_ctx1.state, 32);
      else
        sha256_update (&ctx1, password1_buf, password1_len);
    }

    for (cnt = password2_len; cnt > 0; cnt >>= 1)
    {
      if ((cnt & 1) != 0)
        sha256_update (&ctx2, (char *) alt_ctx2.state, 32);
      else
        sha256_update (&ctx2, password2_buf, password2_len);
    }

    for (cnt = password3_len; cnt > 0; cnt >>= 1)
    {
      if ((cnt & 1) != 0)
        sha256_update (&ctx3, (char *) alt_ctx3.state, 32);
      else
        sha256_update (&ctx3, password3_buf, password3_len);
    }

    /* Create intermediate result.  */
    sha256_final (&ctx0);
    sha256_final (&ctx1);
    sha256_final (&ctx2);
    sha256_final (&ctx3);

    /* Start computation of P byte sequence.  */
    sha256_init (&p_bytes0);
    sha256_init (&p_bytes1);
    sha256_init (&p_bytes2);
    sha256_init (&p_bytes3);

    /* For every character in the password add the entire password.  */
    for (cnt = 0; cnt < password0_len; cnt++)
    {
      sha256_update (&p_bytes0, password0_buf, password0_len);
    }

    for (cnt = 0; cnt < password1_len; cnt++)
    {
      sha256_update (&p_bytes1, password1_buf, password1_len);
    }

    for (cnt = 0; cnt < password2_len; cnt++)
    {
      sha256_update (&p_bytes2, password2_buf, password2_len);
    }

    for (cnt = 0; cnt < password3_len; cnt++)
    {
      sha256_update (&p_bytes3, password3_buf, password3_len);
    }

    /* Finish the state.  */
    sha256_final (&p_bytes0);
    sha256_final (&p_bytes1);
    sha256_final (&p_bytes2);
    sha256_final (&p_bytes3);

    /* Start computation of S byte sequence.  */
    sha256_init (&s_bytes0);
    sha256_init (&s_bytes1);
    sha256_init (&s_bytes2);
    sha256_init (&s_bytes3);

    /* For every character in the password add the entire password.  */
    for (cnt = 0; cnt < 16 + ((unsigned char*) ctx0.state)[0]; cnt++)
    {
      sha256_update (&s_bytes0, salt_buf, salt_len);
    }

    for (cnt = 0; cnt < 16 + ((unsigned char*) ctx1.state)[0]; cnt++)
    {
      sha256_update (&s_bytes1, salt_buf, salt_len);
    }

    for (cnt = 0; cnt < 16 + ((unsigned char*) ctx2.state)[0]; cnt++)
    {
      sha256_update (&s_bytes2, salt_buf, salt_len);
    }

    for (cnt = 0; cnt < 16 + ((unsigned char*) ctx3.state)[0]; cnt++)
    {
      sha256_update (&s_bytes3, salt_buf, salt_len);
    }

    /* Finish the state.  */
    sha256_final (&s_bytes0);
    sha256_final (&s_bytes1);
    sha256_final (&s_bytes2);
    sha256_final (&s_bytes3);

    /* sse2 specific */

    plain_t plain_alt_ctx[4];

    plain_alt_ctx[0].buf[0] = ctx0.state[0];
    plain_alt_ctx[0].buf[1] = ctx0.state[1];
    plain_alt_ctx[0].buf[2] = ctx0.state[2];
    plain_alt_ctx[0].buf[3] = ctx0.state[3];
    plain_alt_ctx[0].buf[4] = ctx0.state[4];
    plain_alt_ctx[0].buf[5] = ctx0.state[5];
    plain_alt_ctx[0].buf[6] = ctx0.state[6];
    plain_alt_ctx[0].buf[7] = ctx0.state[7];
    plain_alt_ctx[1].buf[0] = ctx1.state[0];
    plain_alt_ctx[1].buf[1] = ctx1.state[1];
    plain_alt_ctx[1].buf[2] = ctx1.state[2];
    plain_alt_ctx[1].buf[3] = ctx1.state[3];
    plain_alt_ctx[1].buf[4] = ctx1.state[4];
    plain_alt_ctx[1].buf[5] = ctx1.state[5];
    plain_alt_ctx[1].buf[6] = ctx1.state[6];
    plain_alt_ctx[1].buf[7] = ctx1.state[7];
    plain_alt_ctx[2].buf[0] = ctx2.state[0];
    plain_alt_ctx[2].buf[1] = ctx2.state[1];
    plain_alt_ctx[2].buf[2] = ctx2.state[2];
    plain_alt_ctx[2].buf[3] = ctx2.state[3];
    plain_alt_ctx[2].buf[4] = ctx2.state[4];
    plain_alt_ctx[2].buf[5] = ctx2.state[5];
    plain_alt_ctx[2].buf[6] = ctx2.state[6];
    plain_alt_ctx[2].buf[7] = ctx2.state[7];
    plain_alt_ctx[3].buf[0] = ctx3.state[0];
    plain_alt_ctx[3].buf[1] = ctx3.state[1];
    plain_alt_ctx[3].buf[2] = ctx3.state[2];
    plain_alt_ctx[3].buf[3] = ctx3.state[3];
    plain_alt_ctx[3].buf[4] = ctx3.state[4];
    plain_alt_ctx[3].buf[5] = ctx3.state[5];
    plain_alt_ctx[3].buf[6] = ctx3.state[6];
    plain_alt_ctx[3].buf[7] = ctx3.state[7];

    plain_alt_ctx[0].len = 32;
    plain_alt_ctx[1].len = 32;
    plain_alt_ctx[2].len = 32;
    plain_alt_ctx[3].len = 32;

    plain_t plain_p_bytes[4];

    plain_p_bytes[0].buf[0] = p_bytes0.state[0];
    plain_p_bytes[0].buf[1] = p_bytes0.state[1];
    plain_p_bytes[0].buf[2] = p_bytes0.state[2];
    plain_p_bytes[0].buf[3] = p_bytes0.state[3];
    plain_p_bytes[0].buf[4] = p_bytes0.state[4];
    plain_p_bytes[0].buf[5] = p_bytes0.state[5];
    plain_p_bytes[0].buf[6] = p_bytes0.state[6];
    plain_p_bytes[0].buf[7] = p_bytes0.state[7];
    plain_p_bytes[1].buf[0] = p_bytes1.state[0];
    plain_p_bytes[1].buf[1] = p_bytes1.state[1];
    plain_p_bytes[1].buf[2] = p_bytes1.state[2];
    plain_p_bytes[1].buf[3] = p_bytes1.state[3];
    plain_p_bytes[1].buf[4] = p_bytes1.state[4];
    plain_p_bytes[1].buf[5] = p_bytes1.state[5];
    plain_p_bytes[1].buf[6] = p_bytes1.state[6];
    plain_p_bytes[1].buf[7] = p_bytes1.state[7];
    plain_p_bytes[2].buf[0] = p_bytes2.state[0];
    plain_p_bytes[2].buf[1] = p_bytes2.state[1];
    plain_p_bytes[2].buf[2] = p_bytes2.state[2];
    plain_p_bytes[2].buf[3] = p_bytes2.state[3];
    plain_p_bytes[2].buf[4] = p_bytes2.state[4];
    plain_p_bytes[2].buf[5] = p_bytes2.state[5];
    plain_p_bytes[2].buf[6] = p_bytes2.state[6];
    plain_p_bytes[2].buf[7] = p_bytes2.state[7];
    plain_p_bytes[3].buf[0] = p_bytes3.state[0];
    plain_p_bytes[3].buf[1] = p_bytes3.state[1];
    plain_p_bytes[3].buf[2] = p_bytes3.state[2];
    plain_p_bytes[3].buf[3] = p_bytes3.state[3];
    plain_p_bytes[3].buf[4] = p_bytes3.state[4];
    plain_p_bytes[3].buf[5] = p_bytes3.state[5];
    plain_p_bytes[3].buf[6] = p_bytes3.state[6];
    plain_p_bytes[3].buf[7] = p_bytes3.state[7];

    plain_p_bytes[0].len = password0_len;
    plain_p_bytes[1].len = password1_len;
    plain_p_bytes[2].len = password2_len;
    plain_p_bytes[3].len = password3_len;

    plain_t plain_s_bytes[4];

    plain_s_bytes[0].buf[0] = s_bytes0.state[0];
    plain_s_bytes[0].buf[1] = s_bytes0.state[1];
    plain_s_bytes[0].buf[2] = s_bytes0.state[2];
    plain_s_bytes[0].buf[3] = s_bytes0.state[3];
    plain_s_bytes[0].buf[4] = s_bytes0.state[4];
    plain_s_bytes[0].buf[5] = s_bytes0.state[5];
    plain_s_bytes[0].buf[6] = s_bytes0.state[6];
    plain_s_bytes[0].buf[7] = s_bytes0.state[7];
    plain_s_bytes[1].buf[0] = s_bytes1.state[0];
    plain_s_bytes[1].buf[1] = s_bytes1.state[1];
    plain_s_bytes[1].buf[2] = s_bytes1.state[2];
    plain_s_bytes[1].buf[3] = s_bytes1.state[3];
    plain_s_bytes[1].buf[4] = s_bytes1.state[4];
    plain_s_bytes[1].buf[5] = s_bytes1.state[5];
    plain_s_bytes[1].buf[6] = s_bytes1.state[6];
    plain_s_bytes[1].buf[7] = s_bytes1.state[7];
    plain_s_bytes[2].buf[0] = s_bytes2.state[0];
    plain_s_bytes[2].buf[1] = s_bytes2.state[1];
    plain_s_bytes[2].buf[2] = s_bytes2.state[2];
    plain_s_bytes[2].buf[3] = s_bytes2.state[3];
    plain_s_bytes[2].buf[4] = s_bytes2.state[4];
    plain_s_bytes[2].buf[5] = s_bytes2.state[5];
    plain_s_bytes[2].buf[6] = s_bytes2.state[6];
    plain_s_bytes[2].buf[7] = s_bytes2.state[7];
    plain_s_bytes[3].buf[0] = s_bytes3.state[0];
    plain_s_bytes[3].buf[1] = s_bytes3.state[1];
    plain_s_bytes[3].buf[2] = s_bytes3.state[2];
    plain_s_bytes[3].buf[3] = s_bytes3.state[3];
    plain_s_bytes[3].buf[4] = s_bytes3.state[4];
    plain_s_bytes[3].buf[5] = s_bytes3.state[5];
    plain_s_bytes[3].buf[6] = s_bytes3.state[6];
    plain_s_bytes[3].buf[7] = s_bytes3.state[7];

    plain_s_bytes[0].len = salt_len;
    plain_s_bytes[1].len = salt_len;
    plain_s_bytes[2].len = salt_len;
    plain_s_bytes[3].len = salt_len;

    /* Repeatedly run the collected hash value through sha256 to
       burn CPU cycles.  */

    for (cnt = 0; cnt < (int) salt->iterations; cnt++)
    {
      /* New context.  */

      digest_sha256_sse2_t sse2_ctx;

      sha256_init_sse2 (&sse2_ctx);

      plain_t sse2_plain[4];

      plain_init (sse2_plain);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha256_update_sse2 (sse2_plain, &sse2_ctx, plain_p_bytes);
      else
        sha256_update_sse2 (sse2_plain, &sse2_ctx, plain_alt_ctx);

      /* Add salt for numbers not divisible by 3.  */
      if (cnt % 3 != 0)
        sha256_update_sse2 (sse2_plain, &sse2_ctx, plain_s_bytes);

      /* Add key for numbers not divisible by 7.  */
      if (cnt % 7 != 0)
        sha256_update_sse2 (sse2_plain, &sse2_ctx, plain_p_bytes);

      /* Add key or last result.  */
      if ((cnt & 1) != 0)
        sha256_update_sse2 (sse2_plain, &sse2_ctx, plain_alt_ctx);
      else
        sha256_update_sse2 (sse2_plain, &sse2_ctx, plain_p_bytes);

      /* Create intermediate [SIC] result.  */
      sha256_final_sse2 (sse2_plain, &sse2_ctx);

      plain_alt_ctx[0].buf[0] = sse2_ctx.buf32[ 0];
      plain_alt_ctx[1].buf[0] = sse2_ctx.buf32[ 1];
      plain_alt_ctx[2].buf[0] = sse2_ctx.buf32[ 2];
      plain_alt_ctx[3].buf[0] = sse2_ctx.buf32[ 3];
      plain_alt_ctx[0].buf[1] = sse2_ctx.buf32[ 4];
      plain_alt_ctx[1].buf[1] = sse2_ctx.buf32[ 5];
      plain_alt_ctx[2].buf[1] = sse2_ctx.buf32[ 6];
      plain_alt_ctx[3].buf[1] = sse2_ctx.buf32[ 7];
      plain_alt_ctx[0].buf[2] = sse2_ctx.buf32[ 8];
      plain_alt_ctx[1].buf[2] = sse2_ctx.buf32[ 9];
      plain_alt_ctx[2].buf[2] = sse2_ctx.buf32[10];
      plain_alt_ctx[3].buf[2] = sse2_ctx.buf32[11];
      plain_alt_ctx[0].buf[3] = sse2_ctx.buf32[12];
      plain_alt_ctx[1].buf[3] = sse2_ctx.buf32[13];
      plain_alt_ctx[2].buf[3] = sse2_ctx.buf32[14];
      plain_alt_ctx[3].buf[3] = sse2_ctx.buf32[15];
      plain_alt_ctx[0].buf[4] = sse2_ctx.buf32[16];
      plain_alt_ctx[1].buf[4] = sse2_ctx.buf32[17];
      plain_alt_ctx[2].buf[4] = sse2_ctx.buf32[18];
      plain_alt_ctx[3].buf[4] = sse2_ctx.buf32[19];
      plain_alt_ctx[0].buf[5] = sse2_ctx.buf32[20];
      plain_alt_ctx[1].buf[5] = sse2_ctx.buf32[21];
      plain_alt_ctx[2].buf[5] = sse2_ctx.buf32[22];
      plain_alt_ctx[3].buf[5] = sse2_ctx.buf32[23];
      plain_alt_ctx[0].buf[6] = sse2_ctx.buf32[24];
      plain_alt_ctx[1].buf[6] = sse2_ctx.buf32[25];
      plain_alt_ctx[2].buf[6] = sse2_ctx.buf32[26];
      plain_alt_ctx[3].buf[6] = sse2_ctx.buf32[27];
      plain_alt_ctx[0].buf[7] = sse2_ctx.buf32[28];
      plain_alt_ctx[1].buf[7] = sse2_ctx.buf32[29];
      plain_alt_ctx[2].buf[7] = sse2_ctx.buf32[30];
      plain_alt_ctx[3].buf[7] = sse2_ctx.buf32[31];

      BYTESWAP (plain_alt_ctx[0].buf[0]);
      BYTESWAP (plain_alt_ctx[0].buf[1]);
      BYTESWAP (plain_alt_ctx[0].buf[2]);
      BYTESWAP (plain_alt_ctx[0].buf[3]);
      BYTESWAP (plain_alt_ctx[0].buf[4]);
      BYTESWAP (plain_alt_ctx[0].buf[5]);
      BYTESWAP (plain_alt_ctx[0].buf[6]);
      BYTESWAP (plain_alt_ctx[0].buf[7]);
      BYTESWAP (plain_alt_ctx[1].buf[0]);
      BYTESWAP (plain_alt_ctx[1].buf[1]);
      BYTESWAP (plain_alt_ctx[1].buf[2]);
      BYTESWAP (plain_alt_ctx[1].buf[3]);
      BYTESWAP (plain_alt_ctx[1].buf[4]);
      BYTESWAP (plain_alt_ctx[1].buf[5]);
      BYTESWAP (plain_alt_ctx[1].buf[6]);
      BYTESWAP (plain_alt_ctx[1].buf[7]);
      BYTESWAP (plain_alt_ctx[2].buf[0]);
      BYTESWAP (plain_alt_ctx[2].buf[1]);
      BYTESWAP (plain_alt_ctx[2].buf[2]);
      BYTESWAP (plain_alt_ctx[2].buf[3]);
      BYTESWAP (plain_alt_ctx[2].buf[4]);
      BYTESWAP (plain_alt_ctx[2].buf[5]);
      BYTESWAP (plain_alt_ctx[2].buf[6]);
      BYTESWAP (plain_alt_ctx[2].buf[7]);
      BYTESWAP (plain_alt_ctx[3].buf[0]);
      BYTESWAP (plain_alt_ctx[3].buf[1]);
      BYTESWAP (plain_alt_ctx[3].buf[2]);
      BYTESWAP (plain_alt_ctx[3].buf[3]);
      BYTESWAP (plain_alt_ctx[3].buf[4]);
      BYTESWAP (plain_alt_ctx[3].buf[5]);
      BYTESWAP (plain_alt_ctx[3].buf[6]);
      BYTESWAP (plain_alt_ctx[3].buf[7]);
    }

    digest_t digest[4];

    digest[0].buf.sha256[0] = plain_alt_ctx[0].buf[0];
    digest[0].buf.sha256[1] = plain_alt_ctx[0].buf[1];
    digest[0].buf.sha256[2] = plain_alt_ctx[0].buf[2];
    digest[0].buf.sha256[3] = plain_alt_ctx[0].buf[3];
    digest[0].buf.sha256[4] = plain_alt_ctx[0].buf[4];
    digest[0].buf.sha256[5] = plain_alt_ctx[0].buf[5];
    digest[0].buf.sha256[6] = plain_alt_ctx[0].buf[6];
    digest[0].buf.sha256[7] = plain_alt_ctx[0].buf[7];
    digest[1].buf.sha256[0] = plain_alt_ctx[1].buf[0];
    digest[1].buf.sha256[1] = plain_alt_ctx[1].buf[1];
    digest[1].buf.sha256[2] = plain_alt_ctx[1].buf[2];
    digest[1].buf.sha256[3] = plain_alt_ctx[1].buf[3];
    digest[1].buf.sha256[4] = plain_alt_ctx[1].buf[4];
    digest[1].buf.sha256[5] = plain_alt_ctx[1].buf[5];
    digest[1].buf.sha256[6] = plain_alt_ctx[1].buf[6];
    digest[1].buf.sha256[7] = plain_alt_ctx[1].buf[7];
    digest[2].buf.sha256[0] = plain_alt_ctx[2].buf[0];
    digest[2].buf.sha256[1] = plain_alt_ctx[2].buf[1];
    digest[2].buf.sha256[2] = plain_alt_ctx[2].buf[2];
    digest[2].buf.sha256[3] = plain_alt_ctx[2].buf[3];
    digest[2].buf.sha256[4] = plain_alt_ctx[2].buf[4];
    digest[2].buf.sha256[5] = plain_alt_ctx[2].buf[5];
    digest[2].buf.sha256[6] = plain_alt_ctx[2].buf[6];
    digest[2].buf.sha256[7] = plain_alt_ctx[2].buf[7];
    digest[3].buf.sha256[0] = plain_alt_ctx[3].buf[0];
    digest[3].buf.sha256[1] = plain_alt_ctx[3].buf[1];
    digest[3].buf.sha256[2] = plain_alt_ctx[3].buf[2];
    digest[3].buf.sha256[3] = plain_alt_ctx[3].buf[3];
    digest[3].buf.sha256[4] = plain_alt_ctx[3].buf[4];
    digest[3].buf.sha256[5] = plain_alt_ctx[3].buf[5];
    digest[3].buf.sha256[6] = plain_alt_ctx[3].buf[6];
    digest[3].buf.sha256[7] = plain_alt_ctx[3].buf[7];

    thread_parameter->indb (thread_parameter, in, digest, salt);
  }
}

void hashing_07600 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (in, &digests);

  transpose_sha1_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    uint_to_hex_lower (dgst[i].buf.sha1[0], &ptrs_tmp[i][0]);
    uint_to_hex_lower (dgst[i].buf.sha1[1], &ptrs_tmp[i][8]);
    uint_to_hex_lower (dgst[i].buf.sha1[2], &ptrs_tmp[i][16]);
    uint_to_hex_lower (dgst[i].buf.sha1[3], &ptrs_tmp[i][24]);
    uint_to_hex_lower (dgst[i].buf.sha1[4], &ptrs_tmp[i][32]);

    plains_tmp[i].len = 40;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2 (plains, &digests, salt->salt_plain_struct);

    sha1_update_sse2 (plains, &digests, plains_tmp);

    sha1_final_sse2 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_07900 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha512_sse2_t digests;

  digest_t dgst[4];

  db_t *db = thread_parameter->db;

  plain_t plains[4];

  plain_t plains_tmp[4];

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    // initial sha512 ($salt.$pass)

    plain_init (plains);

    sha512_init_sse2 (&digests);

    sha512_update_sse2 (plains, &digests, salt->salt_plain_struct);

    sha512_update_sse2 (plains, &digests, in);

    sha512_final_sse2 (plains, &digests);

    transpose_sha512_digest (&digests, dgst);

    uint32_t cnt;

    for (cnt = 0; cnt < salt->iterations; cnt++)
    {
      // loop with both: 64 bit digest + $pass

      uint32_t i;

      for (i = 0; i < 4; i++)
      {
        memcpy (plains_tmp[i].buf, dgst[i].buf.sha512, 64);

        BYTESWAP64 (plains_tmp[i].buf64[0]);
        BYTESWAP64 (plains_tmp[i].buf64[1]);
        BYTESWAP64 (plains_tmp[i].buf64[2]);
        BYTESWAP64 (plains_tmp[i].buf64[3]);
        BYTESWAP64 (plains_tmp[i].buf64[4]);
        BYTESWAP64 (plains_tmp[i].buf64[5]);
        BYTESWAP64 (plains_tmp[i].buf64[6]);
        BYTESWAP64 (plains_tmp[i].buf64[7]);

        plains_tmp[i].len = 64;
      }

      plain_init (plains);

      sha512_init_sse2 (&digests);

      // previous digest

      sha512_update_sse2 (plains, &digests, plains_tmp);

      // pass

      sha512_update_sse2 (plains, &digests, in);

      sha512_final_sse2 (plains, &digests);

      transpose_sha512_digest (&digests, dgst);
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

// similar to aix -m 6400 but without the final bitmask hack ( & 0xffff03ff )

void hashing_09200 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  uint32_t ipad[8][4] __attribute__ ((aligned (16)));
  uint32_t opad[8][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  db_t *db = thread_parameter->db;

  uint32_t i;
  uint32_t j;
  uint32_t l;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad[0][i] = SHA256M_A;
    ipad[1][i] = SHA256M_B;
    ipad[2][i] = SHA256M_C;
    ipad[3][i] = SHA256M_D;
    ipad[4][i] = SHA256M_E;
    ipad[5][i] = SHA256M_F;
    ipad[6][i] = SHA256M_G;
    ipad[7][i] = SHA256M_H;

    opad[0][i] = SHA256M_A;
    opad[1][i] = SHA256M_B;
    opad[2][i] = SHA256M_C;
    opad[3][i] = SHA256M_D;
    opad[4][i] = SHA256M_E;
    opad[5][i] = SHA256M_F;
    opad[6][i] = SHA256M_G;
    opad[7][i] = SHA256M_H;
  }

  hashcat_sha256_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
  hashcat_sha256_64 ((__m128i *) opad, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    /**
     * init hmac
     */

    uint32_t tmp[8][4] __attribute__ ((aligned (16)));
    uint32_t out[8][4] __attribute__ ((aligned (16)));

    for (i = 0; i < 4; i++)
    {
      tmp[0][i] = ipad[0][i];
      tmp[1][i] = ipad[1][i];
      tmp[2][i] = ipad[2][i];
      tmp[3][i] = ipad[3][i];
      tmp[4][i] = ipad[4][i];
      tmp[5][i] = ipad[5][i];
      tmp[6][i] = ipad[6][i];
      tmp[7][i] = ipad[7][i];
    }

    for (i = 0; i < 4; i++)
    {
      memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

      memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

      ptrs_tmp[i][salt->salt_plain_len + 3] = 0x01;
      ptrs_tmp[i][salt->salt_plain_len + 4] = 0x80;

      for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + salt->salt_plain_len + 4) * 8;
    }

    for (i = 14; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (ipad_buf[i][l]);

    hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      opad_buf[ 0][i] = tmp[0][i];
      opad_buf[ 1][i] = tmp[1][i];
      opad_buf[ 2][i] = tmp[2][i];
      opad_buf[ 3][i] = tmp[3][i];
      opad_buf[ 4][i] = tmp[4][i];
      opad_buf[ 5][i] = tmp[5][i];
      opad_buf[ 6][i] = tmp[6][i];
      opad_buf[ 7][i] = tmp[7][i];
      opad_buf[ 8][i] = 0x80000000;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 32) * 8;
    }

    for (i = 0; i < 4; i++)
    {
      tmp[0][i] = opad[0][i];
      tmp[1][i] = opad[1][i];
      tmp[2][i] = opad[2][i];
      tmp[3][i] = opad[3][i];
      tmp[4][i] = opad[4][i];
      tmp[5][i] = opad[5][i];
      tmp[6][i] = opad[6][i];
      tmp[7][i] = opad[7][i];
    }

    for (i = 0; i < 16; i++) for (l = 0; l < 4; l++) BYTESWAP (opad_buf[i][l]);

    hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      out[0][i] = tmp[0][i];
      out[1][i] = tmp[1][i];
      out[2][i] = tmp[2][i];
      out[3][i] = tmp[3][i];
      out[4][i] = tmp[4][i];
      out[5][i] = tmp[5][i];
      out[6][i] = tmp[6][i];
      out[7][i] = tmp[7][i];
    }

    /**
     * loop hmac
     */

    for (j = 0; j < salt->iterations - 1; j++)
    {
      for (i = 0; i < 4; i++)
      {
        ipad_buf[ 0][i] = tmp[0][i];
        ipad_buf[ 1][i] = tmp[1][i];
        ipad_buf[ 2][i] = tmp[2][i];
        ipad_buf[ 3][i] = tmp[3][i];
        ipad_buf[ 4][i] = tmp[4][i];
        ipad_buf[ 5][i] = tmp[5][i];
        ipad_buf[ 6][i] = tmp[6][i];
        ipad_buf[ 7][i] = tmp[7][i];
        ipad_buf[ 8][i] = 0x80000000;
        ipad_buf[ 9][i] = 0;
        ipad_buf[10][i] = 0;
        ipad_buf[11][i] = 0;
        ipad_buf[12][i] = 0;
        ipad_buf[13][i] = 0;
        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (64 + 32) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp[0][i] = ipad[0][i];
        tmp[1][i] = ipad[1][i];
        tmp[2][i] = ipad[2][i];
        tmp[3][i] = ipad[3][i];
        tmp[4][i] = ipad[4][i];
        tmp[5][i] = ipad[5][i];
        tmp[6][i] = ipad[6][i];
        tmp[7][i] = ipad[7][i];
      }

      for (i = 0; i < 4; i++) for (l = 0; l < 16; l++) BYTESWAP (ipad_buf[l][i]);

      hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

      for (i = 0; i < 4; i++)
      {
        opad_buf[ 0][i] = tmp[0][i];
        opad_buf[ 1][i] = tmp[1][i];
        opad_buf[ 2][i] = tmp[2][i];
        opad_buf[ 3][i] = tmp[3][i];
        opad_buf[ 4][i] = tmp[4][i];
        opad_buf[ 5][i] = tmp[5][i];
        opad_buf[ 6][i] = tmp[6][i];
        opad_buf[ 7][i] = tmp[7][i];
        opad_buf[ 8][i] = 0x80000000;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (64 + 32) * 8;
      }

      for (i = 0; i < 4; i++)
      {
        tmp[0][i] = opad[0][i];
        tmp[1][i] = opad[1][i];
        tmp[2][i] = opad[2][i];
        tmp[3][i] = opad[3][i];
        tmp[4][i] = opad[4][i];
        tmp[5][i] = opad[5][i];
        tmp[6][i] = opad[6][i];
        tmp[7][i] = opad[7][i];
      }

      for (i = 0; i < 4; i++) for (l = 0; l < 16; l++) BYTESWAP (opad_buf[l][i]);

      hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) opad_buf);

      for (i = 0; i < 4; i++)
      {
        out[0][i] ^= tmp[0][i];
        out[1][i] ^= tmp[1][i];
        out[2][i] ^= tmp[2][i];
        out[3][i] ^= tmp[3][i];
        out[4][i] ^= tmp[4][i];
        out[5][i] ^= tmp[5][i];
        out[6][i] ^= tmp[6][i];
        out[7][i] ^= tmp[7][i];
      }
    }

    for (i = 0; i < 4; i++)
    {
      digests[i].buf.sha256[0] = out[0][i];
      digests[i].buf.sha256[1] = out[1][i];
      digests[i].buf.sha256[2] = out[2][i];
      digests[i].buf.sha256[3] = out[3][i];
      digests[i].buf.sha256[4] = out[4][i];
      digests[i].buf.sha256[5] = out[5][i];
      digests[i].buf.sha256[6] = out[6][i];
      digests[i].buf.sha256[7] = out[7][i];
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

#define GET_SCRYPT_CNT(r,p) (2 * (r) * 16 * (p))
#define GET_SMIX_CNT(r,N)   (2 * (r) * 16 * (N))
#define GET_STATE_CNT(r)    (2 * (r) * 16)

#ifdef __XOP__
#define ADD_ROTATE_XOR(r,i1,i2,s)       \
{                                       \
  __m128i T1;                           \
                                        \
  T1  = _mm_add_epi32  ((i1), (i2));    \
  T1  = _mm_roti_epi32 (T1, (s));       \
  (r) = _mm_xor_si128  ((r), T1);       \
}
#else
#define ADD_ROTATE_XOR(r,i1,i2,s)       \
{                                       \
  __m128i T1;                           \
  __m128i T2;                           \
                                        \
  T1  = _mm_add_epi32  ((i1), (i2));    \
  T2  = _mm_srli_epi32 (T1, 32 - (s));  \
  T1  = _mm_slli_epi32 (T1, (s));       \
  (r) = _mm_xor_si128  ((r), T1);       \
  (r) = _mm_xor_si128  ((r), T2);       \
}
#endif

#define SALSA20_2R()                    \
{                                       \
  ADD_ROTATE_XOR (X1, X0, X3,  7);      \
  ADD_ROTATE_XOR (X2, X1, X0,  9);      \
  ADD_ROTATE_XOR (X3, X2, X1, 13);      \
  ADD_ROTATE_XOR (X0, X3, X2, 18);      \
                                        \
  X1 = _mm_shuffle_epi32 (X1, 0x93);    \
  X2 = _mm_shuffle_epi32 (X2, 0x4e);    \
  X3 = _mm_shuffle_epi32 (X3, 0x39);    \
                                        \
  ADD_ROTATE_XOR (X3, X0, X1,  7);      \
  ADD_ROTATE_XOR (X2, X3, X0,  9);      \
  ADD_ROTATE_XOR (X1, X2, X3, 13);      \
  ADD_ROTATE_XOR (X0, X1, X2, 18);      \
                                        \
  X1 = _mm_shuffle_epi32 (X1, 0x39);    \
  X2 = _mm_shuffle_epi32 (X2, 0x4e);    \
  X3 = _mm_shuffle_epi32 (X3, 0x93);    \
}

#define SALSA20_8_XOR()                 \
{                                       \
  R0 = _mm_xor_si128 (R0, Y0);          \
  R1 = _mm_xor_si128 (R1, Y1);          \
  R2 = _mm_xor_si128 (R2, Y2);          \
  R3 = _mm_xor_si128 (R3, Y3);          \
                                        \
  __m128i X0 = R0;                      \
  __m128i X1 = R1;                      \
  __m128i X2 = R2;                      \
  __m128i X3 = R3;                      \
                                        \
  SALSA20_2R ();                        \
  SALSA20_2R ();                        \
  SALSA20_2R ();                        \
  SALSA20_2R ();                        \
                                        \
  R0 = _mm_add_epi32 (R0, X0);          \
  R1 = _mm_add_epi32 (R1, X1);          \
  R2 = _mm_add_epi32 (R2, X2);          \
  R3 = _mm_add_epi32 (R3, X3);          \
}

static void scrypt_blockmix_salsa8 (__m128i *Bin, __m128i *Bout, const uint32_t r)
{
  __m128i R0 = Bin[8 * r - 4];
  __m128i R1 = Bin[8 * r - 3];
  __m128i R2 = Bin[8 * r - 2];
  __m128i R3 = Bin[8 * r - 1];

  uint32_t idx_y  = 0;
  uint32_t idx_r1 = 0;
  uint32_t idx_r2 = r * 4;

  uint32_t i;

  for (i = 0; i < r; i++)
  {
    __m128i Y0;
    __m128i Y1;
    __m128i Y2;
    __m128i Y3;

    Y0 = Bin[idx_y++];
    Y1 = Bin[idx_y++];
    Y2 = Bin[idx_y++];
    Y3 = Bin[idx_y++];

    SALSA20_8_XOR ();

    Bout[idx_r1++] = R0;
    Bout[idx_r1++] = R1;
    Bout[idx_r1++] = R2;
    Bout[idx_r1++] = R3;

    Y0 = Bin[idx_y++];
    Y1 = Bin[idx_y++];
    Y2 = Bin[idx_y++];
    Y3 = Bin[idx_y++];

    SALSA20_8_XOR ();

    Bout[idx_r2++] = R0;
    Bout[idx_r2++] = R1;
    Bout[idx_r2++] = R2;
    Bout[idx_r2++] = R3;
  }
}

static inline uint32_t scrypt_get_key (__m128i *B, const uint32_t r)
{
  const uint32_t state_cnt = GET_STATE_CNT (r);

  const uint32_t state_cnt4 = state_cnt / 4;

  uint32_t *key = (uint32_t *) &B[state_cnt4 - 4];

  return key[0];
}

static void scrypt_smix (uint32_t *B, const uint32_t r, const uint32_t N, __m128i *V, __m128i *X, __m128i *Y)
{
  const uint32_t state_cnt = GET_STATE_CNT (r);

  const uint32_t state_cnt4 = state_cnt / 4;

  uint32_t *X32 = (uint32_t *) X;

  uint32_t i;
  uint32_t k;

  for (k = 0; k < 2 * r; k++)
  {
    const uint32_t k16 = k * 16;

    X32[k16 +  0] = B[k16 +  0];
    X32[k16 +  1] = B[k16 +  5];
    X32[k16 +  2] = B[k16 + 10];
    X32[k16 +  3] = B[k16 + 15];
    X32[k16 +  4] = B[k16 +  4];
    X32[k16 +  5] = B[k16 +  9];
    X32[k16 +  6] = B[k16 + 14];
    X32[k16 +  7] = B[k16 +  3];
    X32[k16 +  8] = B[k16 +  8];
    X32[k16 +  9] = B[k16 + 13];
    X32[k16 + 10] = B[k16 +  2];
    X32[k16 + 11] = B[k16 +  7];
    X32[k16 + 12] = B[k16 + 12];
    X32[k16 + 13] = B[k16 +  1];
    X32[k16 + 14] = B[k16 +  6];
    X32[k16 + 15] = B[k16 + 11];
  }

  for (i = 0; i < N; i += 2)
  {
    const uint32_t i0_state4 = (i + 0) * state_cnt4;
    const uint32_t i1_state4 = (i + 1) * state_cnt4;

    for (k = 0; k < state_cnt4; k++)
    {
      V[i0_state4 + k] = X[k];
    }

    scrypt_blockmix_salsa8 (X, Y, r);

    for (k = 0; k < state_cnt4; k++)
    {
      V[i1_state4 + k] = Y[k];
    }

    scrypt_blockmix_salsa8 (Y, X, r);
  }

  for (i = 0; i < N; i += 2)
  {
    const uint32_t keyX = scrypt_get_key (X, r) & (N - 1);

    const uint32_t keyX_state4 = keyX * state_cnt4;

    for (k = 0; k < state_cnt4; k++)
    {
      X[k] ^= V[keyX_state4 + k];
    }

    scrypt_blockmix_salsa8 (X, Y, r);

    const uint32_t keyY = scrypt_get_key (Y, r) & (N - 1);

    const uint32_t keyY_state4 = keyY * state_cnt4;

    for (k = 0; k < state_cnt4; k++)
    {
      Y[k] ^= V[keyY_state4 + k];
    }

    scrypt_blockmix_salsa8 (Y, X, r);
  }

  for (k = 0; k < 2 * r; k++)
  {
    const uint32_t k16 = k * 16;

    B[k16 +  0] = X32[k16 +  0];
    B[k16 +  5] = X32[k16 +  1];
    B[k16 + 10] = X32[k16 +  2];
    B[k16 + 15] = X32[k16 +  3];
    B[k16 +  4] = X32[k16 +  4];
    B[k16 +  9] = X32[k16 +  5];
    B[k16 + 14] = X32[k16 +  6];
    B[k16 +  3] = X32[k16 +  7];
    B[k16 +  8] = X32[k16 +  8];
    B[k16 + 13] = X32[k16 +  9];
    B[k16 +  2] = X32[k16 + 10];
    B[k16 +  7] = X32[k16 + 11];
    B[k16 + 12] = X32[k16 + 12];
    B[k16 +  1] = X32[k16 + 13];
    B[k16 +  6] = X32[k16 + 14];
    B[k16 + 11] = X32[k16 + 15];
  }
}

void hashing_08400 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains1[4];

  char *ptrs1[4];

  ptrs1[0] = (char *) &plains1[0].buf;
  ptrs1[1] = (char *) &plains1[1].buf;
  ptrs1[2] = (char *) &plains1[2].buf;
  ptrs1[3] = (char *) &plains1[3].buf;

  plain_t plains2[4];

  char *ptrs2[4];

  ptrs2[0] = (char *) &plains2[0].buf;
  ptrs2[1] = (char *) &plains2[1].buf;
  ptrs2[2] = (char *) &plains2[2].buf;
  ptrs2[3] = (char *) &plains2[3].buf;

  plain_t plains3[4];

  db_t *db = thread_parameter->db;

  // 1st sha1

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (in, &digests);

  transpose_sha1_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    uint_to_hex_lower (dgst[i].buf.sha1[0], &ptrs1[i][0]);
    uint_to_hex_lower (dgst[i].buf.sha1[1], &ptrs1[i][8]);
    uint_to_hex_lower (dgst[i].buf.sha1[2], &ptrs1[i][16]);
    uint_to_hex_lower (dgst[i].buf.sha1[3], &ptrs1[i][24]);
    uint_to_hex_lower (dgst[i].buf.sha1[4], &ptrs1[i][32]);

    plains1[i].len = 40;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    // 2nd sha1

    sha1_init_sse2 (&digests);

    plain_init (plains2);

    sha1_update_sse2 (plains2, &digests, salt->salt_plain_struct);

    sha1_update_sse2 (plains2, &digests, plains1);

    sha1_final_sse2 (plains2, &digests);

    transpose_sha1_digest (&digests, dgst);

    for (i = 0; i < 4; i++)
    {
      uint_to_hex_lower (dgst[i].buf.sha1[0], &ptrs2[i][0]);
      uint_to_hex_lower (dgst[i].buf.sha1[1], &ptrs2[i][8]);
      uint_to_hex_lower (dgst[i].buf.sha1[2], &ptrs2[i][16]);
      uint_to_hex_lower (dgst[i].buf.sha1[3], &ptrs2[i][24]);
      uint_to_hex_lower (dgst[i].buf.sha1[4], &ptrs2[i][32]);

      plains2[i].len = 40;
    }

    // 3rd time

    sha1_init_sse2 (&digests);

    plain_init (plains3);

    sha1_update_sse2 (plains3, &digests, salt->salt_plain_struct);

    sha1_update_sse2 (plains3, &digests, plains2);

    sha1_final_sse2 (plains3, &digests);

    transpose_sha1_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_08900 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  plain_t plains_tmp[4];

  char *ptrs_tmp[4];

  ptrs_tmp[0] = (char *) &plains_tmp[0].buf;
  ptrs_tmp[1] = (char *) &plains_tmp[1].buf;
  ptrs_tmp[2] = (char *) &plains_tmp[2].buf;
  ptrs_tmp[3] = (char *) &plains_tmp[3].buf;

  db_t *db = thread_parameter->db;

  uint32_t **P = thread_parameter->scrypt_P;

  __m128i *V = thread_parameter->scrypt_V;
  __m128i *X = thread_parameter->scrypt_X;
  __m128i *Y = thread_parameter->scrypt_Y;

  /**
   * start
   */

  uint32_t ipad[8][4] __attribute__ ((aligned (16)));
  uint32_t opad[8][4] __attribute__ ((aligned (16)));

  uint32_t ipad_buf[16][4] __attribute__ ((aligned (16)));
  uint32_t opad_buf[16][4] __attribute__ ((aligned (16)));

  uint32_t i;
  uint32_t j;

  for (i = 0; i < 4; i++)
  {
    for (j = 0; j < 16; j++)
    {
      ipad_buf[j][i] = 0x36363636 ^ plains[i].buf[j];
      opad_buf[j][i] = 0x5c5c5c5c ^ plains[i].buf[j];
    }

    ipad[0][i] = SHA256M_A;
    ipad[1][i] = SHA256M_B;
    ipad[2][i] = SHA256M_C;
    ipad[3][i] = SHA256M_D;
    ipad[4][i] = SHA256M_E;
    ipad[5][i] = SHA256M_F;
    ipad[6][i] = SHA256M_G;
    ipad[7][i] = SHA256M_H;

    opad[0][i] = SHA256M_A;
    opad[1][i] = SHA256M_B;
    opad[2][i] = SHA256M_C;
    opad[3][i] = SHA256M_D;
    opad[4][i] = SHA256M_E;
    opad[5][i] = SHA256M_F;
    opad[6][i] = SHA256M_G;
    opad[7][i] = SHA256M_H;
  }

  hashcat_sha256_64 ((__m128i *) ipad, (__m128i *) ipad_buf);
  hashcat_sha256_64 ((__m128i *) opad, (__m128i *) opad_buf);

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    uint32_t N = salt->scrypt_N;
    uint32_t r = salt->scrypt_r;
    uint32_t p = salt->scrypt_p;

    const uint32_t scrypt_cnt = GET_SCRYPT_CNT (r, p);
    const uint32_t state_cnt  = GET_STATE_CNT (r);

    /**
     * init hmac
     */

    uint32_t tmp[8][4] __attribute__ ((aligned (16)));

    uint32_t l;
    uint32_t m;

    for (l = 0, m = 1; l < scrypt_cnt; l += 8, m += 1)
    {
      for (i = 0; i < 4; i++)
      {
        tmp[0][i] = ipad[0][i];
        tmp[1][i] = ipad[1][i];
        tmp[2][i] = ipad[2][i];
        tmp[3][i] = ipad[3][i];
        tmp[4][i] = ipad[4][i];
        tmp[5][i] = ipad[5][i];
        tmp[6][i] = ipad[6][i];
        tmp[7][i] = ipad[7][i];
      }

      for (i = 0; i < 4; i++)
      {
        memcpy (ptrs_tmp[i], salt->salt_plain_buf, salt->salt_plain_len);

        memset (ptrs_tmp[i] + salt->salt_plain_len, 0, BLOCK_SIZE - salt->salt_plain_len);

        ptrs_tmp[i][salt->salt_plain_len + 0] = (m >> 24) & 0xff;
        ptrs_tmp[i][salt->salt_plain_len + 1] = (m >> 16) & 0xff;
        ptrs_tmp[i][salt->salt_plain_len + 2] = (m >>  8) & 0xff;
        ptrs_tmp[i][salt->salt_plain_len + 3] = (m >>  0) & 0xff;
        ptrs_tmp[i][salt->salt_plain_len + 4] = 0x80;

        for (j = 0; j < 14; j++) ipad_buf[j][i] = plains_tmp[i].buf[j];

        ipad_buf[14][i] = 0;
        ipad_buf[15][i] = (64 + salt->salt_plain_len + 4) * 8;

        BYTESWAP (ipad_buf[15][i]);
      }

      hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

      for (i = 0; i < 4; i++)
      {
        opad_buf[ 0][i] = tmp[0][i];
        opad_buf[ 1][i] = tmp[1][i];
        opad_buf[ 2][i] = tmp[2][i];
        opad_buf[ 3][i] = tmp[3][i];
        opad_buf[ 4][i] = tmp[4][i];
        opad_buf[ 5][i] = tmp[5][i];
        opad_buf[ 6][i] = tmp[6][i];
        opad_buf[ 7][i] = tmp[7][i];
        opad_buf[ 8][i] = 0x80;
        opad_buf[ 9][i] = 0;
        opad_buf[10][i] = 0;
        opad_buf[11][i] = 0;
        opad_buf[12][i] = 0;
        opad_buf[13][i] = 0;
        opad_buf[14][i] = 0;
        opad_buf[15][i] = (64 + 32) * 8;

        BYTESWAP (opad_buf[ 0][i]);
        BYTESWAP (opad_buf[ 1][i]);
        BYTESWAP (opad_buf[ 2][i]);
        BYTESWAP (opad_buf[ 3][i]);
        BYTESWAP (opad_buf[ 4][i]);
        BYTESWAP (opad_buf[ 5][i]);
        BYTESWAP (opad_buf[ 6][i]);
        BYTESWAP (opad_buf[ 7][i]);
        BYTESWAP (opad_buf[15][i]);
      }

      for (i = 0; i < 4; i++)
      {
        tmp[0][i] = opad[0][i];
        tmp[1][i] = opad[1][i];
        tmp[2][i] = opad[2][i];
        tmp[3][i] = opad[3][i];
        tmp[4][i] = opad[4][i];
        tmp[5][i] = opad[5][i];
        tmp[6][i] = opad[6][i];
        tmp[7][i] = opad[7][i];
      }

      hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) opad_buf);

      for (i = 0; i < 4; i++)
      {
        BYTESWAP (tmp[0][i]);
        BYTESWAP (tmp[1][i]);
        BYTESWAP (tmp[2][i]);
        BYTESWAP (tmp[3][i]);
        BYTESWAP (tmp[4][i]);
        BYTESWAP (tmp[5][i]);
        BYTESWAP (tmp[6][i]);
        BYTESWAP (tmp[7][i]);
      }

      for (i = 0; i < 4; i++)
      {
        P[i][l + 0] = tmp[0][i];
        P[i][l + 1] = tmp[1][i];
        P[i][l + 2] = tmp[2][i];
        P[i][l + 3] = tmp[3][i];
        P[i][l + 4] = tmp[4][i];
        P[i][l + 5] = tmp[5][i];
        P[i][l + 6] = tmp[6][i];
        P[i][l + 7] = tmp[7][i];
      }
    }

    /*
     * salsa8 stuff
     */

    for (i = 0; i < p; i++)
    {
      scrypt_smix (&P[0][i * state_cnt], r, N, V, X, Y);
    }

    for (i = 0; i < p; i++)
    {
      scrypt_smix (&P[1][i * state_cnt], r, N, V, X, Y);
    }

    for (i = 0; i < p; i++)
    {
      scrypt_smix (&P[2][i * state_cnt], r, N, V, X, Y);
    }

    for (i = 0; i < p; i++)
    {
      scrypt_smix (&P[3][i * state_cnt], r, N, V, X, Y);
    }

    /*
     * final pbkdf2
     */

    for (i = 0; i < 4; i++)
    {
      tmp[0][i] = ipad[0][i];
      tmp[1][i] = ipad[1][i];
      tmp[2][i] = ipad[2][i];
      tmp[3][i] = ipad[3][i];
      tmp[4][i] = ipad[4][i];
      tmp[5][i] = ipad[5][i];
      tmp[6][i] = ipad[6][i];
      tmp[7][i] = ipad[7][i];
    }

    for (l = 0; l < scrypt_cnt; l += 16)
    {
      for (i = 0; i < 4; i++)
      {
        ipad_buf[ 0][i] = P[i][l +  0];
        ipad_buf[ 1][i] = P[i][l +  1];
        ipad_buf[ 2][i] = P[i][l +  2];
        ipad_buf[ 3][i] = P[i][l +  3];
        ipad_buf[ 4][i] = P[i][l +  4];
        ipad_buf[ 5][i] = P[i][l +  5];
        ipad_buf[ 6][i] = P[i][l +  6];
        ipad_buf[ 7][i] = P[i][l +  7];
        ipad_buf[ 8][i] = P[i][l +  8];
        ipad_buf[ 9][i] = P[i][l +  9];
        ipad_buf[10][i] = P[i][l + 10];
        ipad_buf[11][i] = P[i][l + 11];
        ipad_buf[12][i] = P[i][l + 12];
        ipad_buf[13][i] = P[i][l + 13];
        ipad_buf[14][i] = P[i][l + 14];
        ipad_buf[15][i] = P[i][l + 15];
      }

      hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) ipad_buf);
    }

    for (i = 0; i < 4; i++)
    {
      ipad_buf[ 0][i] = 0x01000000;
      ipad_buf[ 1][i] = 0x80;
      ipad_buf[ 2][i] = 0;
      ipad_buf[ 3][i] = 0;
      ipad_buf[ 4][i] = 0;
      ipad_buf[ 5][i] = 0;
      ipad_buf[ 6][i] = 0;
      ipad_buf[ 7][i] = 0;
      ipad_buf[ 8][i] = 0;
      ipad_buf[ 9][i] = 0;
      ipad_buf[10][i] = 0;
      ipad_buf[11][i] = 0;
      ipad_buf[12][i] = 0;
      ipad_buf[13][i] = 0;
      ipad_buf[14][i] = 0;
      ipad_buf[15][i] = (64 + (scrypt_cnt * 4) + 4) * 8;

      BYTESWAP (ipad_buf[15][i]);
    }

    hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) ipad_buf);

    for (i = 0; i < 4; i++)
    {
      opad_buf[ 0][i] = tmp[0][i];
      opad_buf[ 1][i] = tmp[1][i];
      opad_buf[ 2][i] = tmp[2][i];
      opad_buf[ 3][i] = tmp[3][i];
      opad_buf[ 4][i] = tmp[4][i];
      opad_buf[ 5][i] = tmp[5][i];
      opad_buf[ 6][i] = tmp[6][i];
      opad_buf[ 7][i] = tmp[7][i];
      opad_buf[ 8][i] = 0x80;
      opad_buf[ 9][i] = 0;
      opad_buf[10][i] = 0;
      opad_buf[11][i] = 0;
      opad_buf[12][i] = 0;
      opad_buf[13][i] = 0;
      opad_buf[14][i] = 0;
      opad_buf[15][i] = (64 + 32) * 8;

      BYTESWAP (opad_buf[ 0][i]);
      BYTESWAP (opad_buf[ 1][i]);
      BYTESWAP (opad_buf[ 2][i]);
      BYTESWAP (opad_buf[ 3][i]);
      BYTESWAP (opad_buf[ 4][i]);
      BYTESWAP (opad_buf[ 5][i]);
      BYTESWAP (opad_buf[ 6][i]);
      BYTESWAP (opad_buf[ 7][i]);
      BYTESWAP (opad_buf[15][i]);
    }

    for (i = 0; i < 4; i++)
    {
      tmp[0][i] = opad[0][i];
      tmp[1][i] = opad[1][i];
      tmp[2][i] = opad[2][i];
      tmp[3][i] = opad[3][i];
      tmp[4][i] = opad[4][i];
      tmp[5][i] = opad[5][i];
      tmp[6][i] = opad[6][i];
      tmp[7][i] = opad[7][i];
    }

    hashcat_sha256_64 ((__m128i *) tmp, (__m128i *) opad_buf);

    for (i = 0; i < 4; i++)
    {
      digests[i].buf.sha256[0] = tmp[0][i];
      digests[i].buf.sha256[1] = tmp[1][i];
      digests[i].buf.sha256[2] = tmp[2][i];
      digests[i].buf.sha256[3] = tmp[3][i];
      digests[i].buf.sha256[4] = tmp[4][i];
      digests[i].buf.sha256[5] = tmp[5][i];
      digests[i].buf.sha256[6] = tmp[6][i];
      digests[i].buf.sha256[7] = tmp[7][i];
    }

    thread_parameter->indb (thread_parameter, plains, digests, salt);
  }
}

void hashing_09900 (thread_parameter_t *thread_parameter, plain_t *in)
{
  // hack: because md5_update_sse2 () only allows in[x].len <= 64

  db_t *db = thread_parameter->db;

  plain_t plains_tmp[4];

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    memset (plains_tmp[i].buf, 0, 100);
  }

  plain_t plains[4];

  plain_init (plains);

  // first the actual password

  digest_md5_sse2_t digests;

  md5_init_sse2 (&digests);

  md5_update_sse2 (plains, &digests, in);

  // remaining bytes: 100 - in[x].len

  for (i = 0; i < 4; i++)
  {
    plains_tmp[i].len = 100 - in[i].len;
  }

  md5_update_sse2 (plains, &digests, plains_tmp); // at most 64

  md5_final_sse2 (plains, &digests); // if something is left, we handle it here

  digest_t dgst[4];

  transpose_md5_digest (&digests, dgst);

  thread_parameter->indb (thread_parameter, in, dgst, db->salts_buf[0]);
}

void hashing_10300 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  db_t *db = thread_parameter->db;

  plain_t plains[4];

  plain_t plains_tmp[4];

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    // initial sha1 ($pass.$salt)

    plain_init (plains);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains, in);

    sha1_update_sse2_max55 (plains, salt->salt_plain_struct);

    sha1_final_sse2_max55 (plains, &digests);

    transpose_sha1_digest (&digests, dgst);

    uint32_t cnt;

    for (cnt = 0; cnt < salt->iterations - 1; cnt++)
    {
      // loop with both: $pass + 20 bit digest

      uint32_t i;

      for (i = 0; i < 4; i++)
      {
        memcpy (plains_tmp[i].buf, dgst[i].buf.sha1, 20);

        BYTESWAP (plains_tmp[i].buf[0]);
        BYTESWAP (plains_tmp[i].buf[1]);
        BYTESWAP (plains_tmp[i].buf[2]);
        BYTESWAP (plains_tmp[i].buf[3]);
        BYTESWAP (plains_tmp[i].buf[4]);

        plains_tmp[i].len = 20;
      }

      plain_init (plains);

      sha1_init_sse2 (&digests);

      // pass

      sha1_update_sse2 (plains, &digests, in);

      // previous digest

      sha1_update_sse2 (plains, &digests, plains_tmp);

      sha1_final_sse2 (plains, &digests);

      transpose_sha1_digest (&digests, dgst);
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_11000 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    plain_init (plains);

    md5_init_sse2 (&digests);

    md5_update_sse2 (plains, &digests, salt->salt_plain_struct);

    md5_update_sse2 (plains, &digests, in);

    md5_final_sse2 (plains, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_11100 (thread_parameter_t *thread_parameter, plain_t *in)
{
  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains1[4];

  char *ptrs[4];

  ptrs[0] = (char *) &plains1[0].buf;
  ptrs[1] = (char *) &plains1[1].buf;
  ptrs[2] = (char *) &plains1[2].buf;
  ptrs[3] = (char *) &plains1[3].buf;

  plain_t plains2[4];

  db_t *db = thread_parameter->db;

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    // $hash = md5 ($pass.$user_name)

    plain_init (plains1);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains1, in);

    md5_update_sse2_max55 (plains1, salt->additional_plain_struct);

    md5_final_sse2_max55 (plains1, &digests);

    transpose_md5_digest (&digests, dgst);

    uint32_t i;

    for (i = 0; i < 4; i++)
    {
      BYTESWAP (dgst[i].buf.md5[0]);
      BYTESWAP (dgst[i].buf.md5[1]);
      BYTESWAP (dgst[i].buf.md5[2]);
      BYTESWAP (dgst[i].buf.md5[3]);

      uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs[i][0]);
      uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs[i][8]);
      uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs[i][16]);
      uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs[i][24]);

      plains1[i].len = 32;
    }

    // md5 ($hash.$salt)

    plain_init (plains2);

    md5_init_sse2 (&digests);

    md5_update_sse2_max55 (plains2, plains1);

    md5_update_sse2_max55 (plains2, salt->salt_plain_struct);

    md5_final_sse2_max55 (plains2, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_11200 (thread_parameter_t *thread_parameter, plain_t *in)
{
  db_t *db = thread_parameter->db;

  digest_sha1_sse2_t digests;

  digest_t dgst[4];

  plain_t plains1[4];

  uint32_t *ptrs1[4];

  ptrs1[0] = (uint32_t *) &plains1[0].buf;
  ptrs1[1] = (uint32_t *) &plains1[1].buf;
  ptrs1[2] = (uint32_t *) &plains1[2].buf;
  ptrs1[3] = (uint32_t *) &plains1[3].buf;

  plain_t plains1_swapped[4];

  uint32_t *ptrs1_swapped[4];

  ptrs1_swapped[0] = (uint32_t *) &plains1_swapped[0].buf;
  ptrs1_swapped[1] = (uint32_t *) &plains1_swapped[1].buf;
  ptrs1_swapped[2] = (uint32_t *) &plains1_swapped[2].buf;
  ptrs1_swapped[3] = (uint32_t *) &plains1_swapped[3].buf;

  plain_t plains2[4];

  uint32_t *ptrs2[4];

  ptrs2[0] = (uint32_t *) &plains2[0].buf;
  ptrs2[1] = (uint32_t *) &plains2[1].buf;
  ptrs2[2] = (uint32_t *) &plains2[2].buf;
  ptrs2[3] = (uint32_t *) &plains2[3].buf;

  plain_t plains3[4];

  // sha1 ($pass)

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (in, &digests);

  transpose_sha1_digest (&digests, dgst);

  uint32_t i;

  for (i = 0; i < 4; i++)
  {
    ptrs1[i][0] = dgst[i].buf.sha1[0];
    ptrs1[i][1] = dgst[i].buf.sha1[1];
    ptrs1[i][2] = dgst[i].buf.sha1[2];
    ptrs1[i][3] = dgst[i].buf.sha1[3];
    ptrs1[i][4] = dgst[i].buf.sha1[4];

    BYTESWAP (dgst[i].buf.sha1[0]);
    BYTESWAP (dgst[i].buf.sha1[1]);
    BYTESWAP (dgst[i].buf.sha1[2]);
    BYTESWAP (dgst[i].buf.sha1[3]);
    BYTESWAP (dgst[i].buf.sha1[4]);

    ptrs1_swapped[i][0] = dgst[i].buf.sha1[0];
    ptrs1_swapped[i][1] = dgst[i].buf.sha1[1];
    ptrs1_swapped[i][2] = dgst[i].buf.sha1[2];
    ptrs1_swapped[i][3] = dgst[i].buf.sha1[3];
    ptrs1_swapped[i][4] = dgst[i].buf.sha1[4];

    plains1_swapped[i].len = 20;
  }

  // sha1 (sha1 ($pass))

  sha1_init_sse2 (&digests);

  sha1_final_sse2_max55 (plains1_swapped, &digests);

  transpose_sha1_digest (&digests, dgst);

  for (i = 0; i < 4; i++)
  {
    BYTESWAP (dgst[i].buf.sha1[0]);
    BYTESWAP (dgst[i].buf.sha1[1]);
    BYTESWAP (dgst[i].buf.sha1[2]);
    BYTESWAP (dgst[i].buf.sha1[3]);
    BYTESWAP (dgst[i].buf.sha1[4]);

    ptrs2[i][0] = dgst[i].buf.sha1[0];
    ptrs2[i][1] = dgst[i].buf.sha1[1];
    ptrs2[i][2] = dgst[i].buf.sha1[2];
    ptrs2[i][3] = dgst[i].buf.sha1[3];
    ptrs2[i][4] = dgst[i].buf.sha1[4];

    plains2[i].len = 20;
  }

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    // sha1 ($salt . sha1 (sha1 ($pass)))

    plain_init (plains3);

    sha1_init_sse2 (&digests);

    sha1_update_sse2_max55 (plains3, salt->salt_plain_struct);
    sha1_update_sse2_max55 (plains3, plains2);

    sha1_final_sse2_max55 (plains3, &digests);

    transpose_sha1_digest (&digests, dgst);

    // the XOR:
    // sha1 ($pass)  XOR  sha1 ($salt . sha1 (sha1 ($pass)))

    for (i = 0; i < 4; i++)
    {
      dgst[i].buf.sha1[0] ^= ptrs1[i][0];
      dgst[i].buf.sha1[1] ^= ptrs1[i][1];
      dgst[i].buf.sha1[2] ^= ptrs1[i][2];
      dgst[i].buf.sha1[3] ^= ptrs1[i][3];
      dgst[i].buf.sha1[4] ^= ptrs1[i][4];
    }

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_11400 (thread_parameter_t *thread_parameter, plain_t *in)
{
  db_t *db = thread_parameter->db;

  digest_md5_sse2_t digests;

  digest_t dgst[4];

  plain_t plains1[4];

  char *ptrs1[4];

  ptrs1[0] = (char *) &plains1[0].buf;
  ptrs1[1] = (char *) &plains1[1].buf;
  ptrs1[2] = (char *) &plains1[2].buf;
  ptrs1[3] = (char *) &plains1[3].buf;

  plain_t plains2[4];

  plain_t plains3[4];

  uint32_t salts_idx;

  for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
  {
    salt_t *salt = db->salts_buf[salts_idx];

    if (salt->indexes_found == salt->indexes_cnt) continue;

    // HA1 = md5_max55 ($additional_plain_struct . $pass)

    plain_init (plains1);

    md5_init_sse2 (&digests);

    uint32_t i;

    uint remaining_size = salt->additional_plain_struct->len;

    uint8_t *salt_plain_struct_ptr = (uint8_t *) salt->additional_plain_struct->buf8;

    while (remaining_size > 0)
    {
      uint current_size = MIN (63, remaining_size);

      // set plains3

      for (i = 0; i < 4; i++)
      {
        memcpy (plains3[i].buf8, salt_plain_struct_ptr, current_size);

        plains3[i].len = current_size;
      }

      // MD5

      md5_update_sse2 (plains1, &digests, plains3);

      // update size and offset

      remaining_size -= current_size;
      salt_plain_struct_ptr += current_size;
    }

    md5_update_sse2 (plains1, &digests, in);

    md5_final_sse2 (plains1, &digests);

    transpose_md5_digest (&digests, dgst);

    for (i = 0; i < 4; i++)
    {
      BYTESWAP (dgst[i].buf.md5[0]);
      BYTESWAP (dgst[i].buf.md5[1]);
      BYTESWAP (dgst[i].buf.md5[2]);
      BYTESWAP (dgst[i].buf.md5[3]);

      uint_to_hex_lower (dgst[i].buf.md5[0], &ptrs1[i][0]);
      uint_to_hex_lower (dgst[i].buf.md5[1], &ptrs1[i][8]);
      uint_to_hex_lower (dgst[i].buf.md5[2], &ptrs1[i][16]);
      uint_to_hex_lower (dgst[i].buf.md5[3], &ptrs1[i][24]);

      plains1[i].len = 32;
    }

    // HA2 = md5 ($HA1 . $salt)

    plain_init (plains2);

    md5_init_sse2 (&digests);

    md5_update_sse2 (plains2, &digests, plains1);

    remaining_size = salt->salt_plain_struct->len;

    salt_plain_struct_ptr = (uint8_t *) salt->salt_plain_struct->buf8;

    while (remaining_size > 0)
    {
      uint current_size = MIN (63, remaining_size);

      // set plains3

      for (i = 0; i < 4; i++)
      {
        memcpy (plains3[i].buf8, salt_plain_struct_ptr, current_size);

        plains3[i].len = current_size;
      }

      // MD5

      md5_update_sse2 (plains2, &digests, plains3);

      // update size and offset

      remaining_size -= current_size;
      salt_plain_struct_ptr += current_size;
    }

    md5_final_sse2 (plains2, &digests);

    transpose_md5_digest (&digests, dgst);

    thread_parameter->indb (thread_parameter, in, dgst, salt);
  }
}

void hashing_99999 (thread_parameter_t *thread_parameter, plain_t *plains)
{
  digest_t digests[4];

  memcpy (digests[0].buf.plain, plains[0].buf, plains[0].len);
  memcpy (digests[1].buf.plain, plains[1].buf, plains[1].len);
  memcpy (digests[2].buf.plain, plains[2].buf, plains[2].len);
  memcpy (digests[3].buf.plain, plains[3].buf, plains[3].len);

  memset (digests[0].buf.plain + plains[0].len, 0, DIGEST_SIZE_PLAIN - plains[0].len);
  memset (digests[1].buf.plain + plains[1].len, 0, DIGEST_SIZE_PLAIN - plains[1].len);
  memset (digests[2].buf.plain + plains[2].len, 0, DIGEST_SIZE_PLAIN - plains[2].len);
  memset (digests[3].buf.plain + plains[3].len, 0, DIGEST_SIZE_PLAIN - plains[3].len);

  db_t *db = thread_parameter->db;

  thread_parameter->indb (thread_parameter, plains, digests, db->salts_buf[0]);
}

void mp_exec (uint64_t val, uint8_t *buf, cs_t *css, int css_cnt)
{
  do
  {
    const cs_t *cs = css++;

    uint32_t len  = cs->cs_len;

    uint64_t next = val / len;
    uint32_t pos  = val % len;

    const uint8_t c = (uint8_t) cs->cs_buf[pos];

    *buf++ = c;

    val = next;

  } while (--css_cnt);
}

void mp_incr (uint64_t cur, uint64_t next, uint8_t *buf, cs_t *css, int css_cnt)
{
  do
  {
    const cs_t *cs = css++;

    uint32_t cs_len = cs->cs_len;

    uint64_t next_mod = next % cs_len;

    const uint8_t c = (uint8_t) cs->cs_buf[next_mod];

    *buf++ = c;

    uint64_t cur_div  = cur  / cs_len;
    uint64_t next_div = next / cs_len;

    if (cur_div == next_div) break;

    cur  = cur_div;
    next = next_div;

  } while (--css_cnt);
}

uint32_t next_permutation (char *word, uint32_t *p, uint32_t k)
{
  p[k]--;

  uint32_t j = k % 2 * p[k];

  char tmp = word[j];

  word[j] = word[k];

  word[k] = tmp;

  for (k = 1; p[k] == 0; k++)
  {
    p[k] = k;
  }

  return k;
}

uint32_t next_tbl (uint8_t *pw_buf, uint32_t v, tbl_t *tbls_buf[BLOCK_SIZE], uint32_t tbls_cnt)
{
  uint32_t pw_len = 0;

  uint32_t i;

  for (i = 0; i < tbls_cnt; i++)
  {
    const uint32_t tbl_cnt = tbls_buf[i]->tbl_cnt;

    const uint32_t mod = v % tbl_cnt;
    const uint32_t div = v / tbl_cnt;

    v = div;

    hc_wchar_t *hc_wchar_ptr = (hc_wchar_t *) &tbls_buf[i]->tbl_buf[mod];

    memcpy (pw_buf + pw_len, hc_wchar_ptr->w_buf, hc_wchar_ptr->w_len);

    pw_len += hc_wchar_ptr->w_len;
  }

  return pw_len;
}

void transform_netntlmv1_key (const uint8_t *nthash, uint8_t *key)
{
  key[0] =                    (nthash[0] >> 0);
  key[1] = (nthash[0] << 7) | (nthash[1] >> 1);
  key[2] = (nthash[1] << 6) | (nthash[2] >> 2);
  key[3] = (nthash[2] << 5) | (nthash[3] >> 3);
  key[4] = (nthash[3] << 4) | (nthash[4] >> 4);
  key[5] = (nthash[4] << 3) | (nthash[5] >> 5);
  key[6] = (nthash[5] << 2) | (nthash[6] >> 6);
  key[7] = (nthash[6] << 1);

  key[0] |= 0x01;
  key[1] |= 0x01;
  key[2] |= 0x01;
  key[3] |= 0x01;
  key[4] |= 0x01;
  key[5] |= 0x01;
  key[6] |= 0x01;
  key[7] |= 0x01;
}

void *attack_a5r1 ()
{
  log_info ("Custom-Table-Lookup with rules not supported");

  return (NULL);
}

void *attack_a5r0 (thread_parameter_t *thread_parameter)
{
  plain_t plains[4];

  char *ptrs[4];

  memset (plains, 0, sizeof (plains));

  if (thread_parameter->hash_type == HASH_TYPE_SHA512 || thread_parameter->hash_type == HASH_TYPE_SHA512UNIX || thread_parameter->hash_type == HASH_TYPE_MSSQL2012 || thread_parameter->hash_type == HASH_TYPE_KECCAK || thread_parameter->hash_type == HASH_TYPE_SHA512AIX || thread_parameter->hash_type == HASH_TYPE_PBKDF2OSX || thread_parameter->hash_type == HASH_TYPE_PBKDF2GRUB || thread_parameter->hash_type == HASH_TYPE_DRUPAL7)
  {
    ptrs[0] = (char *) &plains[0].buf64;
    ptrs[1] = (char *) &plains[1].buf64;
    ptrs[2] = (char *) &plains[2].buf64;
    ptrs[3] = (char *) &plains[3].buf64;
  }
  else
  {
    ptrs[0] = (char *) &plains[0].buf;
    ptrs[1] = (char *) &plains[1].buf;
    ptrs[2] = (char *) &plains[2].buf;
    ptrs[3] = (char *) &plains[3].buf;
  }

  words_t *words = thread_parameter->db->words;

  uint64_t words_skip  = (thread_parameter->thread_words_skip == 0) ? 0 : thread_parameter->thread_words_skip;
  uint64_t words_limit = (thread_parameter->thread_words_limit == 0) ? words->words_cnt : MIN ((thread_parameter->thread_words_skip + thread_parameter->thread_words_limit), words->words_cnt);
  uint64_t words_todo  = words_limit - words_skip;
  uint64_t words_steps = words_todo / thread_parameter->num_threads;
  uint64_t words_left  = words_todo % thread_parameter->num_threads;

  words_skip += words_steps * thread_parameter->thread_id;

  if ((thread_parameter->thread_id + 1) == thread_parameter->num_threads)

  words_steps += words_left;

  uint64_t words_cur;

  for (words_cur = 0; words_cur < words_steps; words_cur++, thread_parameter->thread_words_done++)
  {
    while (*thread_parameter->hashcat_status == STATUS_PAUSED) hc_sleep (1);

    uint64_t words_next = words_skip + words_cur;

    tbl_t *tbls_buf[BLOCK_SIZE];

    uint32_t tbls_cnt = words->words_len[words_next];

    uint32_t total = 1;

    uint32_t j;

    for (j = 0; j < tbls_cnt; j++)
    {
      uint8_t c = words->words_buf[words_next][j];

      tbls_buf[j] = &thread_parameter->table_buf[c];

      total *= tbls_buf[j]->tbl_cnt;
    }

    uint32_t i;

    for (i = 0; i < total; i += 4)
    {
      uint32_t left = ((i + 4) < total) ? 4 : total - i;

      uint32_t j;

      for (j = 0; j < left; j++)
      {
        uint32_t len = next_tbl ((uint8_t *) ptrs[j], i + j, tbls_buf, tbls_cnt);

        plains[j].len = len;

        plains[j].pos = thread_parameter->thread_plains_done + j; // TODO: needs verification

        memset (ptrs[j] + plains[j].len, 0, BLOCK_SIZE - plains[j].len);
      }

      for (; j < 4; j++)
      {
        memset (ptrs[j], 0, BLOCK_SIZE);

        plains[j].len = 0;
      }

      thread_parameter->hashing (thread_parameter, plains);

      thread_parameter->thread_plains_done += left;
    }

    if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
    if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
  }

  if ((*thread_parameter->hashcat_status != STATUS_QUIT) && (*thread_parameter->hashcat_status != STATUS_BYPASS))
  {
    thread_parameter->thread_words_done = words_steps;

    thread_parameter->thread_plains_done = words_steps;
  }

  return (NULL);
}

void *attack_a4r1 ()
{
  log_info ("Custom-Brute-Force with rules not supported");

  return (NULL);
}

void *attack_a4r0 (thread_parameter_t *thread_parameter)
{
  plain_t plains[4];

  char *ptrs[4];

  memset (plains, 0, sizeof (plains));

  if (thread_parameter->hash_type == HASH_TYPE_SHA512 || thread_parameter->hash_type == HASH_TYPE_SHA512UNIX || thread_parameter->hash_type == HASH_TYPE_MSSQL2012 || thread_parameter->hash_type == HASH_TYPE_KECCAK || thread_parameter->hash_type == HASH_TYPE_SHA512AIX || thread_parameter->hash_type == HASH_TYPE_PBKDF2OSX || thread_parameter->hash_type == HASH_TYPE_PBKDF2GRUB || thread_parameter->hash_type == HASH_TYPE_DRUPAL7)
  {
    ptrs[0] = (char *) &plains[0].buf64;
    ptrs[1] = (char *) &plains[1].buf64;
    ptrs[2] = (char *) &plains[2].buf64;
    ptrs[3] = (char *) &plains[3].buf64;
  }
  else
  {
    ptrs[0] = (char *) &plains[0].buf;
    ptrs[1] = (char *) &plains[1].buf;
    ptrs[2] = (char *) &plains[2].buf;
    ptrs[3] = (char *) &plains[3].buf;
  }

  words_t *words = thread_parameter->db->words;

  /* word range */

  uint64_t words_skip  = (thread_parameter->thread_words_skip == 0) ? 0 : thread_parameter->thread_words_skip;
  uint64_t words_limit = (thread_parameter->thread_words_limit == 0) ? words->words_cnt : MIN ((thread_parameter->thread_words_skip + thread_parameter->thread_words_limit), words->words_cnt);
  uint64_t words_todo  = words_limit - words_skip;
  uint64_t words_steps = words_todo / thread_parameter->num_threads;
  uint64_t words_left  = words_todo % thread_parameter->num_threads;

  words_skip += words_steps * thread_parameter->thread_id;

  if ((thread_parameter->thread_id + 1) == thread_parameter->num_threads)

  words_steps += words_left;

  /* main loop */

  uint64_t words_cur;

  for (words_cur = 0; words_cur < words_steps; words_cur++, thread_parameter->thread_words_done++)
  {
    while (*thread_parameter->hashcat_status == STATUS_PAUSED) hc_sleep (1);

    uint64_t words_next = words_skip + words_cur;

    plains[0].len = words->words_len[words_next];
    plains[1].len = words->words_len[words_next];
    plains[2].len = words->words_len[words_next];
    plains[3].len = words->words_len[words_next];

    memset (ptrs[0] + words->words_len[words_next], 0, BLOCK_SIZE - words->words_len[words_next]);
    memset (ptrs[1] + words->words_len[words_next], 0, BLOCK_SIZE - words->words_len[words_next]);
    memset (ptrs[2] + words->words_len[words_next], 0, BLOCK_SIZE - words->words_len[words_next]);
    memset (ptrs[3] + words->words_len[words_next], 0, BLOCK_SIZE - words->words_len[words_next]);

    /* init permutation */

    uint32_t p[BLOCK_SIZE];

    uint32_t k;

    for (k = 0; k < words->words_len[words_next] + 1; k++) p[k] = k;

    k = 0;

    /* main loop */

    uint32_t i = 4;

    while (i == 4)
    {
      for (i = 0; i < 4; i++)
      {
        k = next_permutation (words->words_buf[words_next], p, k);

        memcpy (ptrs[i], words->words_buf[words_next], words->words_len[words_next]);

        plains[i].pos = thread_parameter->thread_plains_done + i;  // TODO: needs verification

        if (k == words->words_len[words_next]) break;
      }

      int j;

      for (j = i + 1; j < 4; j++) // the +1 is here because if < 4, we did use 'break' to exit the loop
      {
        memset (ptrs[j], 0, BLOCK_SIZE);

        plains[j].len = 0;
      }

      thread_parameter->hashing (thread_parameter, plains);

      thread_parameter->thread_plains_done += 4;
    }

    if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
    if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
  }

  if ((*thread_parameter->hashcat_status != STATUS_QUIT) && (*thread_parameter->hashcat_status != STATUS_BYPASS))
  {
    thread_parameter->thread_words_done = words_steps;

    thread_parameter->thread_plains_done = words_steps;
  }

  return (NULL);
}

void *attack_a3r1 ()
{
  log_info ("Brute-Force with rules not supported");

  return (NULL);
}

void *attack_a3r0 (thread_parameter_t *thread_parameter)
{
  plain_t plains[4];

  memset (plains, 0, sizeof (plains));

  words_t *words = thread_parameter->db->words;

  /* word range */

  uint64_t words_skip  = (thread_parameter->thread_words_skip == 0) ? 0 : thread_parameter->thread_words_skip;
  uint64_t words_limit = (thread_parameter->thread_words_limit == 0) ? words->words_cnt : MIN ((thread_parameter->thread_words_skip + thread_parameter->thread_words_limit), words->words_cnt);
  uint64_t words_todo  = words_limit - words_skip;
  uint64_t words_steps = words_todo / thread_parameter->num_threads;
  uint64_t words_left  = words_todo % thread_parameter->num_threads;

  words_skip += words_steps * thread_parameter->thread_id;

  if ((thread_parameter->thread_id + 1) == thread_parameter->num_threads)

  words_steps += words_left;

  /* init buf */

  cs_t    *css_buf = thread_parameter->css_buf;
  uint32_t pw_len  = thread_parameter->pw_len;

  if (words_steps > 0) plains[0].len = pw_len;
  if (words_steps > 1) plains[1].len = pw_len;
  if (words_steps > 2) plains[2].len = pw_len;
  if (words_steps > 3) plains[3].len = pw_len;

  uint64 cur[4];

  cur[0] = words_skip + 0;
  cur[1] = words_skip + 1;
  cur[2] = words_skip + 2;
  cur[3] = words_skip + 3;

  plains[0].pos = thread_parameter->thread_words_done + 0;  // TODO: needs verification
  plains[1].pos = thread_parameter->thread_words_done + 1;  // TODO: needs verification
  plains[2].pos = thread_parameter->thread_words_done + 2;  // TODO: needs verification
  plains[3].pos = thread_parameter->thread_words_done + 3;  // TODO: needs verification

  mp_exec (cur[0], plains[0].buf8, css_buf, pw_len);
  mp_exec (cur[1], plains[1].buf8, css_buf, pw_len);
  mp_exec (cur[2], plains[2].buf8, css_buf, pw_len);
  mp_exec (cur[3], plains[3].buf8, css_buf, pw_len);

  thread_parameter->hashing (thread_parameter, plains);

  thread_parameter->thread_words_done += 4;

  /* main loop */

  uint64_t words_cur;

  words_step_size = 4;

  for (words_cur = 4; words_cur < words_steps; words_cur += words_step_size)
  {
    while (*thread_parameter->hashcat_status == STATUS_PAUSED) hc_sleep (1);

    uint64_t i;

    for (i = 0; i < 4; i++)
    {
      if ((words_cur + i) == words_steps) break;

      mp_incr (cur[i], cur[i] + 4, plains[i].buf8, css_buf, pw_len);

      plains[i].pos = thread_parameter->thread_words_done + i;  // TODO: needs verification

      cur[i] += 4;
    }

    for ( ; i < 4; i++)
    {
      plains[i].len = 0;
    }

    thread_parameter->hashing (thread_parameter, plains);

    thread_parameter->thread_words_done += words_step_size;

    if (*thread_parameter->hashcat_status == STATUS_QUIT)   break;
    if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
  }

  if ((*thread_parameter->hashcat_status != STATUS_QUIT) && (*thread_parameter->hashcat_status != STATUS_BYPASS))
  {
    thread_parameter->thread_plains_done = words_steps;
    thread_parameter->thread_words_done  = words_steps;
  }

  return (NULL);
}

void *attack_a1r1 (thread_parameter_t *thread_parameter)
{
  plain_t plains[4];

  char *ptrs[4];

  memset (plains, 0, sizeof (plains));

  if (thread_parameter->hash_type == HASH_TYPE_SHA512 || thread_parameter->hash_type == HASH_TYPE_SHA512UNIX || thread_parameter->hash_type == HASH_TYPE_MSSQL2012 || thread_parameter->hash_type == HASH_TYPE_KECCAK || thread_parameter->hash_type == HASH_TYPE_SHA512AIX || thread_parameter->hash_type == HASH_TYPE_PBKDF2OSX || thread_parameter->hash_type == HASH_TYPE_PBKDF2GRUB || thread_parameter->hash_type == HASH_TYPE_DRUPAL7)
  {
    ptrs[0] = (char *) &plains[0].buf64;
    ptrs[1] = (char *) &plains[1].buf64;
    ptrs[2] = (char *) &plains[2].buf64;
    ptrs[3] = (char *) &plains[3].buf64;
  }
  else
  {
    ptrs[0] = (char *) &plains[0].buf;
    ptrs[1] = (char *) &plains[1].buf;
    ptrs[2] = (char *) &plains[2].buf;
    ptrs[3] = (char *) &plains[3].buf;
  }

  words_t *words = thread_parameter->db->words;

  rules_t *rules = thread_parameter->db->rules;

  /* word range */

  uint64_t words_skip  = (thread_parameter->thread_words_skip == 0) ? 0 : thread_parameter->thread_words_skip;
  uint64_t words_limit = (thread_parameter->thread_words_limit == 0) ? words->words_cnt : MIN ((thread_parameter->thread_words_skip + thread_parameter->thread_words_limit), words->words_cnt);
  uint64_t words_todo  = words_limit - words_skip;
  uint64_t words_steps = words_todo / thread_parameter->num_threads;
  uint64_t words_left  = words_todo % thread_parameter->num_threads;

  words_skip += words_steps * thread_parameter->thread_id;

  if ((thread_parameter->thread_id + 1) == thread_parameter->num_threads)

  words_steps += words_left;

  char * debug_buf;

  /* main loop */

  uint64_t words_cur;

  for (words_cur = 0; words_cur < words_steps; words_cur++, thread_parameter->thread_words_done++)
  {
    while (*thread_parameter->hashcat_status == STATUS_PAUSED) hc_sleep (1);

    uint64_t words_next = words_skip + words_cur;

    char orig_plain[BLOCK_SIZE];

    memset (orig_plain, 0, sizeof (orig_plain));

    memcpy (orig_plain, words->words_buf[words_next], words->words_len[words_next]);

    uint32_t rules_idx;

    for (rules_idx = 0; rules_idx < rules->rules_cnt; rules_idx += 4)
    {
      uint32_t l;

      for (l = 0; l < words->words_cnt; l++)
      {
        uint32_t orig_plain_len = words->words_len[words_next] + words->words_len[l];

        if (orig_plain_len > thread_parameter->plain_size_max) continue;

        memcpy (orig_plain + words->words_len[words_next], words->words_buf[l], words->words_len[l]);

        uint32_t i;

        //uint limit = MIN (4, words->words_cnt - l);

        for (i = 0; i < 4; i++)
        {
          if ((rules_idx + i) >= rules->rules_cnt)
          {
            plains[i].len = 0;

            continue;
          }

          int next_len = apply_rule (rules->rules_buf[rules_idx + i], rules->rules_len[rules_idx + i], orig_plain, orig_plain_len, ptrs[i]);

          if ((next_len < 0) || ((uint32_t) next_len > thread_parameter->plain_size_max)) continue;

          plains[i].len = next_len;

          plains[i].pos = thread_parameter->thread_words_done + i;  // TODO: needs verification

          switch (thread_parameter->debug_mode)
          {
            case 1:
              plains[i].debug_buf = rules->rules_buf[rules_idx + i];
              plains[i].debug_len = rules->rules_len[rules_idx + i];
              break;

            case 2:
              plains[i].debug_buf = orig_plain;
              plains[i].debug_len = orig_plain_len;
              break;

            case 3:
            {
              debug_buf = (char*) mymalloc (sizeof (char) * (orig_plain_len + 1 + rules->rules_len[rules_idx + i] + 1));

              memset (debug_buf, 0, orig_plain_len + 1 + rules->rules_len[rules_idx + i] + 1);

              uint pos = 0;

              memcpy (debug_buf + pos, orig_plain, orig_plain_len);

              pos += orig_plain_len;

              debug_buf[pos] = thread_parameter->separator;

              pos += 1;

              memcpy (debug_buf + pos, rules->rules_buf[rules_idx + i], rules->rules_len[rules_idx + i]);

              pos += rules->rules_len[rules_idx + i];

              plains[i].debug_buf = debug_buf;
              plains[i].debug_len = pos;
              break;
            }
            case 4:
            {
              debug_buf = (char*) mymalloc (sizeof (char) * (orig_plain_len + 1 + rules->rules_len[rules_idx + i] + 1 + next_len + 1));

              memset (debug_buf, 0, orig_plain_len + 1 + rules->rules_len[rules_idx + i] + 1 + next_len + 1);

              uint pos = 0;

              memcpy (debug_buf + pos, orig_plain, orig_plain_len);

              pos += orig_plain_len;

              debug_buf[pos] = thread_parameter->separator;

              pos += 1;

              memcpy (debug_buf + pos, rules->rules_buf[rules_idx + i], rules->rules_len[rules_idx + i]);

              pos += rules->rules_len[rules_idx + i];

              debug_buf[pos] = thread_parameter->separator;

              pos += 1;

              memcpy (debug_buf + pos, ptrs[i], next_len);

              pos += next_len;

              plains[i].debug_buf = debug_buf;
              plains[i].debug_len = pos;
              break;
            }
          }
        }

        thread_parameter->hashing (thread_parameter, plains);

        thread_parameter->thread_plains_done += 4;

        // clean up , free debug buffer etc

        if ((thread_parameter->debug_mode == 3) || (thread_parameter->debug_mode == 4))
        {
          for (i = 0; (i < 4); i++)
          {
            myfree (plains[i].debug_buf);

            plains[i].debug_buf = NULL;
          }
        }

        if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
        if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
      }

      if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
      if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
    }

    if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
    if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
  }

  return (NULL);
}

void *attack_a1r0 (thread_parameter_t *thread_parameter)
{
  plain_t plains[4];

  char *ptrs[4];

  memset (plains, 0, sizeof (plains));

  if (thread_parameter->hash_type == HASH_TYPE_SHA512 || thread_parameter->hash_type == HASH_TYPE_SHA512UNIX || thread_parameter->hash_type == HASH_TYPE_MSSQL2012 || thread_parameter->hash_type == HASH_TYPE_KECCAK || thread_parameter->hash_type == HASH_TYPE_SHA512AIX || thread_parameter->hash_type == HASH_TYPE_PBKDF2OSX || thread_parameter->hash_type == HASH_TYPE_PBKDF2GRUB || thread_parameter->hash_type == HASH_TYPE_DRUPAL7)
  {
    ptrs[0] = (char *) &plains[0].buf64;
    ptrs[1] = (char *) &plains[1].buf64;
    ptrs[2] = (char *) &plains[2].buf64;
    ptrs[3] = (char *) &plains[3].buf64;
  }
  else
  {
    ptrs[0] = (char *) &plains[0].buf;
    ptrs[1] = (char *) &plains[1].buf;
    ptrs[2] = (char *) &plains[2].buf;
    ptrs[3] = (char *) &plains[3].buf;
  }

  words_t *words = thread_parameter->db->words;

  /* word range */

  uint64_t words_skip  = (thread_parameter->thread_words_skip == 0) ? 0 : thread_parameter->thread_words_skip;
  uint64_t words_limit = (thread_parameter->thread_words_limit == 0) ? words->words_cnt : MIN ((thread_parameter->thread_words_skip + thread_parameter->thread_words_limit), words->words_cnt);
  uint64_t words_todo  = words_limit - words_skip;
  uint64_t words_steps = words_todo / thread_parameter->num_threads;
  uint64_t words_left  = words_todo % thread_parameter->num_threads;

  words_skip += words_steps * thread_parameter->thread_id;

  if ((thread_parameter->thread_id + 1) == thread_parameter->num_threads)

  words_steps += words_left;

  /* main loop */

  uint64_t words_cur;

  for (words_cur = 0; words_cur < words_steps; words_cur++, thread_parameter->thread_words_done++)
  {
    while (*thread_parameter->hashcat_status == STATUS_PAUSED) hc_sleep (1);

    uint64_t words_next = words_skip + words_cur;

    memcpy (ptrs[0], words->words_buf[words_next], words->words_len[words_next]);
    memcpy (ptrs[1], words->words_buf[words_next], words->words_len[words_next]);
    memcpy (ptrs[2], words->words_buf[words_next], words->words_len[words_next]);
    memcpy (ptrs[3], words->words_buf[words_next], words->words_len[words_next]);

    uint32_t l;

    for (l = 0; l < words->words_cnt; l += 4)
    {
      uint32_t i;

      uint limit = MIN (4, words->words_cnt - l);

      for (i = 0; i < limit; i++)
      {
        uint32_t next_len = words->words_len[words_next] + words->words_len[l + i];

        if (next_len > thread_parameter->plain_size_max) continue;

        memset (ptrs[i] + next_len, 0, BLOCK_SIZE - next_len);

        memcpy (ptrs[i] + words->words_len[words_next], words->words_buf[l + i], words->words_len[l + i]);

        plains[i].len = next_len;

        plains[i].pos = thread_parameter->thread_words_done + i;  // TODO: needs verification
      }

      for (; i < 4; i++)
      {
        // memset () not really needed (but this is what is the main problem):
        // memset (ptrs[i], 0, BLOCK_SIZE);

        plains[i].len = 0;
      }

      thread_parameter->hashing (thread_parameter, plains);

      thread_parameter->thread_plains_done += 4;

      if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
      if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
    }

    if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
    if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
  }

  return (NULL);
}

void *attack_a0r1 (thread_parameter_t *thread_parameter)
{
  plain_t plains[4];

  char *ptrs[4];

  memset (plains, 0, sizeof (plains));

  if (thread_parameter->hash_type == HASH_TYPE_SHA512 || thread_parameter->hash_type == HASH_TYPE_SHA512UNIX || thread_parameter->hash_type == HASH_TYPE_MSSQL2012 || thread_parameter->hash_type == HASH_TYPE_KECCAK || thread_parameter->hash_type == HASH_TYPE_SHA512AIX || thread_parameter->hash_type == HASH_TYPE_PBKDF2OSX || thread_parameter->hash_type == HASH_TYPE_PBKDF2GRUB || thread_parameter->hash_type == HASH_TYPE_DRUPAL7)
  {
    ptrs[0] = (char *) &plains[0].buf64;
    ptrs[1] = (char *) &plains[1].buf64;
    ptrs[2] = (char *) &plains[2].buf64;
    ptrs[3] = (char *) &plains[3].buf64;
  }
  else
  {
    ptrs[0] = (char *) &plains[0].buf;
    ptrs[1] = (char *) &plains[1].buf;
    ptrs[2] = (char *) &plains[2].buf;
    ptrs[3] = (char *) &plains[3].buf;
  }

  words_t *words = thread_parameter->db->words;

  rules_t *rules = thread_parameter->db->rules;

  /* word range */

  uint64_t words_skip  = (thread_parameter->thread_words_skip == 0) ? 0 : thread_parameter->thread_words_skip;
  uint64_t words_limit = (thread_parameter->thread_words_limit == 0) ? words->words_cnt : MIN ((thread_parameter->thread_words_skip + thread_parameter->thread_words_limit), words->words_cnt);
  uint64_t words_todo  = words_limit - words_skip;
  uint64_t words_steps = words_todo / thread_parameter->num_threads;
  uint64_t words_left  = words_todo % thread_parameter->num_threads;

  words_skip += words_steps * thread_parameter->thread_id;

  if ((thread_parameter->thread_id + 1) == thread_parameter->num_threads)

  words_steps += words_left;

  char * debug_buf;

  /* main loop */

  uint64_t words_cur;

  for (words_cur = 0; words_cur < words_steps; words_cur++)
  {
    while (*thread_parameter->hashcat_status == STATUS_PAUSED) hc_sleep (1);

    uint32_t rules_cnt = rules->rules_cnt;

    uint32_t rules_idx = 0;

    while (rules_idx < rules_cnt)
    {
      uint64_t words_next = words_skip + words_cur;

      uint32_t i;

      for (i = 0; ((i < 4) && (rules_idx < rules_cnt)); rules_idx++, thread_parameter->thread_plains_done++)
      {
        int next_len = apply_rule (rules->rules_buf[rules_idx], rules->rules_len[rules_idx], words->words_buf[words_next], words->words_len[words_next], ptrs[i]);

        if ((next_len < 0) || ((uint32_t) next_len > thread_parameter->plain_size_max)) continue;

        plains[i].len = next_len;

        plains[i].pos = thread_parameter->thread_words_done + i;  // TODO: needs verification

        switch (thread_parameter->debug_mode)
        {
          case 1:
            plains[i].debug_buf = rules->rules_buf[rules_idx];
            plains[i].debug_len = rules->rules_len[rules_idx];
            break;

          case 2:
            plains[i].debug_buf = words->words_buf[words_next];
            plains[i].debug_len = words->words_len[words_next];
            break;

          case 3:
          {
            debug_buf = (char*) mymalloc (sizeof (char) * (words->words_len[words_next] + 1 + rules->rules_len[rules_idx] + 1));

            memset (debug_buf, 0, words->words_len[words_next] + 1 + rules->rules_len[rules_idx] + 1);

            uint pos = 0;

            memcpy (debug_buf + pos, words->words_buf[words_next], words->words_len[words_next]);

            pos += words->words_len[words_next];

            debug_buf[pos] = thread_parameter->separator;

            pos += 1;

            memcpy (debug_buf + pos, rules->rules_buf[rules_idx], rules->rules_len[rules_idx]);

            pos += rules->rules_len[rules_idx];

            plains[i].debug_buf = debug_buf;
            plains[i].debug_len = pos;
            break;
          }
          case 4:
          {
            debug_buf = (char*) mymalloc (sizeof (char) * (words->words_len[words_next] + 1 + rules->rules_len[rules_idx] + 1 + next_len + 1));

            memset (debug_buf, 0, words->words_len[words_next] + 1 + rules->rules_len[rules_idx] + 1 + next_len + 1);

            uint pos = 0;

            memcpy (debug_buf + pos, words->words_buf[words_next], words->words_len[words_next]);

            pos += words->words_len[words_next];

            debug_buf[pos] = thread_parameter->separator;

            pos += 1;

            memcpy (debug_buf + pos, rules->rules_buf[rules_idx], rules->rules_len[rules_idx]);

            pos += rules->rules_len[rules_idx];

            debug_buf[pos] = thread_parameter->separator;

            pos += 1;

            memcpy (debug_buf + pos, ptrs[i], next_len);

            pos += next_len;

            plains[i].debug_buf = debug_buf;
            plains[i].debug_len = pos;
            break;
          }
        }

        i++;
      }

      for ( ; i < 4; i++)
      {
        memset (ptrs[i], 0, 64);

        plains[i].len = 0;
      }

      thread_parameter->hashing (thread_parameter, plains);

      // clean up , free debug buffer etc

      if ((thread_parameter->debug_mode == 3) || (thread_parameter->debug_mode == 4))
      {
        for (i = 0; (i < 4); i++)
        {
          myfree (plains[i].debug_buf);

          plains[i].debug_buf = NULL;
        }
      }

      if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
      if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
    }

    thread_parameter->thread_words_done++;

    if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
    if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
  }

  if ((*thread_parameter->hashcat_status != STATUS_QUIT) && (*thread_parameter->hashcat_status != STATUS_BYPASS))
  {
    thread_parameter->thread_plains_done = words_steps * rules->rules_cnt;

    thread_parameter->thread_words_done = words_steps;
  }

  return (NULL);
}

void *attack_a0r0 (thread_parameter_t *thread_parameter)
{
  plain_t plains[4];

  char *ptrs[4];

  memset (plains, 0, sizeof (plains));

  if (thread_parameter->hash_type == HASH_TYPE_SHA512 || thread_parameter->hash_type == HASH_TYPE_SHA512UNIX || thread_parameter->hash_type == HASH_TYPE_MSSQL2012 || thread_parameter->hash_type == HASH_TYPE_KECCAK || thread_parameter->hash_type == HASH_TYPE_SHA512AIX || thread_parameter->hash_type == HASH_TYPE_PBKDF2OSX || thread_parameter->hash_type == HASH_TYPE_PBKDF2GRUB || thread_parameter->hash_type == HASH_TYPE_DRUPAL7)
  {
    ptrs[0] = (char *) &plains[0].buf64;
    ptrs[1] = (char *) &plains[1].buf64;
    ptrs[2] = (char *) &plains[2].buf64;
    ptrs[3] = (char *) &plains[3].buf64;
  }
  else
  {
    ptrs[0] = (char *) &plains[0].buf;
    ptrs[1] = (char *) &plains[1].buf;
    ptrs[2] = (char *) &plains[2].buf;
    ptrs[3] = (char *) &plains[3].buf;
  }

  words_t *words = thread_parameter->db->words;

  /* word range */

  uint64_t words_skip  = (thread_parameter->thread_words_skip == 0) ? 0 : thread_parameter->thread_words_skip;
  uint64_t words_limit = (thread_parameter->thread_words_limit == 0) ? words->words_cnt : MIN ((thread_parameter->thread_words_skip + thread_parameter->thread_words_limit), words->words_cnt);
  uint64_t words_todo  = words_limit - words_skip;
  uint64_t words_steps = words_todo / thread_parameter->num_threads;
  uint64_t words_left  = words_todo % thread_parameter->num_threads;

  words_skip += words_steps * thread_parameter->thread_id;

  if ((thread_parameter->thread_id + 1) == thread_parameter->num_threads)

  words_steps += words_left;

  /* main loop */

  uint64_t words_cur;

  words_step_size = 4;

  for (words_cur = 0; words_cur < words_steps; words_cur += words_step_size)
  {
    while (*thread_parameter->hashcat_status == STATUS_PAUSED) hc_sleep (1);

    uint64_t words_next = words_skip + words_cur;

    uint32_t i;

    uint limit = MIN (4, words_steps - words_cur);

    for (i = 0; i < limit; i++, words_next++)
    {
      int next_len = words->words_len[words_next];

      int zero_len = plains[i].len - next_len;

      if (zero_len > 0) memset (ptrs[i] + next_len, 0, zero_len + 1);

      memcpy (ptrs[i], words->words_buf[words_next], next_len);

      plains[i].len = next_len;

      plains[i].pos = thread_parameter->thread_words_done + i;
    }

    for (; i < 4; i++)
    {
      plains[i].len = 0;
    }

    thread_parameter->hashing (thread_parameter, plains);

    thread_parameter->thread_plains_done += 4;

    thread_parameter->thread_words_done += words_step_size;

    if (*thread_parameter->hashcat_status == STATUS_QUIT) break;
    if (*thread_parameter->hashcat_status == STATUS_BYPASS) break;
  }

  if ((*thread_parameter->hashcat_status != STATUS_QUIT) && (*thread_parameter->hashcat_status != STATUS_BYPASS))
  {
    thread_parameter->thread_plains_done = words_steps;

    thread_parameter->thread_words_done = words_steps;
  }

  return (NULL);
}

void run_threads (engine_parameter_t *engine_parameter, db_t *db, void (*store_out) (plain_t *, digest_t *, salt_t *), void (*store_debug) (char *, int), void (*done) (), digest_t *quick_digest)
{
  unsigned int ids[MAX_THREADS];

  memset (ids, 0, sizeof (ids));

  THREAD threads[MAX_THREADS];

  ACMutexInit (lock_store);

  uint32_t thread_id;

  for (thread_id = 0; thread_id < engine_parameter->num_threads; thread_id++)
  {
    thread_parameters[thread_id].thread_id           = thread_id;
    thread_parameters[thread_id].num_threads         = engine_parameter->num_threads;
    thread_parameters[thread_id].thread_words_skip   = engine_parameter->words_skip;
    thread_parameters[thread_id].thread_words_limit  = engine_parameter->words_limit;
    thread_parameters[thread_id].thread_words_done   = 0;
    thread_parameters[thread_id].thread_plains_done  = 0;
    thread_parameters[thread_id].db                  = db;
    thread_parameters[thread_id].store_out           = store_out;
    thread_parameters[thread_id].store_debug         = store_debug;
    thread_parameters[thread_id].separator           = engine_parameter->separator;
    thread_parameters[thread_id].done                = done;
    thread_parameters[thread_id].hashcat_status      = &engine_parameter->hashcat_status;
    thread_parameters[thread_id].pw_len              = engine_parameter->pw_len;
    thread_parameters[thread_id].css_buf             = engine_parameter->css_buf;
    thread_parameters[thread_id].css_cnt             = engine_parameter->css_cnt;
    thread_parameters[thread_id].debug_mode          = engine_parameter->debug_mode;
    thread_parameters[thread_id].debug_file          = engine_parameter->file_debug;
    thread_parameters[thread_id].plain_size_max      = engine_parameter->plain_size_max;
    thread_parameters[thread_id].table_buf           = engine_parameter->table_buf;
    thread_parameters[thread_id].hash_type           = engine_parameter->hash_type;

    if ((engine_parameter->hash_mode == 8900) || (engine_parameter->hash_mode == 9300))
    {
      uint32_t max_N = 0;
      uint32_t max_r = 0;
      uint32_t max_p = 0;

      uint32_t salts_idx;

      for (salts_idx = 0; salts_idx < db->salts_cnt; salts_idx++)
      {
        salt_t *salt = db->salts_buf[salts_idx];

        max_N = MAX (max_N, salt->scrypt_N);
        max_r = MAX (max_r, salt->scrypt_r);
        max_p = MAX (max_p, salt->scrypt_p);
      }

      const uint32_t scrypt_cnt = GET_SCRYPT_CNT  (max_r, max_p);
      const uint32_t smix_cnt   = GET_SMIX_CNT    (max_r, max_N);
      const uint32_t state_cnt  = GET_STATE_CNT   (max_r);

      thread_parameters[thread_id].scrypt_P[0] = (uint32_t *) mymalloc (scrypt_cnt * sizeof (uint32_t));
      thread_parameters[thread_id].scrypt_P[1] = (uint32_t *) mymalloc (scrypt_cnt * sizeof (uint32_t));
      thread_parameters[thread_id].scrypt_P[2] = (uint32_t *) mymalloc (scrypt_cnt * sizeof (uint32_t));
      thread_parameters[thread_id].scrypt_P[3] = (uint32_t *) mymalloc (scrypt_cnt * sizeof (uint32_t));

      thread_parameters[thread_id].scrypt_V  = (__m128i *) _mm_malloc (smix_cnt  * sizeof (uint32_t), 64);
      thread_parameters[thread_id].scrypt_X  = (__m128i *) _mm_malloc (state_cnt * sizeof (uint32_t), 64);
      thread_parameters[thread_id].scrypt_Y  = (__m128i *) _mm_malloc (state_cnt * sizeof (uint32_t), 64);
    }

    if (quick_digest)
    {
      thread_parameters[thread_id].indb              = indb_single;
      thread_parameters[thread_id].quick_digest      = quick_digest;
    }
    else
    {
      thread_parameters[thread_id].indb              = indb_multi;
      thread_parameters[thread_id].quick_digest      = NULL;
    }

    switch (engine_parameter->hash_mode)
    {
      case     0: thread_parameters[thread_id].hashing = hashing_00000; break;
      case    10: thread_parameters[thread_id].hashing = hashing_00010; break;
      case    20: thread_parameters[thread_id].hashing = hashing_00020; break;
      case    30: thread_parameters[thread_id].hashing = hashing_00030; break;
      case    40: thread_parameters[thread_id].hashing = hashing_00040; break;
      case    50: thread_parameters[thread_id].hashing = hashing_00050; break;
      case    60: thread_parameters[thread_id].hashing = hashing_00060; break;
      case   100: thread_parameters[thread_id].hashing = hashing_00100; break;
      case   110: thread_parameters[thread_id].hashing = hashing_00110; break;
      case   120: thread_parameters[thread_id].hashing = hashing_00120; break;
      case   130: thread_parameters[thread_id].hashing = hashing_00130; break;
      case   140: thread_parameters[thread_id].hashing = hashing_00140; break;
      case   150: thread_parameters[thread_id].hashing = hashing_00150; break;
      case   160: thread_parameters[thread_id].hashing = hashing_00160; break;
      case   200: thread_parameters[thread_id].hashing = hashing_00200; break;
      case   300: thread_parameters[thread_id].hashing = hashing_00300; break;
      case   400: thread_parameters[thread_id].hashing = hashing_00400; break;
      case   500: thread_parameters[thread_id].hashing = hashing_00500; break;
      case   666: thread_parameters[thread_id].hashing = hashing_00666; break;
      case   900: thread_parameters[thread_id].hashing = hashing_00900; break;
      case  1000: thread_parameters[thread_id].hashing = hashing_01000; break;
      case  1100: thread_parameters[thread_id].hashing = hashing_01100; break;
      case  1400: thread_parameters[thread_id].hashing = hashing_01400; break;
      case  1410: thread_parameters[thread_id].hashing = hashing_01410; break;
      case  1420: thread_parameters[thread_id].hashing = hashing_01420; break;
      case  1430: thread_parameters[thread_id].hashing = hashing_01430; break;
      case  1431: thread_parameters[thread_id].hashing = hashing_01431; break;
      case  1440: thread_parameters[thread_id].hashing = hashing_01440; break;
      case  1441: thread_parameters[thread_id].hashing = hashing_01440; break;
      case  1450: thread_parameters[thread_id].hashing = hashing_01450; break;
      case  1460: thread_parameters[thread_id].hashing = hashing_01460; break;
      case  1500: thread_parameters[thread_id].hashing = hashing_01500; break;
      case  1600: thread_parameters[thread_id].hashing = hashing_01600; break;
      case  1700: thread_parameters[thread_id].hashing = hashing_01700; break;
      case  1710: thread_parameters[thread_id].hashing = hashing_01710; break;
      case  1720: thread_parameters[thread_id].hashing = hashing_01720; break;
      case  1730: thread_parameters[thread_id].hashing = hashing_01730; break;
      case  1740: thread_parameters[thread_id].hashing = hashing_01740; break;
      case  1750: thread_parameters[thread_id].hashing = hashing_01750; break;
      case  1760: thread_parameters[thread_id].hashing = hashing_01760; break;
      case  1800: thread_parameters[thread_id].hashing = hashing_01800; break;
      case  2400: thread_parameters[thread_id].hashing = hashing_02400; break;
      case  2410: thread_parameters[thread_id].hashing = hashing_02410; break;
      case  2500: thread_parameters[thread_id].hashing = hashing_02500; break;
      case  2600: thread_parameters[thread_id].hashing = hashing_02600; break;
      case  3200: thread_parameters[thread_id].hashing = hashing_03200; break;
      case  3300: thread_parameters[thread_id].hashing = hashing_03300; break;
      case  3500: thread_parameters[thread_id].hashing = hashing_03500; break;
      case  3610: thread_parameters[thread_id].hashing = hashing_03610; break;
      case  3710: thread_parameters[thread_id].hashing = hashing_03710; break;
      case  3720: thread_parameters[thread_id].hashing = hashing_03720; break;
      case  3800: thread_parameters[thread_id].hashing = hashing_03800; break;
      case  3910: thread_parameters[thread_id].hashing = hashing_03910; break;
      case  4010: thread_parameters[thread_id].hashing = hashing_04010; break;
      case  4110: thread_parameters[thread_id].hashing = hashing_04110; break;
      case  4210: thread_parameters[thread_id].hashing = hashing_04210; break;
      case  4300: thread_parameters[thread_id].hashing = hashing_04300; break;
      case  4400: thread_parameters[thread_id].hashing = hashing_04400; break;
      case  4500: thread_parameters[thread_id].hashing = hashing_04500; break;
      case  4600: thread_parameters[thread_id].hashing = hashing_04600; break;
      case  4700: thread_parameters[thread_id].hashing = hashing_04700; break;
      case  4800: thread_parameters[thread_id].hashing = hashing_04800; break;
      case  4900: thread_parameters[thread_id].hashing = hashing_04900; break;
      case  5000: thread_parameters[thread_id].hashing = hashing_05000; break;
      case  5100: thread_parameters[thread_id].hashing = hashing_05100; break;
      case  5200: thread_parameters[thread_id].hashing = hashing_05200; break;
      case  5300: thread_parameters[thread_id].hashing = hashing_05300; break;
      case  5400: thread_parameters[thread_id].hashing = hashing_05400; break;
      case  5500: thread_parameters[thread_id].hashing = hashing_05500; break;
      case  5600: thread_parameters[thread_id].hashing = hashing_05600; break;
      case  5700: thread_parameters[thread_id].hashing = hashing_01400; break;
      case  5800: thread_parameters[thread_id].hashing = hashing_05800; break;
      case  6300: thread_parameters[thread_id].hashing = hashing_06300; break;
      case  6400: thread_parameters[thread_id].hashing = hashing_06400; break;
      case  6500: thread_parameters[thread_id].hashing = hashing_06500; break;
      case  6700: thread_parameters[thread_id].hashing = hashing_06700; break;
      case  6900: thread_parameters[thread_id].hashing = hashing_06900; break;
      case  7000: thread_parameters[thread_id].hashing = hashing_07000; break;
      case  7100: thread_parameters[thread_id].hashing = hashing_07100; break;
      case  7200: thread_parameters[thread_id].hashing = hashing_07100; break;
      case  7300: thread_parameters[thread_id].hashing = hashing_07300; break;
      case  7400: thread_parameters[thread_id].hashing = hashing_07400; break;
      case  7900: thread_parameters[thread_id].hashing = hashing_07900; break;
      case  8400: thread_parameters[thread_id].hashing = hashing_08400; break;
      case  8900: thread_parameters[thread_id].hashing = hashing_08900; break;
      case  9200: thread_parameters[thread_id].hashing = hashing_09200; break;
      case  9300: thread_parameters[thread_id].hashing = hashing_08900; break;
      case  9900: thread_parameters[thread_id].hashing = hashing_09900; break;
      case 10200: thread_parameters[thread_id].hashing = hashing_00050; break;
      case 10300: thread_parameters[thread_id].hashing = hashing_10300; break;
      case 10000: thread_parameters[thread_id].hashing = hashing_09200; break;
      case 11000: thread_parameters[thread_id].hashing = hashing_11000; break;
      case 11100: thread_parameters[thread_id].hashing = hashing_11100; break;
      case 11200: thread_parameters[thread_id].hashing = hashing_11200; break;
      case 11400: thread_parameters[thread_id].hashing = hashing_11400; break;
      case 99999: thread_parameters[thread_id].hashing = hashing_99999; break;
      case    11: thread_parameters[thread_id].hashing = hashing_00010; break;
      case    12: thread_parameters[thread_id].hashing = hashing_00010; break;
      case    21: thread_parameters[thread_id].hashing = hashing_00020; break;
      case    23: thread_parameters[thread_id].hashing = hashing_00020; break;
      case   101: thread_parameters[thread_id].hashing = hashing_00100; break;
      case   111: thread_parameters[thread_id].hashing = hashing_00110; break;
      case   112: thread_parameters[thread_id].hashing = hashing_00110; break;
      case   121: thread_parameters[thread_id].hashing = hashing_00120; break;
      case   122: thread_parameters[thread_id].hashing = hashing_00120; break;
      case   123: thread_parameters[thread_id].hashing = hashing_00123; break;
      case   124: thread_parameters[thread_id].hashing = hashing_00120; break;
      case   131: thread_parameters[thread_id].hashing = hashing_00131; break;
      case   132: thread_parameters[thread_id].hashing = hashing_00130; break;
      case   133: thread_parameters[thread_id].hashing = hashing_00133; break;
      case   141: thread_parameters[thread_id].hashing = hashing_00140; break;
      case  1421: thread_parameters[thread_id].hashing = hashing_01420; break;
      case  1711: thread_parameters[thread_id].hashing = hashing_01710; break;
      case  1722: thread_parameters[thread_id].hashing = hashing_01722; break;
      case  1731: thread_parameters[thread_id].hashing = hashing_01730; break;
      case  2611: thread_parameters[thread_id].hashing = hashing_02611; break;
      case  2612: thread_parameters[thread_id].hashing = hashing_02611; break;
      case  2711: thread_parameters[thread_id].hashing = hashing_02711; break;
      case  2811: thread_parameters[thread_id].hashing = hashing_02811; break;
      case  3711: thread_parameters[thread_id].hashing = hashing_03710; break;
      case  3721: thread_parameters[thread_id].hashing = hashing_03720; break;
      case  7600: thread_parameters[thread_id].hashing = hashing_07600; break;
    }

    if ((engine_parameter->hash_type == HASH_TYPE_MD5) && (engine_parameter->salt_type == SALT_TYPE_NONE))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_md5;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MD5) && (engine_parameter->salt_type == SALT_TYPE_INCLUDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MD5) && (engine_parameter->salt_type == SALT_TYPE_EXTERNAL))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_md5;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA1) && (engine_parameter->salt_type == SALT_TYPE_NONE))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_sha1;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA1) && (engine_parameter->salt_type == SALT_TYPE_INCLUDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA1) && (engine_parameter->salt_type == SALT_TYPE_EXTERNAL))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_sha1;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MYSQL) && (engine_parameter->salt_type == SALT_TYPE_NONE))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_mysql;
      thread_parameters[thread_id].get_index      = get_index_mysql;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_PHPASS) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MD5UNIX) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MD5SUN) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA1B64) && (engine_parameter->salt_type == SALT_TYPE_NONE))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_sha1;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA1B64S) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MD4) && (engine_parameter->salt_type == SALT_TYPE_NONE))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md4;
      thread_parameters[thread_id].get_index      = get_index_md4;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_DCC) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md4;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MD5CHAP) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MSSQL2000) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MSSQL2005) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_EPIV6) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA256) && (engine_parameter->salt_type == SALT_TYPE_NONE))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_sha256;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA256) && (engine_parameter->salt_type == SALT_TYPE_INCLUDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA256) && (engine_parameter->salt_type == SALT_TYPE_EXTERNAL))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_sha256;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MD5APR) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA512) && (engine_parameter->salt_type == SALT_TYPE_NONE))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_sha512;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA512) && (engine_parameter->salt_type == SALT_TYPE_INCLUDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA512) && (engine_parameter->salt_type == SALT_TYPE_EXTERNAL))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_sha512;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA512UNIX) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA256UNIX) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_OSX1) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_OSX512) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_MSSQL2012) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_DESCRYPT) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_descrypt;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_KECCAK) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_keccak;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_WPA) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_PSAFE3) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_IKEPSK_MD5) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_IKEPSK_SHA1) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_NETNTLMv1) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_netntlmv1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_NETNTLMv2) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_CISCO_SECRET4)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_sha256;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_MD5AIX)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SHA1AIX)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SHA256AIX)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SHA512AIX)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_GOST)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_gost;
      thread_parameters[thread_id].get_index      = get_index_gost;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SHA1FORTIGATE)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_PBKDF2OSX)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_PBKDF2GRUB)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_MD5CISCO_PIX)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_md5;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SHA1ORACLE)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_HMACRAKP)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_BCRYPT) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_bcrypt;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_EPIV6_4) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_SHA512B64S) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha512;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_EPIV4) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if ((engine_parameter->hash_type == HASH_TYPE_DJANGOSHA1) && (engine_parameter->salt_type == SALT_TYPE_EMBEDDED))
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SCRYPT)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_CISCO_SECRET9)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_PHPS)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_HMAIL)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_MEDIAWIKI_B)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_CISCO_SECRET8)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_DJANGO_SHA256)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_PEOPLESOFT)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_sha1;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_CRAM_MD5)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_DRUPAL7)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256; // not a bug (the encoded hash is truncated to 32 bytes)
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_MD5CISCO_ASA)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SAP_H_SHA1)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_PRESTASHOP)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_POSTGRESQL_AUTH)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_MYSQL_AUTH)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha1;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SIP_AUTH)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_md5;
      thread_parameters[thread_id].get_index      = get_index_zero;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_SHA256B64)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_sha256;
      thread_parameters[thread_id].get_index      = get_index_sha256;
    }
    else if (engine_parameter->hash_type == HASH_TYPE_PLAIN)
    {
      thread_parameters[thread_id].compare_digest = compare_digest_plain;
      thread_parameters[thread_id].get_index      = get_index_plain;
    }

    if ((engine_parameter->attack_mode == 0) && (db->rules->rules_cnt == 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a0r0, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 0) && (db->rules->rules_cnt != 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a0r1, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 1) && (db->rules->rules_cnt == 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a1r0, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 1) && (db->rules->rules_cnt != 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a1r1, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 3) && (db->rules->rules_cnt == 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a3r0, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 3) && (db->rules->rules_cnt != 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a3r1, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 4) && (db->rules->rules_cnt == 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a4r0, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 4) && (db->rules->rules_cnt != 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a4r1, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 5) && (db->rules->rules_cnt == 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a5r0, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 5) && (db->rules->rules_cnt != 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a5r1, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 8) && (db->rules->rules_cnt == 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a0r0, &thread_parameters[thread_id], &ids[thread_id]);
    }
    else if ((engine_parameter->attack_mode == 8) && (db->rules->rules_cnt != 0))
    {
      ACCreateThreadEx (threads[thread_id], attack_a0r1, &thread_parameters[thread_id], &ids[thread_id]);
    }

#ifdef WINDOWS
    SetThreadPriority (threads[thread_id], THREAD_PRIORITY_IDLE);
#endif

    ids[thread_id] = 0;
  }

#ifdef WINDOWS
  WaitForMultipleObjects (engine_parameter->num_threads, threads, TRUE, INFINITE);
#endif

  for (thread_id = 0; thread_id < engine_parameter->num_threads; thread_id++)
  {
#ifdef WINDOWS
    CloseHandle (threads[thread_id]);
#endif

#if defined LINUX || defined OSX || defined FREEBSD
    pthread_join (threads[thread_id], NULL);
#endif
  }

  if ((engine_parameter->hash_mode == 8900) || (engine_parameter->hash_mode == 9300))
  {
    for (thread_id = 0; thread_id < engine_parameter->num_threads; thread_id++)
    {
      free (thread_parameters[thread_id].scrypt_P[0]);
      free (thread_parameters[thread_id].scrypt_P[1]);
      free (thread_parameters[thread_id].scrypt_P[2]);
      free (thread_parameters[thread_id].scrypt_P[3]);

      _mm_free (thread_parameters[thread_id].scrypt_V);
      _mm_free (thread_parameters[thread_id].scrypt_X);
      _mm_free (thread_parameters[thread_id].scrypt_Y);
    }
  }
}
