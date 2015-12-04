/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

static __m128i SHA512_S0_SSE (const __m128i x)
{
  __m128i t0;
  __m128i t1;

  t1 = ROTR64_SSE (x,  34);
  t0 = ROTR64_SSE (x,  39);
//  t0 = _mm_xor_si128    (t0, t1);
  t0 ^= t1;
  t1 = ROTR64_SSE (x,  28);
//  t0 = _mm_xor_si128    (t0, t1);
  t0 ^= t1;

  return t0;
}

static __m128i SHA512_S1_SSE (const __m128i x)
{
  __m128i t0;
  __m128i t1;

  t1 = ROTR64_SSE (x,  41);
  t0 = ROTR64_SSE (x,  18);
//  t0 = _mm_xor_si128    (t0, t1);
  t0 ^= t1;
  t1 = ROTR64_SSE (x,  14);
//  t0 = _mm_xor_si128    (t0, t1);
  t0 ^= t1;

  return t0;
}

static __m128i SHA512_S2_SSE (const __m128i x)
{
  __m128i t0;
  __m128i t1;

  t1 = SHR64_SSE  (x,   7);
  t0 = ROTR64_SSE (x,   8);
//  t0 = _mm_xor_si128    (t0, t1);
  t0 ^= t1;
  t1 = ROTR64_SSE (x,   1);
//  t0 = _mm_xor_si128    (t0, t1);
  t0 ^= t1;

  return t0;
}

static __m128i SHA512_S3_SSE (const __m128i x)
{
  __m128i t0;
  __m128i t1;

  t1 = SHR64_SSE  (x,   6);
  t0 = ROTR64_SSE (x,  61);
//  t0 = _mm_xor_si128    (t0, t1);
  t0 ^= t1;
  t1 = ROTR64_SSE (x,  19);
//  t0 = _mm_xor_si128    (t0, t1);
  t0 ^= t1;

  return t0;
}

#if __XOP__
static __m128i SHA512_F1_SSE (const __m128i x, const __m128i y, const __m128i z)
{
  __m128i t0;
  __m128i t1;

  t1 = _mm_xor_si128  (y, z);
  t0 = _mm_cmov_si128 (x, y, t1);

  return t0;
}
#else
static __m128i SHA512_F1_SSE (const __m128i x, const __m128i y, const __m128i z)
{
  __m128i t0;
  __m128i t1;

  t1 = _mm_and_si128 (x,  y);
  t0 = _mm_or_si128  (x,  y);
//  t0 = _mm_and_si128 (z,  t0);
  t0 &= z;
  t0 = _mm_or_si128  (t0, t1);

  return t0;
}
#endif

#if __XOP__
static __m128i SHA512_F0_SSE (const __m128i x, const __m128i y, const __m128i z)
{
  __m128i t0;

  t0 = _mm_cmov_si128 (y, z, x);

  return t0;
}
#else
static __m128i SHA512_F0_SSE (const __m128i x, const __m128i y, const __m128i z)
{
  __m128i t0;

  t0 = _mm_xor_si128 (y,  z);
//  t0 = _mm_and_si128 (t0, x);
  t0 &= x;
//  t0 = _mm_xor_si128 (t0, z);
  t0 ^= z;

  return t0;
}
#endif



#define SHA512_STEP_SSE(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                                   \
  __m128i t0;                                       \
  __m128i t1;                                       \
  t0 = _mm_set1_epi64 ((__m64) K);                  \
  t0 = _mm_add_epi64 (t0, h);                       \
  t0 = _mm_add_epi64 (t0, W[x & 0xf]);              \
  t1 = SHA512_S1_SSE (e);                           \
  t0 = _mm_add_epi64 (t0, t1);                      \
  t1 = F0 (e, f, g);                                \
  t0 = _mm_add_epi64 (t0, t1);                      \
  d  = _mm_add_epi64 (d, t0);                       \
  t1 = SHA512_S0_SSE (a);                           \
  t0 = _mm_add_epi64 (t0, t1);                      \
  t1 = F1 (a, b, c);                                \
  h  = _mm_add_epi64 (t0, t1);                      \
}

#define SHA512_EXPAND_SSE(i)                  \
{                                             \
  __m128i t0;                                 \
  __m128i t1;                                 \
  t0 = SHA512_S3_SSE (W[(i - 2) & 0xf]);      \
  t0 = _mm_add_epi64 (t0, W[(i - 7) & 0xf]);  \
  t1 = SHA512_S2_SSE (W[(i - 15) & 0xf]);     \
  t0 = _mm_add_epi64 (t0, t1);                \
  t0 = _mm_add_epi64 (t0, W[(i - 16) & 0xf]); \
  W[(i) & 0xf] = t0;                          \
}

void hashcat_sha512_64 (__m128i digests[8], __m128i W[16])
{
  __m128i a = digests[0];
  __m128i b = digests[1];
  __m128i c = digests[2];
  __m128i d = digests[3];
  __m128i e = digests[4];
  __m128i f = digests[5];
  __m128i g = digests[6];
  __m128i h = digests[7];

  int i;

  for (i = 0; i < 16; i++) W[i] = SWAP64_SSE (W[i]);

  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h,  0, SHA512C00);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g,  1, SHA512C01);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f,  2, SHA512C02);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e,  3, SHA512C03);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d,  4, SHA512C04);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c,  5, SHA512C05);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b,  6, SHA512C06);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a,  7, SHA512C07);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h,  8, SHA512C08);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g,  9, SHA512C09);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 10, SHA512C0a);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 11, SHA512C0b);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 12, SHA512C0c);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 13, SHA512C0d);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 14, SHA512C0e);
  SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 15, SHA512C0f);

  SHA512_EXPAND_SSE (16); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h, 16, SHA512C10);
  SHA512_EXPAND_SSE (17); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g, 17, SHA512C11);
  SHA512_EXPAND_SSE (18); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 18, SHA512C12);
  SHA512_EXPAND_SSE (19); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 19, SHA512C13);
  SHA512_EXPAND_SSE (20); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 20, SHA512C14);
  SHA512_EXPAND_SSE (21); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 21, SHA512C15);
  SHA512_EXPAND_SSE (22); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 22, SHA512C16);
  SHA512_EXPAND_SSE (23); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 23, SHA512C17);
  SHA512_EXPAND_SSE (24); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h, 24, SHA512C18);
  SHA512_EXPAND_SSE (25); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g, 25, SHA512C19);
  SHA512_EXPAND_SSE (26); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 26, SHA512C1a);
  SHA512_EXPAND_SSE (27); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 27, SHA512C1b);
  SHA512_EXPAND_SSE (28); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 28, SHA512C1c);
  SHA512_EXPAND_SSE (29); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 29, SHA512C1d);
  SHA512_EXPAND_SSE (30); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 30, SHA512C1e);
  SHA512_EXPAND_SSE (31); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 31, SHA512C1f);
  SHA512_EXPAND_SSE (32); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h, 32, SHA512C20);
  SHA512_EXPAND_SSE (33); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g, 33, SHA512C21);
  SHA512_EXPAND_SSE (34); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 34, SHA512C22);
  SHA512_EXPAND_SSE (35); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 35, SHA512C23);
  SHA512_EXPAND_SSE (36); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 36, SHA512C24);
  SHA512_EXPAND_SSE (37); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 37, SHA512C25);
  SHA512_EXPAND_SSE (38); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 38, SHA512C26);
  SHA512_EXPAND_SSE (39); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 39, SHA512C27);
  SHA512_EXPAND_SSE (40); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h, 40, SHA512C28);
  SHA512_EXPAND_SSE (41); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g, 41, SHA512C29);
  SHA512_EXPAND_SSE (42); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 42, SHA512C2a);
  SHA512_EXPAND_SSE (43); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 43, SHA512C2b);
  SHA512_EXPAND_SSE (44); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 44, SHA512C2c);
  SHA512_EXPAND_SSE (45); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 45, SHA512C2d);
  SHA512_EXPAND_SSE (46); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 46, SHA512C2e);
  SHA512_EXPAND_SSE (47); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 47, SHA512C2f);
  SHA512_EXPAND_SSE (48); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h, 48, SHA512C30);
  SHA512_EXPAND_SSE (49); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g, 49, SHA512C31);
  SHA512_EXPAND_SSE (50); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 50, SHA512C32);
  SHA512_EXPAND_SSE (51); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 51, SHA512C33);
  SHA512_EXPAND_SSE (52); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 52, SHA512C34);
  SHA512_EXPAND_SSE (53); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 53, SHA512C35);
  SHA512_EXPAND_SSE (54); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 54, SHA512C36);
  SHA512_EXPAND_SSE (55); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 55, SHA512C37);
  SHA512_EXPAND_SSE (56); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h, 56, SHA512C38);
  SHA512_EXPAND_SSE (57); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g, 57, SHA512C39);
  SHA512_EXPAND_SSE (58); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 58, SHA512C3a);
  SHA512_EXPAND_SSE (59); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 59, SHA512C3b);
  SHA512_EXPAND_SSE (60); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 60, SHA512C3c);
  SHA512_EXPAND_SSE (61); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 61, SHA512C3d);
  SHA512_EXPAND_SSE (62); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 62, SHA512C3e);
  SHA512_EXPAND_SSE (63); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 63, SHA512C3f);
  SHA512_EXPAND_SSE (64); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h, 64, SHA512C40);
  SHA512_EXPAND_SSE (65); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g, 65, SHA512C41);
  SHA512_EXPAND_SSE (66); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 66, SHA512C42);
  SHA512_EXPAND_SSE (67); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 67, SHA512C43);
  SHA512_EXPAND_SSE (68); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 68, SHA512C44);
  SHA512_EXPAND_SSE (69); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 69, SHA512C45);
  SHA512_EXPAND_SSE (70); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 70, SHA512C46);
  SHA512_EXPAND_SSE (71); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 71, SHA512C47);
  SHA512_EXPAND_SSE (72); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, a, b, c, d, e, f, g, h, 72, SHA512C48);
  SHA512_EXPAND_SSE (73); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, h, a, b, c, d, e, f, g, 73, SHA512C49);
  SHA512_EXPAND_SSE (74); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, g, h, a, b, c, d, e, f, 74, SHA512C4a);
  SHA512_EXPAND_SSE (75); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, f, g, h, a, b, c, d, e, 75, SHA512C4b);
  SHA512_EXPAND_SSE (76); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, e, f, g, h, a, b, c, d, 76, SHA512C4c);
  SHA512_EXPAND_SSE (77); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, d, e, f, g, h, a, b, c, 77, SHA512C4d);
  SHA512_EXPAND_SSE (78); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, c, d, e, f, g, h, a, b, 78, SHA512C4e);
  SHA512_EXPAND_SSE (79); SHA512_STEP_SSE (SHA512_F0_SSE, SHA512_F1_SSE, b, c, d, e, f, g, h, a, 79, SHA512C4f);

  digests[0] = _mm_add_epi64 (a, digests[0]);
  digests[1] = _mm_add_epi64 (b, digests[1]);
  digests[2] = _mm_add_epi64 (c, digests[2]);
  digests[3] = _mm_add_epi64 (d, digests[3]);
  digests[4] = _mm_add_epi64 (e, digests[4]);
  digests[5] = _mm_add_epi64 (f, digests[5]);
  digests[6] = _mm_add_epi64 (g, digests[6]);
  digests[7] = _mm_add_epi64 (h, digests[7]);
}
