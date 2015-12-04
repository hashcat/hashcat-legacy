/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define SHA256_S0_SSE(x) (_mm_xor_si128(ROTL32_SSE ((x), 25), _mm_xor_si128(ROTL32_SSE ((x), 14),SHR32_SSE  ((x),  3))))
#define SHA256_S1_SSE(x) (_mm_xor_si128(ROTL32_SSE ((x), 15), _mm_xor_si128(ROTL32_SSE ((x), 13),SHR32_SSE  ((x), 10))))
#define SHA256_S2_SSE(x) (_mm_xor_si128(ROTL32_SSE ((x), 30), _mm_xor_si128(ROTL32_SSE ((x), 19),ROTL32_SSE ((x), 10))))
#define SHA256_S3_SSE(x) (_mm_xor_si128(ROTL32_SSE ((x), 26), _mm_xor_si128(ROTL32_SSE ((x), 21),ROTL32_SSE ((x),  7))))

#ifdef __XOP__
#define SHA256_F0_SSE(x,y,z) _mm_cmov_si128 (x, z, _mm_xor_si128 (y, z))
#else
#define SHA256_F0_SSE(x,y,z) _mm_or_si128 (_mm_and_si128 (z, _mm_or_si128 (x, y)), _mm_and_si128 (x, y))
#endif

#ifdef __XOP__
#define SHA256_F1_SSE(x,y,z) _mm_cmov_si128 (y, z, x)
#else
#define SHA256_F1_SSE(x,y,z) _mm_xor_si128 (z, _mm_and_si128 (x, _mm_xor_si128 (y, z)))
#endif

#define SHA256_STEP_SSE(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                                   \
  h = _mm_add_epi32 (h, _mm_set1_epi32 (K));        \
  h = _mm_add_epi32 (h, W[x & 0xf]);                \
  h = _mm_add_epi32 (h, SHA256_S3_SSE (e));         \
  h = _mm_add_epi32 (h, F1 (e,f,g));                \
  d = _mm_add_epi32 (d, h);                         \
  h = _mm_add_epi32 (h, SHA256_S2_SSE (a));         \
  h = _mm_add_epi32 (h, F0 (a,b,c));                \
}

#define SHA256_EXPAND_SSE(i)                        \
{                                                   \
  __m128i t0;                                       \
  __m128i t1;                                       \
  t0 = SHA256_S1_SSE (W[(i - 2) & 0xf]);            \
  t0 = _mm_add_epi32 (t0, W[(i - 7) & 0xf]);        \
  t1 = SHA256_S0_SSE (W[(i - 15) & 0xf]);           \
  t0 = _mm_add_epi32 (t0, t1);                      \
  t0 = _mm_add_epi32 (t0, W[(i - 16) & 0xf]);       \
  W[(i) & 0xf] = t0;                                \
}

void hashcat_sha256_64 (__m128i digests[8], __m128i W[16])
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

  for (i = 0; i < 16; i++) W[i] = SWAP32_SSE (W[i]);

  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, a, b, c, d, e, f, g, h,  0, SHA256C00);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, h, a, b, c, d, e, f, g,  1, SHA256C01);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, g, h, a, b, c, d, e, f,  2, SHA256C02);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, f, g, h, a, b, c, d, e,  3, SHA256C03);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, e, f, g, h, a, b, c, d,  4, SHA256C04);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, d, e, f, g, h, a, b, c,  5, SHA256C05);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, c, d, e, f, g, h, a, b,  6, SHA256C06);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, b, c, d, e, f, g, h, a,  7, SHA256C07);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, a, b, c, d, e, f, g, h,  8, SHA256C08);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, h, a, b, c, d, e, f, g,  9, SHA256C09);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, g, h, a, b, c, d, e, f, 10, SHA256C0a);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, f, g, h, a, b, c, d, e, 11, SHA256C0b);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, e, f, g, h, a, b, c, d, 12, SHA256C0c);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, d, e, f, g, h, a, b, c, 13, SHA256C0d);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, c, d, e, f, g, h, a, b, 14, SHA256C0e);
  SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, b, c, d, e, f, g, h, a, 15, SHA256C0f);

  SHA256_EXPAND_SSE (16); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, a, b, c, d, e, f, g, h, 16, SHA256C10);
  SHA256_EXPAND_SSE (17); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, h, a, b, c, d, e, f, g, 17, SHA256C11);
  SHA256_EXPAND_SSE (18); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, g, h, a, b, c, d, e, f, 18, SHA256C12);
  SHA256_EXPAND_SSE (19); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, f, g, h, a, b, c, d, e, 19, SHA256C13);
  SHA256_EXPAND_SSE (20); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, e, f, g, h, a, b, c, d, 20, SHA256C14);
  SHA256_EXPAND_SSE (21); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, d, e, f, g, h, a, b, c, 21, SHA256C15);
  SHA256_EXPAND_SSE (22); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, c, d, e, f, g, h, a, b, 22, SHA256C16);
  SHA256_EXPAND_SSE (23); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, b, c, d, e, f, g, h, a, 23, SHA256C17);
  SHA256_EXPAND_SSE (24); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, a, b, c, d, e, f, g, h, 24, SHA256C18);
  SHA256_EXPAND_SSE (25); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, h, a, b, c, d, e, f, g, 25, SHA256C19);
  SHA256_EXPAND_SSE (26); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, g, h, a, b, c, d, e, f, 26, SHA256C1a);
  SHA256_EXPAND_SSE (27); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, f, g, h, a, b, c, d, e, 27, SHA256C1b);
  SHA256_EXPAND_SSE (28); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, e, f, g, h, a, b, c, d, 28, SHA256C1c);
  SHA256_EXPAND_SSE (29); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, d, e, f, g, h, a, b, c, 29, SHA256C1d);
  SHA256_EXPAND_SSE (30); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, c, d, e, f, g, h, a, b, 30, SHA256C1e);
  SHA256_EXPAND_SSE (31); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, b, c, d, e, f, g, h, a, 31, SHA256C1f);
  SHA256_EXPAND_SSE (32); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, a, b, c, d, e, f, g, h, 32, SHA256C20);
  SHA256_EXPAND_SSE (33); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, h, a, b, c, d, e, f, g, 33, SHA256C21);
  SHA256_EXPAND_SSE (34); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, g, h, a, b, c, d, e, f, 34, SHA256C22);
  SHA256_EXPAND_SSE (35); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, f, g, h, a, b, c, d, e, 35, SHA256C23);
  SHA256_EXPAND_SSE (36); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, e, f, g, h, a, b, c, d, 36, SHA256C24);
  SHA256_EXPAND_SSE (37); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, d, e, f, g, h, a, b, c, 37, SHA256C25);
  SHA256_EXPAND_SSE (38); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, c, d, e, f, g, h, a, b, 38, SHA256C26);
  SHA256_EXPAND_SSE (39); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, b, c, d, e, f, g, h, a, 39, SHA256C27);
  SHA256_EXPAND_SSE (40); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, a, b, c, d, e, f, g, h, 40, SHA256C28);
  SHA256_EXPAND_SSE (41); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, h, a, b, c, d, e, f, g, 41, SHA256C29);
  SHA256_EXPAND_SSE (42); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, g, h, a, b, c, d, e, f, 42, SHA256C2a);
  SHA256_EXPAND_SSE (43); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, f, g, h, a, b, c, d, e, 43, SHA256C2b);
  SHA256_EXPAND_SSE (44); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, e, f, g, h, a, b, c, d, 44, SHA256C2c);
  SHA256_EXPAND_SSE (45); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, d, e, f, g, h, a, b, c, 45, SHA256C2d);
  SHA256_EXPAND_SSE (46); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, c, d, e, f, g, h, a, b, 46, SHA256C2e);
  SHA256_EXPAND_SSE (47); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, b, c, d, e, f, g, h, a, 47, SHA256C2f);
  SHA256_EXPAND_SSE (48); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, a, b, c, d, e, f, g, h, 48, SHA256C30);
  SHA256_EXPAND_SSE (49); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, h, a, b, c, d, e, f, g, 49, SHA256C31);
  SHA256_EXPAND_SSE (50); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, g, h, a, b, c, d, e, f, 50, SHA256C32);
  SHA256_EXPAND_SSE (51); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, f, g, h, a, b, c, d, e, 51, SHA256C33);
  SHA256_EXPAND_SSE (52); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, e, f, g, h, a, b, c, d, 52, SHA256C34);
  SHA256_EXPAND_SSE (53); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, d, e, f, g, h, a, b, c, 53, SHA256C35);
  SHA256_EXPAND_SSE (54); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, c, d, e, f, g, h, a, b, 54, SHA256C36);
  SHA256_EXPAND_SSE (55); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, b, c, d, e, f, g, h, a, 55, SHA256C37);
  SHA256_EXPAND_SSE (56); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, a, b, c, d, e, f, g, h, 56, SHA256C38);
  SHA256_EXPAND_SSE (57); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, h, a, b, c, d, e, f, g, 57, SHA256C39);
  SHA256_EXPAND_SSE (58); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, g, h, a, b, c, d, e, f, 58, SHA256C3a);
  SHA256_EXPAND_SSE (59); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, f, g, h, a, b, c, d, e, 59, SHA256C3b);
  SHA256_EXPAND_SSE (60); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, e, f, g, h, a, b, c, d, 60, SHA256C3c);
  SHA256_EXPAND_SSE (61); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, d, e, f, g, h, a, b, c, 61, SHA256C3d);
  SHA256_EXPAND_SSE (62); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, c, d, e, f, g, h, a, b, 62, SHA256C3e);
  SHA256_EXPAND_SSE (63); SHA256_STEP_SSE (SHA256_F0_SSE, SHA256_F1_SSE, b, c, d, e, f, g, h, a, 63, SHA256C3f);

  digests[0] = _mm_add_epi32 (a, digests[0]);
  digests[1] = _mm_add_epi32 (b, digests[1]);
  digests[2] = _mm_add_epi32 (c, digests[2]);
  digests[3] = _mm_add_epi32 (d, digests[3]);
  digests[4] = _mm_add_epi32 (e, digests[4]);
  digests[5] = _mm_add_epi32 (f, digests[5]);
  digests[6] = _mm_add_epi32 (g, digests[6]);
  digests[7] = _mm_add_epi32 (h, digests[7]);
}
