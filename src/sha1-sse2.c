/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifdef __XOP__
#define SHA1_F0(x,y,z) _mm_cmov_si128 (y, z, x)
#else
#define SHA1_F0(x,y,z) _mm_or_si128 (_mm_and_si128 (x, y), _mm_andnot_si128 (x, z))
#endif

#define SHA1_F1(x,y,z) _mm_xor_si128 (z, _mm_xor_si128 (x, y))

#ifdef __XOP__
#define SHA1_F2(x,y,z) _mm_cmov_si128 (x, z, _mm_xor_si128 (y, z))
#else
#define SHA1_F2(x,y,z) _mm_or_si128 (_mm_and_si128 (z, _mm_or_si128 (x, y)), _mm_and_si128 (x, y))
#endif

#define SHA1_STEP(f,a,b,c,d,e,x)                  \
{                                                 \
  e = _mm_add_epi32 (e, K);                       \
  e = _mm_add_epi32 (e, W[x & 0xf]);              \
  e = _mm_add_epi32 (e, f (b, c, d));             \
  e = _mm_add_epi32 (e, ROTL32_SSE (a, 5));       \
  b = ROTL32_SSE    (b, 30);                      \
}

#define SHA1_EXPAND(i) W[(i) & 0xf] = ROTL32_SSE ((W[((i) - 16) & 0xf] ^ W[((i) - 14) & 0xf] ^ W[((i) - 8) & 0xf] ^ W[((i) - 3) & 0xf]), 1)

void hashcat_sha1_64 (__m128i digests[5], __m128i W[16])
{
  __m128i a = digests[0];
  __m128i b = digests[1];
  __m128i c = digests[2];
  __m128i d = digests[3];
  __m128i e = digests[4];

  int i;

  for (i = 0; i < 16; i++) W[i] = SWAP32_SSE (W[i]);

  __m128i K;

  K = _mm_set1_epi32 (SHA1C00);

  SHA1_STEP (SHA1_F0, a, b, c, d, e,  0);
  SHA1_STEP (SHA1_F0, e, a, b, c, d,  1);
  SHA1_STEP (SHA1_F0, d, e, a, b, c,  2);
  SHA1_STEP (SHA1_F0, c, d, e, a, b,  3);
  SHA1_STEP (SHA1_F0, b, c, d, e, a,  4);
  SHA1_STEP (SHA1_F0, a, b, c, d, e,  5);
  SHA1_STEP (SHA1_F0, e, a, b, c, d,  6);
  SHA1_STEP (SHA1_F0, d, e, a, b, c,  7);
  SHA1_STEP (SHA1_F0, c, d, e, a, b,  8);
  SHA1_STEP (SHA1_F0, b, c, d, e, a,  9);
  SHA1_STEP (SHA1_F0, a, b, c, d, e, 10);
  SHA1_STEP (SHA1_F0, e, a, b, c, d, 11);
  SHA1_STEP (SHA1_F0, d, e, a, b, c, 12);
  SHA1_STEP (SHA1_F0, c, d, e, a, b, 13);
  SHA1_STEP (SHA1_F0, b, c, d, e, a, 14);
  SHA1_STEP (SHA1_F0, a, b, c, d, e, 15);

  SHA1_EXPAND (16); SHA1_STEP (SHA1_F0, e, a, b, c, d, 16);
  SHA1_EXPAND (17); SHA1_STEP (SHA1_F0, d, e, a, b, c, 17);
  SHA1_EXPAND (18); SHA1_STEP (SHA1_F0, c, d, e, a, b, 18);
  SHA1_EXPAND (19); SHA1_STEP (SHA1_F0, b, c, d, e, a, 19);

  K = _mm_set1_epi32 (SHA1C01);

  SHA1_EXPAND (20); SHA1_STEP (SHA1_F1, a, b, c, d, e, 20);
  SHA1_EXPAND (21); SHA1_STEP (SHA1_F1, e, a, b, c, d, 21);
  SHA1_EXPAND (22); SHA1_STEP (SHA1_F1, d, e, a, b, c, 22);
  SHA1_EXPAND (23); SHA1_STEP (SHA1_F1, c, d, e, a, b, 23);
  SHA1_EXPAND (24); SHA1_STEP (SHA1_F1, b, c, d, e, a, 24);
  SHA1_EXPAND (25); SHA1_STEP (SHA1_F1, a, b, c, d, e, 25);
  SHA1_EXPAND (26); SHA1_STEP (SHA1_F1, e, a, b, c, d, 26);
  SHA1_EXPAND (27); SHA1_STEP (SHA1_F1, d, e, a, b, c, 27);
  SHA1_EXPAND (28); SHA1_STEP (SHA1_F1, c, d, e, a, b, 28);
  SHA1_EXPAND (29); SHA1_STEP (SHA1_F1, b, c, d, e, a, 29);
  SHA1_EXPAND (30); SHA1_STEP (SHA1_F1, a, b, c, d, e, 30);
  SHA1_EXPAND (31); SHA1_STEP (SHA1_F1, e, a, b, c, d, 31);
  SHA1_EXPAND (32); SHA1_STEP (SHA1_F1, d, e, a, b, c, 32);
  SHA1_EXPAND (33); SHA1_STEP (SHA1_F1, c, d, e, a, b, 33);
  SHA1_EXPAND (34); SHA1_STEP (SHA1_F1, b, c, d, e, a, 34);
  SHA1_EXPAND (35); SHA1_STEP (SHA1_F1, a, b, c, d, e, 35);
  SHA1_EXPAND (36); SHA1_STEP (SHA1_F1, e, a, b, c, d, 36);
  SHA1_EXPAND (37); SHA1_STEP (SHA1_F1, d, e, a, b, c, 37);
  SHA1_EXPAND (38); SHA1_STEP (SHA1_F1, c, d, e, a, b, 38);
  SHA1_EXPAND (39); SHA1_STEP (SHA1_F1, b, c, d, e, a, 39);

  K = _mm_set1_epi32 (SHA1C02);

  SHA1_EXPAND (40); SHA1_STEP (SHA1_F2, a, b, c, d, e, 40);
  SHA1_EXPAND (41); SHA1_STEP (SHA1_F2, e, a, b, c, d, 41);
  SHA1_EXPAND (42); SHA1_STEP (SHA1_F2, d, e, a, b, c, 42);
  SHA1_EXPAND (43); SHA1_STEP (SHA1_F2, c, d, e, a, b, 43);
  SHA1_EXPAND (44); SHA1_STEP (SHA1_F2, b, c, d, e, a, 44);
  SHA1_EXPAND (45); SHA1_STEP (SHA1_F2, a, b, c, d, e, 45);
  SHA1_EXPAND (46); SHA1_STEP (SHA1_F2, e, a, b, c, d, 46);
  SHA1_EXPAND (47); SHA1_STEP (SHA1_F2, d, e, a, b, c, 47);
  SHA1_EXPAND (48); SHA1_STEP (SHA1_F2, c, d, e, a, b, 48);
  SHA1_EXPAND (49); SHA1_STEP (SHA1_F2, b, c, d, e, a, 49);
  SHA1_EXPAND (50); SHA1_STEP (SHA1_F2, a, b, c, d, e, 50);
  SHA1_EXPAND (51); SHA1_STEP (SHA1_F2, e, a, b, c, d, 51);
  SHA1_EXPAND (52); SHA1_STEP (SHA1_F2, d, e, a, b, c, 52);
  SHA1_EXPAND (53); SHA1_STEP (SHA1_F2, c, d, e, a, b, 53);
  SHA1_EXPAND (54); SHA1_STEP (SHA1_F2, b, c, d, e, a, 54);
  SHA1_EXPAND (55); SHA1_STEP (SHA1_F2, a, b, c, d, e, 55);
  SHA1_EXPAND (56); SHA1_STEP (SHA1_F2, e, a, b, c, d, 56);
  SHA1_EXPAND (57); SHA1_STEP (SHA1_F2, d, e, a, b, c, 57);
  SHA1_EXPAND (58); SHA1_STEP (SHA1_F2, c, d, e, a, b, 58);
  SHA1_EXPAND (59); SHA1_STEP (SHA1_F2, b, c, d, e, a, 59);

  K = _mm_set1_epi32 (SHA1C03);

  SHA1_EXPAND (60); SHA1_STEP (SHA1_F1, a, b, c, d, e, 60);
  SHA1_EXPAND (61); SHA1_STEP (SHA1_F1, e, a, b, c, d, 61);
  SHA1_EXPAND (62); SHA1_STEP (SHA1_F1, d, e, a, b, c, 62);
  SHA1_EXPAND (63); SHA1_STEP (SHA1_F1, c, d, e, a, b, 63);
  SHA1_EXPAND (64); SHA1_STEP (SHA1_F1, b, c, d, e, a, 64);
  SHA1_EXPAND (65); SHA1_STEP (SHA1_F1, a, b, c, d, e, 65);
  SHA1_EXPAND (66); SHA1_STEP (SHA1_F1, e, a, b, c, d, 66);
  SHA1_EXPAND (67); SHA1_STEP (SHA1_F1, d, e, a, b, c, 67);
  SHA1_EXPAND (68); SHA1_STEP (SHA1_F1, c, d, e, a, b, 68);
  SHA1_EXPAND (69); SHA1_STEP (SHA1_F1, b, c, d, e, a, 69);
  SHA1_EXPAND (70); SHA1_STEP (SHA1_F1, a, b, c, d, e, 70);
  SHA1_EXPAND (71); SHA1_STEP (SHA1_F1, e, a, b, c, d, 71);
  SHA1_EXPAND (72); SHA1_STEP (SHA1_F1, d, e, a, b, c, 72);
  SHA1_EXPAND (73); SHA1_STEP (SHA1_F1, c, d, e, a, b, 73);
  SHA1_EXPAND (74); SHA1_STEP (SHA1_F1, b, c, d, e, a, 74);
  SHA1_EXPAND (75); SHA1_STEP (SHA1_F1, a, b, c, d, e, 75);
  SHA1_EXPAND (76); SHA1_STEP (SHA1_F1, e, a, b, c, d, 76);
  SHA1_EXPAND (77); SHA1_STEP (SHA1_F1, d, e, a, b, c, 77);
  SHA1_EXPAND (78); SHA1_STEP (SHA1_F1, c, d, e, a, b, 78);
  SHA1_EXPAND (79); SHA1_STEP (SHA1_F1, b, c, d, e, a, 79);

  digests[0] = _mm_add_epi32 (a, digests[0]);
  digests[1] = _mm_add_epi32 (b, digests[1]);
  digests[2] = _mm_add_epi32 (c, digests[2]);
  digests[3] = _mm_add_epi32 (d, digests[3]);
  digests[4] = _mm_add_epi32 (e, digests[4]);
}
