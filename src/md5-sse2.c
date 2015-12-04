/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifdef __XOP__
#define MD5_F(x,y,z) _mm_cmov_si128 (y, z, x)
#else
#define MD5_F(x,y,z) _mm_xor_si128 (z, _mm_and_si128 (x, _mm_xor_si128 (y, z)))
#endif

#ifdef __XOP__
#define MD5_G(x,y,z) _mm_cmov_si128 (x, y, z)
#else
#define MD5_G(x,y,z) _mm_xor_si128 (y, _mm_and_si128 (z, _mm_xor_si128 (x, y)))
#endif

#define MD5_H1(x,y,z) ((tmp2 = ((x) ^ (y))) ^ (z))
#define MD5_H2(x,y,z) ((x) ^ tmp2)

#define MD5_I(x,y,z) _mm_xor_si128 (y, _mm_or_si128 (x, ~z))

#define MD5_STEP(f,a,b,c,d,x,K,s)             \
{                                             \
  a = _mm_add_epi32 (a, _mm_set1_epi32 (K));  \
  a = _mm_add_epi32 (a, x);                   \
  a = _mm_add_epi32 (a, f (b, c, d));         \
  a = ROTL32_SSE    (a, s);                   \
  a = _mm_add_epi32 (a, b);                   \
}

void hashcat_md5_64 (__m128i digests[4], __m128i W[16])
{
  __m128i a = digests[0];
  __m128i b = digests[1];
  __m128i c = digests[2];
  __m128i d = digests[3];

  __m128i tmp2;

  MD5_STEP (MD5_F , a, b, c, d, W[ 0], MD5C00, MD5S00);
  MD5_STEP (MD5_F , d, a, b, c, W[ 1], MD5C01, MD5S01);
  MD5_STEP (MD5_F , c, d, a, b, W[ 2], MD5C02, MD5S02);
  MD5_STEP (MD5_F , b, c, d, a, W[ 3], MD5C03, MD5S03);
  MD5_STEP (MD5_F , a, b, c, d, W[ 4], MD5C04, MD5S00);
  MD5_STEP (MD5_F , d, a, b, c, W[ 5], MD5C05, MD5S01);
  MD5_STEP (MD5_F , c, d, a, b, W[ 6], MD5C06, MD5S02);
  MD5_STEP (MD5_F , b, c, d, a, W[ 7], MD5C07, MD5S03);
  MD5_STEP (MD5_F , a, b, c, d, W[ 8], MD5C08, MD5S00);
  MD5_STEP (MD5_F , d, a, b, c, W[ 9], MD5C09, MD5S01);
  MD5_STEP (MD5_F , c, d, a, b, W[10], MD5C0a, MD5S02);
  MD5_STEP (MD5_F , b, c, d, a, W[11], MD5C0b, MD5S03);
  MD5_STEP (MD5_F , a, b, c, d, W[12], MD5C0c, MD5S00);
  MD5_STEP (MD5_F , d, a, b, c, W[13], MD5C0d, MD5S01);
  MD5_STEP (MD5_F , c, d, a, b, W[14], MD5C0e, MD5S02);
  MD5_STEP (MD5_F , b, c, d, a, W[15], MD5C0f, MD5S03);

  MD5_STEP (MD5_G , a, b, c, d, W[ 1], MD5C10, MD5S10);
  MD5_STEP (MD5_G , d, a, b, c, W[ 6], MD5C11, MD5S11);
  MD5_STEP (MD5_G , c, d, a, b, W[11], MD5C12, MD5S12);
  MD5_STEP (MD5_G , b, c, d, a, W[ 0], MD5C13, MD5S13);
  MD5_STEP (MD5_G , a, b, c, d, W[ 5], MD5C14, MD5S10);
  MD5_STEP (MD5_G , d, a, b, c, W[10], MD5C15, MD5S11);
  MD5_STEP (MD5_G , c, d, a, b, W[15], MD5C16, MD5S12);
  MD5_STEP (MD5_G , b, c, d, a, W[ 4], MD5C17, MD5S13);
  MD5_STEP (MD5_G , a, b, c, d, W[ 9], MD5C18, MD5S10);
  MD5_STEP (MD5_G , d, a, b, c, W[14], MD5C19, MD5S11);
  MD5_STEP (MD5_G , c, d, a, b, W[ 3], MD5C1a, MD5S12);
  MD5_STEP (MD5_G , b, c, d, a, W[ 8], MD5C1b, MD5S13);
  MD5_STEP (MD5_G , a, b, c, d, W[13], MD5C1c, MD5S10);
  MD5_STEP (MD5_G , d, a, b, c, W[ 2], MD5C1d, MD5S11);
  MD5_STEP (MD5_G , c, d, a, b, W[ 7], MD5C1e, MD5S12);
  MD5_STEP (MD5_G , b, c, d, a, W[12], MD5C1f, MD5S13);

  MD5_STEP (MD5_H1, a, b, c, d, W[ 5], MD5C20, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, W[ 8], MD5C21, MD5S21);
  MD5_STEP (MD5_H1, c, d, a, b, W[11], MD5C22, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, W[14], MD5C23, MD5S23);
  MD5_STEP (MD5_H1, a, b, c, d, W[ 1], MD5C24, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, W[ 4], MD5C25, MD5S21);
  MD5_STEP (MD5_H1, c, d, a, b, W[ 7], MD5C26, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, W[10], MD5C27, MD5S23);
  MD5_STEP (MD5_H1, a, b, c, d, W[13], MD5C28, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, W[ 0], MD5C29, MD5S21);
  MD5_STEP (MD5_H1, c, d, a, b, W[ 3], MD5C2a, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, W[ 6], MD5C2b, MD5S23);
  MD5_STEP (MD5_H1, a, b, c, d, W[ 9], MD5C2c, MD5S20);
  MD5_STEP (MD5_H2, d, a, b, c, W[12], MD5C2d, MD5S21);
  MD5_STEP (MD5_H1, c, d, a, b, W[15], MD5C2e, MD5S22);
  MD5_STEP (MD5_H2, b, c, d, a, W[ 2], MD5C2f, MD5S23);

  MD5_STEP (MD5_I , a, b, c, d, W[ 0], MD5C30, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, W[ 7], MD5C31, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, W[14], MD5C32, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, W[ 5], MD5C33, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, W[12], MD5C34, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, W[ 3], MD5C35, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, W[10], MD5C36, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, W[ 1], MD5C37, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, W[ 8], MD5C38, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, W[15], MD5C39, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, W[ 6], MD5C3a, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, W[13], MD5C3b, MD5S33);
  MD5_STEP (MD5_I , a, b, c, d, W[ 4], MD5C3c, MD5S30);
  MD5_STEP (MD5_I , d, a, b, c, W[11], MD5C3d, MD5S31);
  MD5_STEP (MD5_I , c, d, a, b, W[ 2], MD5C3e, MD5S32);
  MD5_STEP (MD5_I , b, c, d, a, W[ 9], MD5C3f, MD5S33);

  digests[0] = _mm_add_epi32 (a, digests[0]);
  digests[1] = _mm_add_epi32 (b, digests[1]);
  digests[2] = _mm_add_epi32 (c, digests[2]);
  digests[3] = _mm_add_epi32 (d, digests[3]);
}
