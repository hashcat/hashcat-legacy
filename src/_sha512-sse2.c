/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define Sh_32(h,l,n) (_mm_or_si128 (_mm_srli_epi32 (h,      n), _mm_slli_epi32 (l, 32 - n)))
#define Sh_64(h,l,n) (_mm_or_si128 (_mm_slli_epi32 (h, 64 - n), _mm_srli_epi32 (l, n - 32)))
#define Rh_32(h,l,n) (_mm_srli_epi32 (h, n))
#define Rh_64(h,l,n) (0)
#define Rl_32(h,l,n) (_mm_or_si128 (_mm_slli_epi32 (h, 32 - n), _mm_srli_epi32 (l, n)))
#define Rl_64(h,l,n) (_mm_srli_epi32 (h, n - 32))
#define Sl_32(h,l,n) (_mm_or_si128 (_mm_slli_epi32 (h, 32 - n), _mm_srli_epi32 (l, n)))
#define Sl_64(h,l,n) (_mm_or_si128 (_mm_srli_epi32 (h, n - 32), _mm_slli_epi32 (l, 64 - n)))

#define SHA512_F1(x,y,z) (_mm_or_si128  (_mm_and_si128 (x, y), _mm_and_si128 (z, _mm_or_si128 (x, y))))
#define SHA512_F0(x,y,z) (_mm_xor_si128 (z, _mm_and_si128 (x, _mm_xor_si128 (y, z))))

#define SHA512_S3h(h,l) (_mm_xor_si128 (_mm_xor_si128 (Sh_32 (h, l, 19), Sh_64 (h, l, 61)), Rh_32 (h, l,  6)))
#define SHA512_S3l(h,l) (_mm_xor_si128 (_mm_xor_si128 (Sl_32 (h, l, 19), Sl_64 (h, l, 61)), Rl_32 (h, l,  6)))
#define SHA512_S2h(h,l) (_mm_xor_si128 (_mm_xor_si128 (Sh_32 (h, l,  1), Sh_32 (h, l,  8)), Rh_32 (h, l,  7)))
#define SHA512_S2l(h,l) (_mm_xor_si128 (_mm_xor_si128 (Sl_32 (h, l,  1), Sl_32 (h, l,  8)), Rl_32 (h, l,  7)))
#define SHA512_S1h(h,l) (_mm_xor_si128 (_mm_xor_si128 (Sh_32 (h, l, 14), Sh_32 (h, l, 18)), Sh_64 (h, l, 41)))
#define SHA512_S1l(h,l) (_mm_xor_si128 (_mm_xor_si128 (Sl_32 (h, l, 14), Sl_32 (h, l, 18)), Sl_64 (h, l, 41)))
#define SHA512_S0h(h,l) (_mm_xor_si128 (_mm_xor_si128 (Sh_32 (h, l, 28), Sh_64 (h, l, 34)), Sh_64 (h, l, 39)))
#define SHA512_S0l(h,l) (_mm_xor_si128 (_mm_xor_si128 (Sl_32 (h, l, 28), Sl_64 (h, l, 34)), Sl_64 (h, l, 39)))

#define ADDC(xh,xl,yh,yl)         \
{                                 \
  __m128i t1;                     \
  __m128i t2;                     \
  t1 = _mm_and_si128    (xl, yl); \
  t2 = _mm_or_si128     (xl, yl); \
  xl = _mm_add_epi32    (xl, yl); \
  t2 = _mm_andnot_si128 (xl, t2); \
  t1 = _mm_or_si128     (t1, t2); \
  t1 = _mm_srli_epi32   (t1, 31); \
  xh = _mm_add_epi32    (xh, t1); \
  xh = _mm_add_epi32    (xh, yh); \
}

#define SHA512_EXPAND(t)                                \
{                                                       \
  __m128i oh;                                           \
  __m128i ol;                                           \
  __m128i th;                                           \
  __m128i tl;                                           \
  th = SHA512_S3h (W[(t -  4) & 31], W[(t -  3) & 31]); \
  tl = SHA512_S3l (W[(t -  4) & 31], W[(t -  3) & 31]); \
  oh = th; ol = tl;                                     \
  th = W[(t - 14) & 31];                                \
  tl = W[(t - 13) & 31];                                \
  ADDC (oh, ol, th, tl);                                \
  th = SHA512_S2h (W[(t - 30) & 31], W[(t - 29) & 31]); \
  tl = SHA512_S2l (W[(t - 30) & 31], W[(t - 29) & 31]); \
  ADDC (oh, ol, th, tl);                                \
  th = W[(t - 32) & 31];                                \
  tl = W[(t - 31) & 31];                                \
  ADDC (oh, ol, th, tl);                                \
  W[(t + 0) & 31] = oh;                                 \
  W[(t + 1) & 31] = ol;                                 \
}

#define SHA512_ROUND(t, a0, a1, b0, b1, c0, c1, d0, d1, e0, e1, f0, f1, g0, g1, h0, h1) \
{                                                   \
  __m128i oh;                                       \
  __m128i ol;                                       \
  __m128i tl;                                       \
  __m128i th;                                       \
  th = sha512_const[t + 0];                         \
  tl = sha512_const[t + 1];                         \
  oh = th; ol = tl;                                 \
  th = W[(t + 0) & 31];                             \
  tl = W[(t + 1) & 31];                             \
  ADDC (oh, ol, th, tl);                            \
  th = h0;                                          \
  tl = h1;                                          \
  ADDC (oh, ol, th, tl);                            \
  th = SHA512_S1h (e0, e1);                         \
  tl = SHA512_S1l (e0, e1);                         \
  ADDC (oh, ol, th, tl);                            \
  th = SHA512_F0 (e0, f0, g0);                      \
  tl = SHA512_F0 (e1, f1, g1);                      \
  ADDC (oh, ol, th, tl);                            \
  ADDC (d0, d1, oh, ol);                            \
  th = SHA512_S0h (a0, a1);                         \
  tl = SHA512_S0l (a0, a1);                         \
  ADDC (oh, ol, th, tl);                            \
  th = SHA512_F1 (a0, b0, c0);                      \
  tl = SHA512_F1 (a1, b1, c1);                      \
  ADDC (oh, ol, th, tl);                            \
  h0 = oh;                                          \
  h1 = ol;                                          \
}

static const uint32_t SHA512_MAGIC[16] =
{
  0x6a09e667,
  0xf3bcc908,
  0xbb67ae85,
  0x84caa73b,
  0x3c6ef372,
  0xfe94f82b,
  0xa54ff53a,
  0x5f1d36f1,
  0x510e527f,
  0xade682d1,
  0x9b05688c,
  0x2b3e6c1f,
  0x1f83d9ab,
  0xfb41bd6b,
  0x5be0cd19,
  0x137e2179,
};

static const uint32_t SHA512_CONST[160][4] __attribute__ ((aligned (16))) =
{
  { 0x428a2f98, 0x428a2f98, 0x428a2f98, 0x428a2f98 },
  { 0xd728ae22, 0xd728ae22, 0xd728ae22, 0xd728ae22 },
  { 0x71374491, 0x71374491, 0x71374491, 0x71374491 },
  { 0x23ef65cd, 0x23ef65cd, 0x23ef65cd, 0x23ef65cd },
  { 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf, 0xb5c0fbcf },
  { 0xec4d3b2f, 0xec4d3b2f, 0xec4d3b2f, 0xec4d3b2f },
  { 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5, 0xe9b5dba5 },
  { 0x8189dbbc, 0x8189dbbc, 0x8189dbbc, 0x8189dbbc },
  { 0x3956c25b, 0x3956c25b, 0x3956c25b, 0x3956c25b },
  { 0xf348b538, 0xf348b538, 0xf348b538, 0xf348b538 },
  { 0x59f111f1, 0x59f111f1, 0x59f111f1, 0x59f111f1 },
  { 0xb605d019, 0xb605d019, 0xb605d019, 0xb605d019 },
  { 0x923f82a4, 0x923f82a4, 0x923f82a4, 0x923f82a4 },
  { 0xaf194f9b, 0xaf194f9b, 0xaf194f9b, 0xaf194f9b },
  { 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5, 0xab1c5ed5 },
  { 0xda6d8118, 0xda6d8118, 0xda6d8118, 0xda6d8118 },
  { 0xd807aa98, 0xd807aa98, 0xd807aa98, 0xd807aa98 },
  { 0xa3030242, 0xa3030242, 0xa3030242, 0xa3030242 },
  { 0x12835b01, 0x12835b01, 0x12835b01, 0x12835b01 },
  { 0x45706fbe, 0x45706fbe, 0x45706fbe, 0x45706fbe },
  { 0x243185be, 0x243185be, 0x243185be, 0x243185be },
  { 0x4ee4b28c, 0x4ee4b28c, 0x4ee4b28c, 0x4ee4b28c },
  { 0x550c7dc3, 0x550c7dc3, 0x550c7dc3, 0x550c7dc3 },
  { 0xd5ffb4e2, 0xd5ffb4e2, 0xd5ffb4e2, 0xd5ffb4e2 },
  { 0x72be5d74, 0x72be5d74, 0x72be5d74, 0x72be5d74 },
  { 0xf27b896f, 0xf27b896f, 0xf27b896f, 0xf27b896f },
  { 0x80deb1fe, 0x80deb1fe, 0x80deb1fe, 0x80deb1fe },
  { 0x3b1696b1, 0x3b1696b1, 0x3b1696b1, 0x3b1696b1 },
  { 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7, 0x9bdc06a7 },
  { 0x25c71235, 0x25c71235, 0x25c71235, 0x25c71235 },
  { 0xc19bf174, 0xc19bf174, 0xc19bf174, 0xc19bf174 },
  { 0xcf692694, 0xcf692694, 0xcf692694, 0xcf692694 },
  { 0xe49b69c1, 0xe49b69c1, 0xe49b69c1, 0xe49b69c1 },
  { 0x9ef14ad2, 0x9ef14ad2, 0x9ef14ad2, 0x9ef14ad2 },
  { 0xefbe4786, 0xefbe4786, 0xefbe4786, 0xefbe4786 },
  { 0x384f25e3, 0x384f25e3, 0x384f25e3, 0x384f25e3 },
  { 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6, 0x0fc19dc6 },
  { 0x8b8cd5b5, 0x8b8cd5b5, 0x8b8cd5b5, 0x8b8cd5b5 },
  { 0x240ca1cc, 0x240ca1cc, 0x240ca1cc, 0x240ca1cc },
  { 0x77ac9c65, 0x77ac9c65, 0x77ac9c65, 0x77ac9c65 },
  { 0x2de92c6f, 0x2de92c6f, 0x2de92c6f, 0x2de92c6f },
  { 0x592b0275, 0x592b0275, 0x592b0275, 0x592b0275 },
  { 0x4a7484aa, 0x4a7484aa, 0x4a7484aa, 0x4a7484aa },
  { 0x6ea6e483, 0x6ea6e483, 0x6ea6e483, 0x6ea6e483 },
  { 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc, 0x5cb0a9dc },
  { 0xbd41fbd4, 0xbd41fbd4, 0xbd41fbd4, 0xbd41fbd4 },
  { 0x76f988da, 0x76f988da, 0x76f988da, 0x76f988da },
  { 0x831153b5, 0x831153b5, 0x831153b5, 0x831153b5 },
  { 0x983e5152, 0x983e5152, 0x983e5152, 0x983e5152 },
  { 0xee66dfab, 0xee66dfab, 0xee66dfab, 0xee66dfab },
  { 0xa831c66d, 0xa831c66d, 0xa831c66d, 0xa831c66d },
  { 0x2db43210, 0x2db43210, 0x2db43210, 0x2db43210 },
  { 0xb00327c8, 0xb00327c8, 0xb00327c8, 0xb00327c8 },
  { 0x98fb213f, 0x98fb213f, 0x98fb213f, 0x98fb213f },
  { 0xbf597fc7, 0xbf597fc7, 0xbf597fc7, 0xbf597fc7 },
  { 0xbeef0ee4, 0xbeef0ee4, 0xbeef0ee4, 0xbeef0ee4 },
  { 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3, 0xc6e00bf3 },
  { 0x3da88fc2, 0x3da88fc2, 0x3da88fc2, 0x3da88fc2 },
  { 0xd5a79147, 0xd5a79147, 0xd5a79147, 0xd5a79147 },
  { 0x930aa725, 0x930aa725, 0x930aa725, 0x930aa725 },
  { 0x06ca6351, 0x06ca6351, 0x06ca6351, 0x06ca6351 },
  { 0xe003826f, 0xe003826f, 0xe003826f, 0xe003826f },
  { 0x14292967, 0x14292967, 0x14292967, 0x14292967 },
  { 0x0a0e6e70, 0x0a0e6e70, 0x0a0e6e70, 0x0a0e6e70 },
  { 0x27b70a85, 0x27b70a85, 0x27b70a85, 0x27b70a85 },
  { 0x46d22ffc, 0x46d22ffc, 0x46d22ffc, 0x46d22ffc },
  { 0x2e1b2138, 0x2e1b2138, 0x2e1b2138, 0x2e1b2138 },
  { 0x5c26c926, 0x5c26c926, 0x5c26c926, 0x5c26c926 },
  { 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc, 0x4d2c6dfc },
  { 0x5ac42aed, 0x5ac42aed, 0x5ac42aed, 0x5ac42aed },
  { 0x53380d13, 0x53380d13, 0x53380d13, 0x53380d13 },
  { 0x9d95b3df, 0x9d95b3df, 0x9d95b3df, 0x9d95b3df },
  { 0x650a7354, 0x650a7354, 0x650a7354, 0x650a7354 },
  { 0x8baf63de, 0x8baf63de, 0x8baf63de, 0x8baf63de },
  { 0x766a0abb, 0x766a0abb, 0x766a0abb, 0x766a0abb },
  { 0x3c77b2a8, 0x3c77b2a8, 0x3c77b2a8, 0x3c77b2a8 },
  { 0x81c2c92e, 0x81c2c92e, 0x81c2c92e, 0x81c2c92e },
  { 0x47edaee6, 0x47edaee6, 0x47edaee6, 0x47edaee6 },
  { 0x92722c85, 0x92722c85, 0x92722c85, 0x92722c85 },
  { 0x1482353b, 0x1482353b, 0x1482353b, 0x1482353b },
  { 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1, 0xa2bfe8a1 },
  { 0x4cf10364, 0x4cf10364, 0x4cf10364, 0x4cf10364 },
  { 0xa81a664b, 0xa81a664b, 0xa81a664b, 0xa81a664b },
  { 0xbc423001, 0xbc423001, 0xbc423001, 0xbc423001 },
  { 0xc24b8b70, 0xc24b8b70, 0xc24b8b70, 0xc24b8b70 },
  { 0xd0f89791, 0xd0f89791, 0xd0f89791, 0xd0f89791 },
  { 0xc76c51a3, 0xc76c51a3, 0xc76c51a3, 0xc76c51a3 },
  { 0x0654be30, 0x0654be30, 0x0654be30, 0x0654be30 },
  { 0xd192e819, 0xd192e819, 0xd192e819, 0xd192e819 },
  { 0xd6ef5218, 0xd6ef5218, 0xd6ef5218, 0xd6ef5218 },
  { 0xd6990624, 0xd6990624, 0xd6990624, 0xd6990624 },
  { 0x5565a910, 0x5565a910, 0x5565a910, 0x5565a910 },
  { 0xf40e3585, 0xf40e3585, 0xf40e3585, 0xf40e3585 },
  { 0x5771202a, 0x5771202a, 0x5771202a, 0x5771202a },
  { 0x106aa070, 0x106aa070, 0x106aa070, 0x106aa070 },
  { 0x32bbd1b8, 0x32bbd1b8, 0x32bbd1b8, 0x32bbd1b8 },
  { 0x19a4c116, 0x19a4c116, 0x19a4c116, 0x19a4c116 },
  { 0xb8d2d0c8, 0xb8d2d0c8, 0xb8d2d0c8, 0xb8d2d0c8 },
  { 0x1e376c08, 0x1e376c08, 0x1e376c08, 0x1e376c08 },
  { 0x5141ab53, 0x5141ab53, 0x5141ab53, 0x5141ab53 },
  { 0x2748774c, 0x2748774c, 0x2748774c, 0x2748774c },
  { 0xdf8eeb99, 0xdf8eeb99, 0xdf8eeb99, 0xdf8eeb99 },
  { 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5, 0x34b0bcb5 },
  { 0xe19b48a8, 0xe19b48a8, 0xe19b48a8, 0xe19b48a8 },
  { 0x391c0cb3, 0x391c0cb3, 0x391c0cb3, 0x391c0cb3 },
  { 0xc5c95a63, 0xc5c95a63, 0xc5c95a63, 0xc5c95a63 },
  { 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a, 0x4ed8aa4a },
  { 0xe3418acb, 0xe3418acb, 0xe3418acb, 0xe3418acb },
  { 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f, 0x5b9cca4f },
  { 0x7763e373, 0x7763e373, 0x7763e373, 0x7763e373 },
  { 0x682e6ff3, 0x682e6ff3, 0x682e6ff3, 0x682e6ff3 },
  { 0xd6b2b8a3, 0xd6b2b8a3, 0xd6b2b8a3, 0xd6b2b8a3 },
  { 0x748f82ee, 0x748f82ee, 0x748f82ee, 0x748f82ee },
  { 0x5defb2fc, 0x5defb2fc, 0x5defb2fc, 0x5defb2fc },
  { 0x78a5636f, 0x78a5636f, 0x78a5636f, 0x78a5636f },
  { 0x43172f60, 0x43172f60, 0x43172f60, 0x43172f60 },
  { 0x84c87814, 0x84c87814, 0x84c87814, 0x84c87814 },
  { 0xa1f0ab72, 0xa1f0ab72, 0xa1f0ab72, 0xa1f0ab72 },
  { 0x8cc70208, 0x8cc70208, 0x8cc70208, 0x8cc70208 },
  { 0x1a6439ec, 0x1a6439ec, 0x1a6439ec, 0x1a6439ec },
  { 0x90befffa, 0x90befffa, 0x90befffa, 0x90befffa },
  { 0x23631e28, 0x23631e28, 0x23631e28, 0x23631e28 },
  { 0xa4506ceb, 0xa4506ceb, 0xa4506ceb, 0xa4506ceb },
  { 0xde82bde9, 0xde82bde9, 0xde82bde9, 0xde82bde9 },
  { 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7, 0xbef9a3f7 },
  { 0xb2c67915, 0xb2c67915, 0xb2c67915, 0xb2c67915 },
  { 0xc67178f2, 0xc67178f2, 0xc67178f2, 0xc67178f2 },
  { 0xe372532b, 0xe372532b, 0xe372532b, 0xe372532b },
  { 0xca273ece, 0xca273ece, 0xca273ece, 0xca273ece },
  { 0xea26619c, 0xea26619c, 0xea26619c, 0xea26619c },
  { 0xd186b8c7, 0xd186b8c7, 0xd186b8c7, 0xd186b8c7 },
  { 0x21c0c207, 0x21c0c207, 0x21c0c207, 0x21c0c207 },
  { 0xeada7dd6, 0xeada7dd6, 0xeada7dd6, 0xeada7dd6 },
  { 0xcde0eb1e, 0xcde0eb1e, 0xcde0eb1e, 0xcde0eb1e },
  { 0xf57d4f7f, 0xf57d4f7f, 0xf57d4f7f, 0xf57d4f7f },
  { 0xee6ed178, 0xee6ed178, 0xee6ed178, 0xee6ed178 },
  { 0x06f067aa, 0x06f067aa, 0x06f067aa, 0x06f067aa },
  { 0x72176fba, 0x72176fba, 0x72176fba, 0x72176fba },
  { 0x0a637dc5, 0x0a637dc5, 0x0a637dc5, 0x0a637dc5 },
  { 0xa2c898a6, 0xa2c898a6, 0xa2c898a6, 0xa2c898a6 },
  { 0x113f9804, 0x113f9804, 0x113f9804, 0x113f9804 },
  { 0xbef90dae, 0xbef90dae, 0xbef90dae, 0xbef90dae },
  { 0x1b710b35, 0x1b710b35, 0x1b710b35, 0x1b710b35 },
  { 0x131c471b, 0x131c471b, 0x131c471b, 0x131c471b },
  { 0x28db77f5, 0x28db77f5, 0x28db77f5, 0x28db77f5 },
  { 0x23047d84, 0x23047d84, 0x23047d84, 0x23047d84 },
  { 0x32caab7b, 0x32caab7b, 0x32caab7b, 0x32caab7b },
  { 0x40c72493, 0x40c72493, 0x40c72493, 0x40c72493 },
  { 0x3c9ebe0a, 0x3c9ebe0a, 0x3c9ebe0a, 0x3c9ebe0a },
  { 0x15c9bebc, 0x15c9bebc, 0x15c9bebc, 0x15c9bebc },
  { 0x431d67c4, 0x431d67c4, 0x431d67c4, 0x431d67c4 },
  { 0x9c100d4c, 0x9c100d4c, 0x9c100d4c, 0x9c100d4c },
  { 0x4cc5d4be, 0x4cc5d4be, 0x4cc5d4be, 0x4cc5d4be },
  { 0xcb3e42b6, 0xcb3e42b6, 0xcb3e42b6, 0xcb3e42b6 },
  { 0x597f299c, 0x597f299c, 0x597f299c, 0x597f299c },
  { 0xfc657e2a, 0xfc657e2a, 0xfc657e2a, 0xfc657e2a },
  { 0x5fcb6fab, 0x5fcb6fab, 0x5fcb6fab, 0x5fcb6fab },
  { 0x3ad6faec, 0x3ad6faec, 0x3ad6faec, 0x3ad6faec },
  { 0x6c44198c, 0x6c44198c, 0x6c44198c, 0x6c44198c },
  { 0x4a475817, 0x4a475817, 0x4a475817, 0x4a475817 }
};

__m128i sha512_const[160];

void hashcat_sha512_128 (uint32_t digests[16][4], uint32_t blocks[160][4])
{
  __m128i *sha512_digests = (__m128i *) digests;
  __m128i *sha512_blocks  = (__m128i *) blocks;

  #define W sha512_blocks

  __m128i Ah = sha512_digests[ 0];
  __m128i Al = sha512_digests[ 1];
  __m128i Bh = sha512_digests[ 2];
  __m128i Bl = sha512_digests[ 3];
  __m128i Ch = sha512_digests[ 4];
  __m128i Cl = sha512_digests[ 5];
  __m128i Dh = sha512_digests[ 6];
  __m128i Dl = sha512_digests[ 7];
  __m128i Eh = sha512_digests[ 8];
  __m128i El = sha512_digests[ 9];
  __m128i Fh = sha512_digests[10];
  __m128i Fl = sha512_digests[11];
  __m128i Gh = sha512_digests[12];
  __m128i Gl = sha512_digests[13];
  __m128i Hh = sha512_digests[14];
  __m128i Hl = sha512_digests[15];

  int t;
  int tN;

  for (t = 0; t < 16; t += 8)
  {
    tN = ((t + 0) * 2);                     SHA512_ROUND (tN, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
    tN = ((t + 1) * 2);                     SHA512_ROUND (tN, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl);
    tN = ((t + 2) * 2);                     SHA512_ROUND (tN, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl);
    tN = ((t + 3) * 2);                     SHA512_ROUND (tN, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El);
    tN = ((t + 4) * 2);                     SHA512_ROUND (tN, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl);
    tN = ((t + 5) * 2);                     SHA512_ROUND (tN, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl);
    tN = ((t + 6) * 2);                     SHA512_ROUND (tN, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl);
    tN = ((t + 7) * 2);                     SHA512_ROUND (tN, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al);
  }

  for (t = 16; t < 80; t += 8)
  {
    tN = ((t + 0) * 2); SHA512_EXPAND (tN); SHA512_ROUND (tN, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
    tN = ((t + 1) * 2); SHA512_EXPAND (tN); SHA512_ROUND (tN, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl);
    tN = ((t + 2) * 2); SHA512_EXPAND (tN); SHA512_ROUND (tN, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl);
    tN = ((t + 3) * 2); SHA512_EXPAND (tN); SHA512_ROUND (tN, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El);
    tN = ((t + 4) * 2); SHA512_EXPAND (tN); SHA512_ROUND (tN, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl);
    tN = ((t + 5) * 2); SHA512_EXPAND (tN); SHA512_ROUND (tN, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl, Ch, Cl);
    tN = ((t + 6) * 2); SHA512_EXPAND (tN); SHA512_ROUND (tN, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al, Bh, Bl);
    tN = ((t + 7) * 2); SHA512_EXPAND (tN); SHA512_ROUND (tN, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl, Ah, Al);
  }

  ADDC (sha512_digests[ 0], sha512_digests[ 1], Ah, Al);
  ADDC (sha512_digests[ 2], sha512_digests[ 3], Bh, Bl);
  ADDC (sha512_digests[ 4], sha512_digests[ 5], Ch, Cl);
  ADDC (sha512_digests[ 6], sha512_digests[ 7], Dh, Dl);
  ADDC (sha512_digests[ 8], sha512_digests[ 9], Eh, El);
  ADDC (sha512_digests[10], sha512_digests[11], Fh, Fl);
  ADDC (sha512_digests[12], sha512_digests[13], Gh, Gl);
  ADDC (sha512_digests[14], sha512_digests[15], Hh, Hl);
}
