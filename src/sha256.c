/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define SHR(x,n) ((x) >> (n))

#define SHA256_S0(x) (ROTR32 ((x),  7) ^ ROTR32 ((x), 18) ^ SHR    ((x),  3))
#define SHA256_S1(x) (ROTR32 ((x), 17) ^ ROTR32 ((x), 19) ^ SHR    ((x), 10))
#define SHA256_S2(x) (ROTR32 ((x),  2) ^ ROTR32 ((x), 13) ^ ROTR32 ((x), 22))
#define SHA256_S3(x) (ROTR32 ((x),  6) ^ ROTR32 ((x), 11) ^ ROTR32 ((x), 25))

#define SHA256_F0(x,y,z) ((x & y) | (z & (x | y)))
#define SHA256_F1(x,y,z) (z ^ (x & (y ^ z)))

#define SHA256_F0o(x,y,z) (SHA256_F0 ((x), (y), (z)))
#define SHA256_F1o(x,y,z) (SHA256_F1 ((x), (y), (z)))

#define SHA256_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                               \
  h += K;                                       \
  h += x;                                       \
  h += SHA256_S3 (e);                           \
  h += F1 (e,f,g);                              \
  d += h;                                       \
  h += SHA256_S2 (a);                           \
  h += F0 (a,b,c);                              \
}

void hashcat_sha256 (uint32_t digest[8], uint32_t W[16])
{
  uint32_t a = digest[0];
  uint32_t b = digest[1];
  uint32_t c = digest[2];
  uint32_t d = digest[3];
  uint32_t e = digest[4];
  uint32_t f = digest[5];
  uint32_t g = digest[6];
  uint32_t h = digest[7];

  #define w0_t W[ 0]
  #define w1_t W[ 1]
  #define w2_t W[ 2]
  #define w3_t W[ 3]
  #define w4_t W[ 4]
  #define w5_t W[ 5]
  #define w6_t W[ 6]
  #define w7_t W[ 7]
  #define w8_t W[ 8]
  #define w9_t W[ 9]
  #define wa_t W[10]
  #define wb_t W[11]
  #define wc_t W[12]
  #define wd_t W[13]
  #define we_t W[14]
  #define wf_t W[15]

  SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C00);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C01);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C02);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C03);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C04);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C05);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C06);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C07);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C08);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C09);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C0a);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C0b);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C0c);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C0d);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C0e);
  SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C0f);
  w0_t = SHA256_S1(we_t) + w9_t + SHA256_S0(w1_t) + w0_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C10);
  w1_t = SHA256_S1(wf_t) + wa_t + SHA256_S0(w2_t) + w1_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C11);
  w2_t = SHA256_S1(w0_t) + wb_t + SHA256_S0(w3_t) + w2_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C12);
  w3_t = SHA256_S1(w1_t) + wc_t + SHA256_S0(w4_t) + w3_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C13);
  w4_t = SHA256_S1(w2_t) + wd_t + SHA256_S0(w5_t) + w4_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C14);
  w5_t = SHA256_S1(w3_t) + we_t + SHA256_S0(w6_t) + w5_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C15);
  w6_t = SHA256_S1(w4_t) + wf_t + SHA256_S0(w7_t) + w6_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C16);
  w7_t = SHA256_S1(w5_t) + w0_t + SHA256_S0(w8_t) + w7_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C17);
  w8_t = SHA256_S1(w6_t) + w1_t + SHA256_S0(w9_t) + w8_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C18);
  w9_t = SHA256_S1(w7_t) + w2_t + SHA256_S0(wa_t) + w9_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C19);
  wa_t = SHA256_S1(w8_t) + w3_t + SHA256_S0(wb_t) + wa_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C1a);
  wb_t = SHA256_S1(w9_t) + w4_t + SHA256_S0(wc_t) + wb_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C1b);
  wc_t = SHA256_S1(wa_t) + w5_t + SHA256_S0(wd_t) + wc_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C1c);
  wd_t = SHA256_S1(wb_t) + w6_t + SHA256_S0(we_t) + wd_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C1d);
  we_t = SHA256_S1(wc_t) + w7_t + SHA256_S0(wf_t) + we_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C1e);
  wf_t = SHA256_S1(wd_t) + w8_t + SHA256_S0(w0_t) + wf_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C1f);
  w0_t = SHA256_S1(we_t) + w9_t + SHA256_S0(w1_t) + w0_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C20);
  w1_t = SHA256_S1(wf_t) + wa_t + SHA256_S0(w2_t) + w1_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C21);
  w2_t = SHA256_S1(w0_t) + wb_t + SHA256_S0(w3_t) + w2_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C22);
  w3_t = SHA256_S1(w1_t) + wc_t + SHA256_S0(w4_t) + w3_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C23);
  w4_t = SHA256_S1(w2_t) + wd_t + SHA256_S0(w5_t) + w4_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C24);
  w5_t = SHA256_S1(w3_t) + we_t + SHA256_S0(w6_t) + w5_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C25);
  w6_t = SHA256_S1(w4_t) + wf_t + SHA256_S0(w7_t) + w6_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C26);
  w7_t = SHA256_S1(w5_t) + w0_t + SHA256_S0(w8_t) + w7_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C27);
  w8_t = SHA256_S1(w6_t) + w1_t + SHA256_S0(w9_t) + w8_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C28);
  w9_t = SHA256_S1(w7_t) + w2_t + SHA256_S0(wa_t) + w9_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C29);
  wa_t = SHA256_S1(w8_t) + w3_t + SHA256_S0(wb_t) + wa_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C2a);
  wb_t = SHA256_S1(w9_t) + w4_t + SHA256_S0(wc_t) + wb_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C2b);
  wc_t = SHA256_S1(wa_t) + w5_t + SHA256_S0(wd_t) + wc_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C2c);
  wd_t = SHA256_S1(wb_t) + w6_t + SHA256_S0(we_t) + wd_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C2d);
  we_t = SHA256_S1(wc_t) + w7_t + SHA256_S0(wf_t) + we_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C2e);
  wf_t = SHA256_S1(wd_t) + w8_t + SHA256_S0(w0_t) + wf_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C2f);
  w0_t = SHA256_S1(we_t) + w9_t + SHA256_S0(w1_t) + w0_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, SHA256C30);
  w1_t = SHA256_S1(wf_t) + wa_t + SHA256_S0(w2_t) + w1_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, SHA256C31);
  w2_t = SHA256_S1(w0_t) + wb_t + SHA256_S0(w3_t) + w2_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, SHA256C32);
  w3_t = SHA256_S1(w1_t) + wc_t + SHA256_S0(w4_t) + w3_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, SHA256C33);
  w4_t = SHA256_S1(w2_t) + wd_t + SHA256_S0(w5_t) + w4_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, SHA256C34);
  w5_t = SHA256_S1(w3_t) + we_t + SHA256_S0(w6_t) + w5_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, SHA256C35);
  w6_t = SHA256_S1(w4_t) + wf_t + SHA256_S0(w7_t) + w6_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, SHA256C36);
  w7_t = SHA256_S1(w5_t) + w0_t + SHA256_S0(w8_t) + w7_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, SHA256C37);
  w8_t = SHA256_S1(w6_t) + w1_t + SHA256_S0(w9_t) + w8_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, SHA256C38);
  w9_t = SHA256_S1(w7_t) + w2_t + SHA256_S0(wa_t) + w9_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, SHA256C39);
  wa_t = SHA256_S1(w8_t) + w3_t + SHA256_S0(wb_t) + wa_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, SHA256C3a);
  wb_t = SHA256_S1(w9_t) + w4_t + SHA256_S0(wc_t) + wb_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, SHA256C3b);
  wc_t = SHA256_S1(wa_t) + w5_t + SHA256_S0(wd_t) + wc_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, SHA256C3c);
  wd_t = SHA256_S1(wb_t) + w6_t + SHA256_S0(we_t) + wd_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, SHA256C3d);
  we_t = SHA256_S1(wc_t) + w7_t + SHA256_S0(wf_t) + we_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, SHA256C3e);
  wf_t = SHA256_S1(wd_t) + w8_t + SHA256_S0(w0_t) + wf_t; SHA256_STEP (SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, SHA256C3f);

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}
