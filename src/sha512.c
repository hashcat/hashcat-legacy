/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define SHA512_S0(x) (ROTR64 ((x), 28) ^ ROTR64 ((x), 34) ^ ROTR64 ((x), 39))
#define SHA512_S1(x) (ROTR64 ((x), 14) ^ ROTR64 ((x), 18) ^ ROTR64 ((x), 41))
#define SHA512_S2(x) (ROTR64 ((x),  1) ^ ROTR64 ((x),  8) ^ SHR    ((x), 7))
#define SHA512_S3(x) (ROTR64 ((x), 19) ^ ROTR64 ((x), 61) ^ SHR    ((x), 6))

#define SHA512_F0o(x,y,z) ((z) ^ ((x) & ((y) ^ (z))))
#define SHA512_F1o(x,y,z) (((x) & (y)) | ((z) & ((x) ^ (y))))

#define SHA512_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)  \
{                                               \
  temp0  = K;                                   \
  temp0 += x;                                   \
  temp0 += h;                                   \
  temp0 += SHA512_S1 (e);                       \
  temp0 += F0 (e, f, g);                        \
  d     += temp0;                               \
  temp1  = SHA512_S0 (a);                       \
  temp1 += F1 (a, b, c);                        \
  h      = temp0 + temp1;                       \
}

void hashcat_sha512 (uint64_t digest[8], uint64_t W[16])
{
  uint64_t a = digest[0];
  uint64_t b = digest[1];
  uint64_t c = digest[2];
  uint64_t d = digest[3];
  uint64_t e = digest[4];
  uint64_t f = digest[5];
  uint64_t g = digest[6];
  uint64_t h = digest[7];

  uint64_t temp0;
  uint64_t temp1;

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

  SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, (uint64_t) (SHA512C00));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, (uint64_t) (SHA512C01));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, (uint64_t) (SHA512C02));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, (uint64_t) (SHA512C03));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, (uint64_t) (SHA512C04));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, (uint64_t) (SHA512C05));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, (uint64_t) (SHA512C06));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, (uint64_t) (SHA512C07));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, (uint64_t) (SHA512C08));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, (uint64_t) (SHA512C09));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, (uint64_t) (SHA512C0a));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, (uint64_t) (SHA512C0b));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, (uint64_t) (SHA512C0c));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, (uint64_t) (SHA512C0d));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, (uint64_t) (SHA512C0e));
  SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, (uint64_t) (SHA512C0f));
  w0_t = SHA512_S3(we_t) + w9_t + SHA512_S2(w1_t) + w0_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, (uint64_t) (SHA512C10));
  w1_t = SHA512_S3(wf_t) + wa_t + SHA512_S2(w2_t) + w1_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, (uint64_t) (SHA512C11));
  w2_t = SHA512_S3(w0_t) + wb_t + SHA512_S2(w3_t) + w2_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, (uint64_t) (SHA512C12));
  w3_t = SHA512_S3(w1_t) + wc_t + SHA512_S2(w4_t) + w3_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, (uint64_t) (SHA512C13));
  w4_t = SHA512_S3(w2_t) + wd_t + SHA512_S2(w5_t) + w4_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, (uint64_t) (SHA512C14));
  w5_t = SHA512_S3(w3_t) + we_t + SHA512_S2(w6_t) + w5_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, (uint64_t) (SHA512C15));
  w6_t = SHA512_S3(w4_t) + wf_t + SHA512_S2(w7_t) + w6_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, (uint64_t) (SHA512C16));
  w7_t = SHA512_S3(w5_t) + w0_t + SHA512_S2(w8_t) + w7_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, (uint64_t) (SHA512C17));
  w8_t = SHA512_S3(w6_t) + w1_t + SHA512_S2(w9_t) + w8_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, (uint64_t) (SHA512C18));
  w9_t = SHA512_S3(w7_t) + w2_t + SHA512_S2(wa_t) + w9_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, (uint64_t) (SHA512C19));
  wa_t = SHA512_S3(w8_t) + w3_t + SHA512_S2(wb_t) + wa_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, (uint64_t) (SHA512C1a));
  wb_t = SHA512_S3(w9_t) + w4_t + SHA512_S2(wc_t) + wb_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, (uint64_t) (SHA512C1b));
  wc_t = SHA512_S3(wa_t) + w5_t + SHA512_S2(wd_t) + wc_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, (uint64_t) (SHA512C1c));
  wd_t = SHA512_S3(wb_t) + w6_t + SHA512_S2(we_t) + wd_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, (uint64_t) (SHA512C1d));
  we_t = SHA512_S3(wc_t) + w7_t + SHA512_S2(wf_t) + we_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, (uint64_t) (SHA512C1e));
  wf_t = SHA512_S3(wd_t) + w8_t + SHA512_S2(w0_t) + wf_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, (uint64_t) (SHA512C1f));
  w0_t = SHA512_S3(we_t) + w9_t + SHA512_S2(w1_t) + w0_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, (uint64_t) (SHA512C20));
  w1_t = SHA512_S3(wf_t) + wa_t + SHA512_S2(w2_t) + w1_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, (uint64_t) (SHA512C21));
  w2_t = SHA512_S3(w0_t) + wb_t + SHA512_S2(w3_t) + w2_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, (uint64_t) (SHA512C22));
  w3_t = SHA512_S3(w1_t) + wc_t + SHA512_S2(w4_t) + w3_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, (uint64_t) (SHA512C23));
  w4_t = SHA512_S3(w2_t) + wd_t + SHA512_S2(w5_t) + w4_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, (uint64_t) (SHA512C24));
  w5_t = SHA512_S3(w3_t) + we_t + SHA512_S2(w6_t) + w5_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, (uint64_t) (SHA512C25));
  w6_t = SHA512_S3(w4_t) + wf_t + SHA512_S2(w7_t) + w6_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, (uint64_t) (SHA512C26));
  w7_t = SHA512_S3(w5_t) + w0_t + SHA512_S2(w8_t) + w7_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, (uint64_t) (SHA512C27));
  w8_t = SHA512_S3(w6_t) + w1_t + SHA512_S2(w9_t) + w8_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, (uint64_t) (SHA512C28));
  w9_t = SHA512_S3(w7_t) + w2_t + SHA512_S2(wa_t) + w9_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, (uint64_t) (SHA512C29));
  wa_t = SHA512_S3(w8_t) + w3_t + SHA512_S2(wb_t) + wa_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, (uint64_t) (SHA512C2a));
  wb_t = SHA512_S3(w9_t) + w4_t + SHA512_S2(wc_t) + wb_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, (uint64_t) (SHA512C2b));
  wc_t = SHA512_S3(wa_t) + w5_t + SHA512_S2(wd_t) + wc_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, (uint64_t) (SHA512C2c));
  wd_t = SHA512_S3(wb_t) + w6_t + SHA512_S2(we_t) + wd_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, (uint64_t) (SHA512C2d));
  we_t = SHA512_S3(wc_t) + w7_t + SHA512_S2(wf_t) + we_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, (uint64_t) (SHA512C2e));
  wf_t = SHA512_S3(wd_t) + w8_t + SHA512_S2(w0_t) + wf_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, (uint64_t) (SHA512C2f));
  w0_t = SHA512_S3(we_t) + w9_t + SHA512_S2(w1_t) + w0_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, (uint64_t) (SHA512C30));
  w1_t = SHA512_S3(wf_t) + wa_t + SHA512_S2(w2_t) + w1_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, (uint64_t) (SHA512C31));
  w2_t = SHA512_S3(w0_t) + wb_t + SHA512_S2(w3_t) + w2_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, (uint64_t) (SHA512C32));
  w3_t = SHA512_S3(w1_t) + wc_t + SHA512_S2(w4_t) + w3_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, (uint64_t) (SHA512C33));
  w4_t = SHA512_S3(w2_t) + wd_t + SHA512_S2(w5_t) + w4_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, (uint64_t) (SHA512C34));
  w5_t = SHA512_S3(w3_t) + we_t + SHA512_S2(w6_t) + w5_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, (uint64_t) (SHA512C35));
  w6_t = SHA512_S3(w4_t) + wf_t + SHA512_S2(w7_t) + w6_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, (uint64_t) (SHA512C36));
  w7_t = SHA512_S3(w5_t) + w0_t + SHA512_S2(w8_t) + w7_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, (uint64_t) (SHA512C37));
  w8_t = SHA512_S3(w6_t) + w1_t + SHA512_S2(w9_t) + w8_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, (uint64_t) (SHA512C38));
  w9_t = SHA512_S3(w7_t) + w2_t + SHA512_S2(wa_t) + w9_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, (uint64_t) (SHA512C39));
  wa_t = SHA512_S3(w8_t) + w3_t + SHA512_S2(wb_t) + wa_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, (uint64_t) (SHA512C3a));
  wb_t = SHA512_S3(w9_t) + w4_t + SHA512_S2(wc_t) + wb_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, (uint64_t) (SHA512C3b));
  wc_t = SHA512_S3(wa_t) + w5_t + SHA512_S2(wd_t) + wc_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, (uint64_t) (SHA512C3c));
  wd_t = SHA512_S3(wb_t) + w6_t + SHA512_S2(we_t) + wd_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, (uint64_t) (SHA512C3d));
  we_t = SHA512_S3(wc_t) + w7_t + SHA512_S2(wf_t) + we_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, (uint64_t) (SHA512C3e));
  wf_t = SHA512_S3(wd_t) + w8_t + SHA512_S2(w0_t) + wf_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, (uint64_t) (SHA512C3f));
  w0_t = SHA512_S3(we_t) + w9_t + SHA512_S2(w1_t) + w0_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w0_t, (uint64_t) (SHA512C40));
  w1_t = SHA512_S3(wf_t) + wa_t + SHA512_S2(w2_t) + w1_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w1_t, (uint64_t) (SHA512C41));
  w2_t = SHA512_S3(w0_t) + wb_t + SHA512_S2(w3_t) + w2_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, w2_t, (uint64_t) (SHA512C42));
  w3_t = SHA512_S3(w1_t) + wc_t + SHA512_S2(w4_t) + w3_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, w3_t, (uint64_t) (SHA512C43));
  w4_t = SHA512_S3(w2_t) + wd_t + SHA512_S2(w5_t) + w4_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, w4_t, (uint64_t) (SHA512C44));
  w5_t = SHA512_S3(w3_t) + we_t + SHA512_S2(w6_t) + w5_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, w5_t, (uint64_t) (SHA512C45));
  w6_t = SHA512_S3(w4_t) + wf_t + SHA512_S2(w7_t) + w6_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, w6_t, (uint64_t) (SHA512C46));
  w7_t = SHA512_S3(w5_t) + w0_t + SHA512_S2(w8_t) + w7_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, w7_t, (uint64_t) (SHA512C47));
  w8_t = SHA512_S3(w6_t) + w1_t + SHA512_S2(w9_t) + w8_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, a, b, c, d, e, f, g, h, w8_t, (uint64_t) (SHA512C48));
  w9_t = SHA512_S3(w7_t) + w2_t + SHA512_S2(wa_t) + w9_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, h, a, b, c, d, e, f, g, w9_t, (uint64_t) (SHA512C49));
  wa_t = SHA512_S3(w8_t) + w3_t + SHA512_S2(wb_t) + wa_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, g, h, a, b, c, d, e, f, wa_t, (uint64_t) (SHA512C4a));
  wb_t = SHA512_S3(w9_t) + w4_t + SHA512_S2(wc_t) + wb_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, f, g, h, a, b, c, d, e, wb_t, (uint64_t) (SHA512C4b));
  wc_t = SHA512_S3(wa_t) + w5_t + SHA512_S2(wd_t) + wc_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, e, f, g, h, a, b, c, d, wc_t, (uint64_t) (SHA512C4c));
  wd_t = SHA512_S3(wb_t) + w6_t + SHA512_S2(we_t) + wd_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, d, e, f, g, h, a, b, c, wd_t, (uint64_t) (SHA512C4d));
  we_t = SHA512_S3(wc_t) + w7_t + SHA512_S2(wf_t) + we_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, c, d, e, f, g, h, a, b, we_t, (uint64_t) (SHA512C4e));
  wf_t = SHA512_S3(wd_t) + w8_t + SHA512_S2(w0_t) + wf_t; SHA512_STEP (SHA512_F0o, SHA512_F1o, b, c, d, e, f, g, h, a, wf_t, (uint64_t) (SHA512C4f));

  digest[0] += a;
  digest[1] += b;
  digest[2] += c;
  digest[3] += d;
  digest[4] += e;
  digest[5] += f;
  digest[6] += g;
  digest[7] += h;
}
