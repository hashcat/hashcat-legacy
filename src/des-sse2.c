/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#define PERM_OP(a,b,tt,n,m) \
{                           \
  tt = a >> n;              \
  tt = tt ^ b;              \
  tt = tt & m;              \
  b = b ^ tt;               \
  tt = tt << n;             \
  a = a ^ tt;               \
}

#define HPERM_OP(a,tt,n,m)  \
{                           \
  tt = a << (16 + n);       \
  tt = tt ^ a;              \
  tt = tt & m;              \
  a  = a ^ tt;              \
  tt = tt >> (16 + n);      \
  a  = a ^ tt;              \
}

#define IP(l,r,tt)                     \
{                                      \
  PERM_OP (r, l, tt,  4, 0x0f0f0f0f);  \
  PERM_OP (l, r, tt, 16, 0x0000ffff);  \
  PERM_OP (r, l, tt,  2, 0x33333333);  \
  PERM_OP (l, r, tt,  8, 0x00ff00ff);  \
  PERM_OP (r, l, tt,  1, 0x55555555);  \
}

#define FP(l,r,tt)                     \
{                                      \
  PERM_OP (l, r, tt,  1, 0x55555555);  \
  PERM_OP (r, l, tt,  8, 0x00ff00ff);  \
  PERM_OP (l, r, tt,  2, 0x33333333);  \
  PERM_OP (r, l, tt, 16, 0x0000ffff);  \
  PERM_OP (l, r, tt,  4, 0x0f0f0f0f);  \
}

#define BOX(v,i,S) (S)[(i)][(v)]

void _des_keysetup (uint32_t data[2], uint32_t Kc[16], uint32_t Kd[16], const uint s_skb[8][64])
{
  uint32_t c = data[0];
  uint32_t d = data[1];

  uint32_t tt;

  PERM_OP  (d, c, tt, 4, 0x0f0f0f0f);
  HPERM_OP (c,    tt, 2, 0xcccc0000);
  HPERM_OP (d,    tt, 2, 0xcccc0000);
  PERM_OP  (d, c, tt, 1, 0x55555555);
  PERM_OP  (c, d, tt, 8, 0x00ff00ff);
  PERM_OP  (d, c, tt, 1, 0x55555555);

  d = ((d & 0x000000ff) << 16)
    | ((d & 0x0000ff00) <<  0)
    | ((d & 0x00ff0000) >> 16)
    | ((c & 0xf0000000) >>  4);

  c = c & 0x0fffffff;

  int i;

  for (i = 0; i < 16; i++)
  {
    const uint shifts3s0[16] = {  1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1 };
    const uint shifts3s1[16] = { 27, 27, 26, 26, 26, 26, 26, 26, 27, 26, 26, 26, 26, 26, 26, 27 };

    c = c >> shifts3s0[i] | c << shifts3s1[i];
    d = d >> shifts3s0[i] | d << shifts3s1[i];

    c = c & 0x0fffffff;
    d = d & 0x0fffffff;

    uint32_t s = BOX ((( c >>  0) & 0x3f),  0, s_skb)
               | BOX ((((c >>  6) & 0x03)
                     | ((c >>  7) & 0x3c)), 1, s_skb)
               | BOX ((((c >> 13) & 0x0f)
                     | ((c >> 14) & 0x30)), 2, s_skb)
               | BOX ((((c >> 20) & 0x01)
                     | ((c >> 21) & 0x06)
                     | ((c >> 22) & 0x38)), 3, s_skb);

    uint32_t t = BOX ((( d >>  0) & 0x3f),  4, s_skb)
               | BOX ((((d >>  7) & 0x03)
                     | ((d >>  8) & 0x3c)), 5, s_skb)
               | BOX ((((d >> 15) & 0x3f)), 6, s_skb)
               | BOX ((((d >> 21) & 0x0f)
                     | ((d >> 22) & 0x30)), 7, s_skb);

    Kc[i] = ((t << 16) | (s & 0x0000ffff));
    Kd[i] = ((s >> 16) | (t & 0xffff0000));

    Kc[i] = ROTL32 (Kc[i], 2u);
    Kd[i] = ROTL32 (Kd[i], 2u);
  }
}

void _des_encrypt (uint32_t data[2], uint32_t Kc[16], uint32_t Kd[16], const uint s_SPtrans[8][64])
{
  uint32_t r = data[0];
  uint32_t l = data[1];

  uint32_t tt;

  IP (r, l, tt);

  r = ROTL32 (r, 3u);
  l = ROTL32 (l, 3u);

  int i;

  for (i = 0; i < 16; i++)
  {
    uint32_t u = Kc[i] ^ r;
    uint32_t t = Kd[i] ^ ROTL32 (r, 28u);

    l ^= BOX (((u >>  2) & 0x3f), 0, s_SPtrans)
       | BOX (((u >> 10) & 0x3f), 2, s_SPtrans)
       | BOX (((u >> 18) & 0x3f), 4, s_SPtrans)
       | BOX (((u >> 26) & 0x3f), 6, s_SPtrans)
       | BOX (((t >>  2) & 0x3f), 1, s_SPtrans)
       | BOX (((t >> 10) & 0x3f), 3, s_SPtrans)
       | BOX (((t >> 18) & 0x3f), 5, s_SPtrans)
       | BOX (((t >> 26) & 0x3f), 7, s_SPtrans);

    tt = l;
    l  = r;
    r  = tt;
  }

  l = ROTL32 (l, 29u);
  r = ROTL32 (r, 29u);

  FP (r, l, tt);

  data[0] = l;
  data[1] = r;
}
