/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

const uint64_t keccakf_rndc[24] =
{
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

const uint32_t keccakf_rotc[24] =
{
   1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
  27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

const uint32_t keccakf_piln[24] =
{
  10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
  15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

#define Theta1_sse(s) (digests[0 + s] ^ digests[5 + s] ^ digests[10 + s] ^ digests[15 + s] ^ digests[20 + s])

#define Theta2_sse(s)   \
{                       \
  digests[ 0 + s] ^= t; \
  digests[ 5 + s] ^= t; \
  digests[10 + s] ^= t; \
  digests[15 + s] ^= t; \
  digests[20 + s] ^= t; \
}

#define Chi_sse(s)                  \
{                                   \
  bc0 = digests[0 + s];             \
  bc1 = digests[1 + s];             \
  bc2 = digests[2 + s];             \
  bc3 = digests[3 + s];             \
  bc4 = digests[4 + s];             \
  digests[0 + s] ^= _mm_andnot_si128 (bc1, bc2);  \
  digests[1 + s] ^= _mm_andnot_si128 (bc2, bc3);  \
  digests[2 + s] ^= _mm_andnot_si128 (bc3, bc4);  \
  digests[3 + s] ^= _mm_andnot_si128 (bc4, bc0);  \
  digests[4 + s] ^= _mm_andnot_si128 (bc0, bc1);  \
}

#define Rho_Pi_sse(s)             \
{                                 \
  uint32_t j = keccakf_piln[s];   \
  uint32_t k = keccakf_rotc[s];   \
  bc0 = digests[j];               \
  digests[j] = ROTL64_SSE (t, k); \
  t = bc0;                        \
}

void hashcat_keccak_64 (__m128i digests[25])
{
  int round;

  for (round = 0; round < KECCAK_ROUNDS; round++)
  {
    // Theta

    __m128i bc0 = Theta1_sse (0);
    __m128i bc1 = Theta1_sse (1);
    __m128i bc2 = Theta1_sse (2);
    __m128i bc3 = Theta1_sse (3);
    __m128i bc4 = Theta1_sse (4);

    __m128i t;

    t = ROTL64_SSE (bc1, 1); t ^= bc4; Theta2_sse (0);
    t = ROTL64_SSE (bc2, 1); t ^= bc0; Theta2_sse (1);
    t = ROTL64_SSE (bc3, 1); t ^= bc1; Theta2_sse (2);
    t = ROTL64_SSE (bc4, 1); t ^= bc2; Theta2_sse (3);
    t = ROTL64_SSE (bc0, 1); t ^= bc3; Theta2_sse (4);

    // Rho Pi

    t = digests[1];

    Rho_Pi_sse (0);
    Rho_Pi_sse (1);
    Rho_Pi_sse (2);
    Rho_Pi_sse (3);
    Rho_Pi_sse (4);
    Rho_Pi_sse (5);
    Rho_Pi_sse (6);
    Rho_Pi_sse (7);
    Rho_Pi_sse (8);
    Rho_Pi_sse (9);
    Rho_Pi_sse (10);
    Rho_Pi_sse (11);
    Rho_Pi_sse (12);
    Rho_Pi_sse (13);
    Rho_Pi_sse (14);
    Rho_Pi_sse (15);
    Rho_Pi_sse (16);
    Rho_Pi_sse (17);
    Rho_Pi_sse (18);
    Rho_Pi_sse (19);
    Rho_Pi_sse (20);
    Rho_Pi_sse (21);
    Rho_Pi_sse (22);
    Rho_Pi_sse (23);

    //  Chi

    Chi_sse (0);
    Chi_sse (5);
    Chi_sse (10);
    Chi_sse (15);
    Chi_sse (20);

    //  Iota

    digests[0] ^= _mm_set1_epi64 ((__m64) keccakf_rndc[round]);
  }
}
