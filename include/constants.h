/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifdef SHARED_H
#define _BCRYPT_
#define _SHA1_
#define _SHA256_
#define _SHA512_
#define _MD4_
#define _MD5_
#endif

#ifdef _BCRYPT_
/**
 * bcrypt Constants
 */

#define BCRYPTM_0 0x4F727068u
#define BCRYPTM_1 0x65616E42u
#define BCRYPTM_2 0x65686F6Cu
#define BCRYPTM_3 0x64657253u
#define BCRYPTM_4 0x63727944u
#define BCRYPTM_5 0x6F756274u
#endif

#ifdef _SHA1_
/**
 * SHA1 Constants
 */

#define SHA1M_A 0x67452301u
#define SHA1M_B 0xefcdab89u
#define SHA1M_C 0x98badcfeu
#define SHA1M_D 0x10325476u
#define SHA1M_E 0xc3d2e1f0u

#define SHA1C00 0x5a827999u
#define SHA1C01 0x6ed9eba1u
#define SHA1C02 0x8f1bbcdcu
#define SHA1C03 0xca62c1d6u
#endif

#ifdef _SHA256_
/**
 * SHA256 Constants
 */

#define SHA256M_A 0x6a09e667u
#define SHA256M_B 0xbb67ae85u
#define SHA256M_C 0x3c6ef372u
#define SHA256M_D 0xa54ff53au
#define SHA256M_E 0x510e527fu
#define SHA256M_F 0x9b05688cu
#define SHA256M_G 0x1f83d9abu
#define SHA256M_H 0x5be0cd19u

#define SHA256C00 0x428a2f98u
#define SHA256C01 0x71374491u
#define SHA256C02 0xb5c0fbcfu
#define SHA256C03 0xe9b5dba5u
#define SHA256C04 0x3956c25bu
#define SHA256C05 0x59f111f1u
#define SHA256C06 0x923f82a4u
#define SHA256C07 0xab1c5ed5u
#define SHA256C08 0xd807aa98u
#define SHA256C09 0x12835b01u
#define SHA256C0a 0x243185beu
#define SHA256C0b 0x550c7dc3u
#define SHA256C0c 0x72be5d74u
#define SHA256C0d 0x80deb1feu
#define SHA256C0e 0x9bdc06a7u
#define SHA256C0f 0xc19bf174u
#define SHA256C10 0xe49b69c1u
#define SHA256C11 0xefbe4786u
#define SHA256C12 0x0fc19dc6u
#define SHA256C13 0x240ca1ccu
#define SHA256C14 0x2de92c6fu
#define SHA256C15 0x4a7484aau
#define SHA256C16 0x5cb0a9dcu
#define SHA256C17 0x76f988dau
#define SHA256C18 0x983e5152u
#define SHA256C19 0xa831c66du
#define SHA256C1a 0xb00327c8u
#define SHA256C1b 0xbf597fc7u
#define SHA256C1c 0xc6e00bf3u
#define SHA256C1d 0xd5a79147u
#define SHA256C1e 0x06ca6351u
#define SHA256C1f 0x14292967u
#define SHA256C20 0x27b70a85u
#define SHA256C21 0x2e1b2138u
#define SHA256C22 0x4d2c6dfcu
#define SHA256C23 0x53380d13u
#define SHA256C24 0x650a7354u
#define SHA256C25 0x766a0abbu
#define SHA256C26 0x81c2c92eu
#define SHA256C27 0x92722c85u
#define SHA256C28 0xa2bfe8a1u
#define SHA256C29 0xa81a664bu
#define SHA256C2a 0xc24b8b70u
#define SHA256C2b 0xc76c51a3u
#define SHA256C2c 0xd192e819u
#define SHA256C2d 0xd6990624u
#define SHA256C2e 0xf40e3585u
#define SHA256C2f 0x106aa070u
#define SHA256C30 0x19a4c116u
#define SHA256C31 0x1e376c08u
#define SHA256C32 0x2748774cu
#define SHA256C33 0x34b0bcb5u
#define SHA256C34 0x391c0cb3u
#define SHA256C35 0x4ed8aa4au
#define SHA256C36 0x5b9cca4fu
#define SHA256C37 0x682e6ff3u
#define SHA256C38 0x748f82eeu
#define SHA256C39 0x78a5636fu
#define SHA256C3a 0x84c87814u
#define SHA256C3b 0x8cc70208u
#define SHA256C3c 0x90befffau
#define SHA256C3d 0xa4506cebu
#define SHA256C3e 0xbef9a3f7u
#define SHA256C3f 0xc67178f2u
#endif

#ifdef _MD4_
/**
 * MD4 Constants
 */

#define MD4M_A 0x67452301u
#define MD4M_B 0xefcdab89u
#define MD4M_C 0x98badcfeu
#define MD4M_D 0x10325476u

#define MD4S00  3u
#define MD4S01  7u
#define MD4S02 11u
#define MD4S03 19u
#define MD4S10  3u
#define MD4S11  5u
#define MD4S12  9u
#define MD4S13 13u
#define MD4S20  3u
#define MD4S21  9u
#define MD4S22 11u
#define MD4S23 15u

#define MD4C00 0x00000000u
#define MD4C01 0x5a827999u
#define MD4C02 0x6ed9eba1u
#endif

#ifdef _MD5_
/**
 * MD5 Constants
 */

#define MD5M_A 0x67452301u
#define MD5M_B 0xefcdab89u
#define MD5M_C 0x98badcfeu
#define MD5M_D 0x10325476u

#define MD5S00  7u
#define MD5S01 12u
#define MD5S02 17u
#define MD5S03 22u
#define MD5S10  5u
#define MD5S11  9u
#define MD5S12 14u
#define MD5S13 20u
#define MD5S20  4u
#define MD5S21 11u
#define MD5S22 16u
#define MD5S23 23u
#define MD5S30  6u
#define MD5S31 10u
#define MD5S32 15u
#define MD5S33 21u

#define MD5C00 0xd76aa478u
#define MD5C01 0xe8c7b756u
#define MD5C02 0x242070dbu
#define MD5C03 0xc1bdceeeu
#define MD5C04 0xf57c0fafu
#define MD5C05 0x4787c62au
#define MD5C06 0xa8304613u
#define MD5C07 0xfd469501u
#define MD5C08 0x698098d8u
#define MD5C09 0x8b44f7afu
#define MD5C0a 0xffff5bb1u
#define MD5C0b 0x895cd7beu
#define MD5C0c 0x6b901122u
#define MD5C0d 0xfd987193u
#define MD5C0e 0xa679438eu
#define MD5C0f 0x49b40821u
#define MD5C10 0xf61e2562u
#define MD5C11 0xc040b340u
#define MD5C12 0x265e5a51u
#define MD5C13 0xe9b6c7aau
#define MD5C14 0xd62f105du
#define MD5C15 0x02441453u
#define MD5C16 0xd8a1e681u
#define MD5C17 0xe7d3fbc8u
#define MD5C18 0x21e1cde6u
#define MD5C19 0xc33707d6u
#define MD5C1a 0xf4d50d87u
#define MD5C1b 0x455a14edu
#define MD5C1c 0xa9e3e905u
#define MD5C1d 0xfcefa3f8u
#define MD5C1e 0x676f02d9u
#define MD5C1f 0x8d2a4c8au
#define MD5C20 0xfffa3942u
#define MD5C21 0x8771f681u
#define MD5C22 0x6d9d6122u
#define MD5C23 0xfde5380cu
#define MD5C24 0xa4beea44u
#define MD5C25 0x4bdecfa9u
#define MD5C26 0xf6bb4b60u
#define MD5C27 0xbebfbc70u
#define MD5C28 0x289b7ec6u
#define MD5C29 0xeaa127fau
#define MD5C2a 0xd4ef3085u
#define MD5C2b 0x04881d05u
#define MD5C2c 0xd9d4d039u
#define MD5C2d 0xe6db99e5u
#define MD5C2e 0x1fa27cf8u
#define MD5C2f 0xc4ac5665u
#define MD5C30 0xf4292244u
#define MD5C31 0x432aff97u
#define MD5C32 0xab9423a7u
#define MD5C33 0xfc93a039u
#define MD5C34 0x655b59c3u
#define MD5C35 0x8f0ccc92u
#define MD5C36 0xffeff47du
#define MD5C37 0x85845dd1u
#define MD5C38 0x6fa87e4fu
#define MD5C39 0xfe2ce6e0u
#define MD5C3a 0xa3014314u
#define MD5C3b 0x4e0811a1u
#define MD5C3c 0xf7537e82u
#define MD5C3d 0xbd3af235u
#define MD5C3e 0x2ad7d2bbu
#define MD5C3f 0xeb86d391u
#endif

#ifdef _SHA512_
/**
 * SHA512 Constants (64 bits)
 */

#define SHA512M_A 0x6a09e667f3bcc908ull
#define SHA512M_B 0xbb67ae8584caa73bull
#define SHA512M_C 0x3c6ef372fe94f82bull
#define SHA512M_D 0xa54ff53a5f1d36f1ull
#define SHA512M_E 0x510e527fade682d1ull
#define SHA512M_F 0x9b05688c2b3e6c1full
#define SHA512M_G 0x1f83d9abfb41bd6bull
#define SHA512M_H 0x5be0cd19137e2179ull

#define SHA512C00 0x428a2f98d728ae22ull
#define SHA512C01 0x7137449123ef65cdull
#define SHA512C02 0xb5c0fbcfec4d3b2full
#define SHA512C03 0xe9b5dba58189dbbcull
#define SHA512C04 0x3956c25bf348b538ull
#define SHA512C05 0x59f111f1b605d019ull
#define SHA512C06 0x923f82a4af194f9bull
#define SHA512C07 0xab1c5ed5da6d8118ull
#define SHA512C08 0xd807aa98a3030242ull
#define SHA512C09 0x12835b0145706fbeull
#define SHA512C0a 0x243185be4ee4b28cull
#define SHA512C0b 0x550c7dc3d5ffb4e2ull
#define SHA512C0c 0x72be5d74f27b896full
#define SHA512C0d 0x80deb1fe3b1696b1ull
#define SHA512C0e 0x9bdc06a725c71235ull
#define SHA512C0f 0xc19bf174cf692694ull
#define SHA512C10 0xe49b69c19ef14ad2ull
#define SHA512C11 0xefbe4786384f25e3ull
#define SHA512C12 0x0fc19dc68b8cd5b5ull
#define SHA512C13 0x240ca1cc77ac9c65ull
#define SHA512C14 0x2de92c6f592b0275ull
#define SHA512C15 0x4a7484aa6ea6e483ull
#define SHA512C16 0x5cb0a9dcbd41fbd4ull
#define SHA512C17 0x76f988da831153b5ull
#define SHA512C18 0x983e5152ee66dfabull
#define SHA512C19 0xa831c66d2db43210ull
#define SHA512C1a 0xb00327c898fb213full
#define SHA512C1b 0xbf597fc7beef0ee4ull
#define SHA512C1c 0xc6e00bf33da88fc2ull
#define SHA512C1d 0xd5a79147930aa725ull
#define SHA512C1e 0x06ca6351e003826full
#define SHA512C1f 0x142929670a0e6e70ull
#define SHA512C20 0x27b70a8546d22ffcull
#define SHA512C21 0x2e1b21385c26c926ull
#define SHA512C22 0x4d2c6dfc5ac42aedull
#define SHA512C23 0x53380d139d95b3dfull
#define SHA512C24 0x650a73548baf63deull
#define SHA512C25 0x766a0abb3c77b2a8ull
#define SHA512C26 0x81c2c92e47edaee6ull
#define SHA512C27 0x92722c851482353bull
#define SHA512C28 0xa2bfe8a14cf10364ull
#define SHA512C29 0xa81a664bbc423001ull
#define SHA512C2a 0xc24b8b70d0f89791ull
#define SHA512C2b 0xc76c51a30654be30ull
#define SHA512C2c 0xd192e819d6ef5218ull
#define SHA512C2d 0xd69906245565a910ull
#define SHA512C2e 0xf40e35855771202aull
#define SHA512C2f 0x106aa07032bbd1b8ull
#define SHA512C30 0x19a4c116b8d2d0c8ull
#define SHA512C31 0x1e376c085141ab53ull
#define SHA512C32 0x2748774cdf8eeb99ull
#define SHA512C33 0x34b0bcb5e19b48a8ull
#define SHA512C34 0x391c0cb3c5c95a63ull
#define SHA512C35 0x4ed8aa4ae3418acbull
#define SHA512C36 0x5b9cca4f7763e373ull
#define SHA512C37 0x682e6ff3d6b2b8a3ull
#define SHA512C38 0x748f82ee5defb2fcull
#define SHA512C39 0x78a5636f43172f60ull
#define SHA512C3a 0x84c87814a1f0ab72ull
#define SHA512C3b 0x8cc702081a6439ecull
#define SHA512C3c 0x90befffa23631e28ull
#define SHA512C3d 0xa4506cebde82bde9ull
#define SHA512C3e 0xbef9a3f7b2c67915ull
#define SHA512C3f 0xc67178f2e372532bull
#define SHA512C40 0xca273eceea26619cull
#define SHA512C41 0xd186b8c721c0c207ull
#define SHA512C42 0xeada7dd6cde0eb1eull
#define SHA512C43 0xf57d4f7fee6ed178ull
#define SHA512C44 0x06f067aa72176fbaull
#define SHA512C45 0x0a637dc5a2c898a6ull
#define SHA512C46 0x113f9804bef90daeull
#define SHA512C47 0x1b710b35131c471bull
#define SHA512C48 0x28db77f523047d84ull
#define SHA512C49 0x32caab7b40c72493ull
#define SHA512C4a 0x3c9ebe0a15c9bebcull
#define SHA512C4b 0x431d67c49c100d4cull
#define SHA512C4c 0x4cc5d4becb3e42b6ull
#define SHA512C4d 0x597f299cfc657e2aull
#define SHA512C4e 0x5fcb6fab3ad6faecull
#define SHA512C4f 0x6c44198c4a475817ull

#define SHA512REV0 0x5218a97a1b97e8a0ull
#define SHA512REV1 0x4334c1bea164f555ull

#endif
