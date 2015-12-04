/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef ENGINE_H
#define ENGINE_H

#define INCR_RULES_PTR            100000
#define INCR_WORDS_PTR            1000000
#define INCR_SALT_PTR             10000
#define INCR_POT                  100000
#define INCR_INDEX_PTR            1
#define INCR_DIGEST_PTR           1
#define INCR_MASK_PTR             1000

#define INDEX_BITS                8

#define DIGEST_SIZE_MD5            4 * 4
#define DIGEST_SIZE_SHA1           5 * 4
#define DIGEST_SIZE_MYSQL          2 * 4
#define DIGEST_SIZE_MD4            4 * 4
#define DIGEST_SIZE_SHA256         8 * 4
#define DIGEST_SIZE_SHA512         8 * 8
#define DIGEST_SIZE_DESCRYPT       2 * 4
#define DIGEST_SIZE_KECCAK        25 * 8
#define DIGEST_SIZE_NETNTLMv1      6 * 4
#define DIGEST_SIZE_GOST           8 * 4
#define DIGEST_SIZE_BCRYPT         6 * 4
#define DIGEST_SIZE_PLAIN          55

#define HASH_SIZE_MD5             32
#define HASH_SIZE_SHA1            40
#define HASH_SIZE_MYSQL           16
#define HASH_SIZE_PHPASS          22
#define HASH_SIZE_MD5UNIX         22
#define HASH_SIZE_SHA1B64         28
#define HASH_SIZE_MD4             32
#define HASH_SIZE_MD5CHAP         32
#define HASH_SIZE_MSSQL2000       80
#define HASH_SIZE_MSSQL2005       40
#define HASH_SIZE_SHA256          64
#define HASH_SIZE_MD5APR          22
#define HASH_SIZE_SHA512          128
#define HASH_SIZE_SHA512UNIX      86
#define HASH_SIZE_MD5SUN          22
#define HASH_SIZE_OSX1            40
#define HASH_SIZE_OSX512          128
#define HASH_SIZE_MSSQL2012       128
#define HASH_SIZE_DESCRYPT        11
#define HASH_SIZE_KECCAK_MIN      1
#define HASH_SIZE_KECCAK_MAX      200
#define HASH_SIZE_EPIV6_MIN       27
#define HASH_SIZE_EPIV6_MAX       27
#define HASH_SIZE_VS2012_MIN      44
#define HASH_SIZE_VS2012_MAX      44
#define HASH_SIZE_IKEPSK_MD5_MIN  48
#define HASH_SIZE_IKEPSK_MD5_MAX  1024
#define HASH_SIZE_IKEPSK_SHA1_MIN 56
#define HASH_SIZE_IKEPSK_SHA1_MAX 1024
#define HASH_SIZE_NETNTLMv1       48
#define HASH_SIZE_NETNTLMv2       32
#define HASH_SIZE_CISCO_SECRET4   43
#define HASH_SIZE_MD5AIX          22
#define HASH_SIZE_SHA1AIX         27
#define HASH_SIZE_SHA256AIX       43
#define HASH_SIZE_SHA512AIX       86
#define HASH_SIZE_GOST            64
#define HASH_SIZE_SHA1FORTIGATE   40
#define HASH_SIZE_PBKDF2OSX       128
#define HASH_SIZE_PBKDF2GRUB      128
#define HASH_SIZE_MD5CISCO        16
#define HASH_SIZE_SHA1ORACLE      40
#define HASH_SIZE_BCRYPT          31
#define HASH_SIZE_HMACRAKP        40
#define HASH_SIZE_SHA256UNIX      43
#define HASH_SIZE_EPIV6_4_MIN     43
#define HASH_SIZE_EPIV6_4_MAX     43
#define HASH_SIZE_SHA512B64       86
#define HASH_SIZE_EPIV4_MIN       40
#define HASH_SIZE_EPIV4_MAX       40
#define HASH_SIZE_SCRYPT_MIN      44
#define HASH_SIZE_SCRYPT_MAX      44
#define HASH_SIZE_CISCO_SECRET9   43
#define HASH_SIZE_DJANGOSHA1_MIN  40
#define HASH_SIZE_DJANGOSHA1_MAX  40
#define HASH_SIZE_HMAIL           64
#define HASH_SIZE_MEDIAWIKI_B_MIN 32
#define HASH_SIZE_MEDIAWIKI_B_MAX 32
#define HASH_SIZE_CISCO_SECRET8   43
#define HASH_SIZE_DJANGO_SHA256   44
#define HASH_SIZE_PEOPLESOFT      28
#define HASH_SIZE_CRAM_MD5_MIN    44
#define HASH_SIZE_CRAM_MD5_MAX    132
#define HASH_SIZE_DRUPAL7         43
#define HASH_SIZE_SAP_H_MIN       33
#define HASH_SIZE_SAP_H_MAX       49
#define HASH_SIZE_SHA256B64       44
#define HASH_SIZE_PLAIN           55

#define HASH_TYPE_MD5             1
#define HASH_TYPE_SHA1            2
#define HASH_TYPE_MYSQL           3
#define HASH_TYPE_PHPASS          4
#define HASH_TYPE_MD5UNIX         5
#define HASH_TYPE_SHA1B64         6
#define HASH_TYPE_SHA1B64S        7
#define HASH_TYPE_MD4             9
#define HASH_TYPE_DCC             10
#define HASH_TYPE_MD5CHAP         11
#define HASH_TYPE_MSSQL2000       12
#define HASH_TYPE_SHA256          13
#define HASH_TYPE_MD5APR          14
#define HASH_TYPE_SHA512          15
#define HASH_TYPE_SHA512UNIX      16
#define HASH_TYPE_MD5SUN          17
#define HASH_TYPE_OSX1            18
#define HASH_TYPE_OSX512          19
#define HASH_TYPE_MSSQL2012       20
#define HASH_TYPE_DESCRYPT        21
#define HASH_TYPE_KECCAK          22
#define HASH_TYPE_EPIV6           23
#define HASH_TYPE_VS2012          24
#define HASH_TYPE_PSAFE3          25
#define HASH_TYPE_IKEPSK_MD5      26
#define HASH_TYPE_IKEPSK_SHA1     27
#define HASH_TYPE_NETNTLMv1       28
#define HASH_TYPE_NETNTLMv2       29
#define HASH_TYPE_WPA             30
#define HASH_TYPE_CISCO_SECRET4   31
#define HASH_TYPE_MD5AIX          32
#define HASH_TYPE_SHA1AIX         33
#define HASH_TYPE_SHA256AIX       34
#define HASH_TYPE_SHA512AIX       35
#define HASH_TYPE_GOST            36
#define HASH_TYPE_SHA1FORTIGATE   37
#define HASH_TYPE_PBKDF2OSX       38
#define HASH_TYPE_PBKDF2GRUB      39
#define HASH_TYPE_MSSQL2005       40
#define HASH_TYPE_MD5CISCO_PIX    41
#define HASH_TYPE_SHA1ORACLE      42
#define HASH_TYPE_HMACRAKP        43
#define HASH_TYPE_BCRYPT          44
#define HASH_TYPE_SHA256UNIX      45
#define HASH_TYPE_EPIV6_4         46
#define HASH_TYPE_SHA512B64S      47
#define HASH_TYPE_EPIV4           48
#define HASH_TYPE_SCRYPT          49
#define HASH_TYPE_CISCO_SECRET9   50
#define HASH_TYPE_PHPS            51
#define HASH_TYPE_DJANGOSHA1      52
#define HASH_TYPE_HMAIL           53
#define HASH_TYPE_MEDIAWIKI_B     54
#define HASH_TYPE_CISCO_SECRET8   55
#define HASH_TYPE_DJANGO_SHA256   56
#define HASH_TYPE_PEOPLESOFT      57
#define HASH_TYPE_CRAM_MD5        58
#define HASH_TYPE_DRUPAL7         59
#define HASH_TYPE_MD5CISCO_ASA    60
#define HASH_TYPE_SAP_H_SHA1      61
#define HASH_TYPE_PRESTASHOP      62
#define HASH_TYPE_POSTGRESQL_AUTH 63
#define HASH_TYPE_MYSQL_AUTH      64
#define HASH_TYPE_SIP_AUTH        65
#define HASH_TYPE_SHA256B64       66
#define HASH_TYPE_PLAIN           99

#define PLAIN_SIZE_MD5            55
#define PLAIN_SIZE_SHA1           55
#define PLAIN_SIZE_MYSQL          55
#define PLAIN_SIZE_PHPASS         55
#define PLAIN_SIZE_MD5UNIX        16
#define PLAIN_SIZE_SHA1B64        55
#define PLAIN_SIZE_SHA1B64S       55
#define PLAIN_SIZE_MD4            55
#define PLAIN_SIZE_NTLM           27
#define PLAIN_SIZE_DCC            27
#define PLAIN_SIZE_MD5CHAP        55
#define PLAIN_SIZE_MSSQL2000      27
#define PLAIN_SIZE_MSSQL2005      27
#define PLAIN_SIZE_SHA256         55
#define PLAIN_SIZE_MD5APR         16
#define PLAIN_SIZE_SHA512         55
#define PLAIN_SIZE_SHA512UNIX     64
#define PLAIN_SIZE_MD5SUN         55
#define PLAIN_SIZE_OSX1           55
#define PLAIN_SIZE_OSX512         55
#define PLAIN_SIZE_MSSQL2012      27
#define PLAIN_SIZE_DESCRYPT       8
#define PLAIN_SIZE_KECCAK         55
#define PLAIN_SIZE_EPIV6          27
#define PLAIN_SIZE_VS2012         55
#define PLAIN_SIZE_WPA            64
#define PLAIN_SIZE_MD5AIX         16
#define PLAIN_SIZE_SHA1AIX        55
#define PLAIN_SIZE_SHA256AIX      55
#define PLAIN_SIZE_SHA512AIX      55
#define PLAIN_SIZE_GOST           55
#define PLAIN_SIZE_FORTIGATE      47
#define PLAIN_SIZE_PBKDF2OSX      55
#define PLAIN_SIZE_PBKDF2GRUB     55
#define PLAIN_SIZE_NETNTLMv1      27
#define PLAIN_SIZE_NETNTLMv2      27
#define PLAIN_SIZE_MD5CISCO       16
#define PLAIN_SIZE_SHA1ORACLE     55
#define PLAIN_SIZE_HMACRAKP       55
#define PLAIN_SIZE_BCRYPT         55
#define PLAIN_SIZE_SHA256UNIX     16
#define PLAIN_SIZE_EPIV6_4        55
#define PLAIN_SIZE_SHA512B64S     55
#define PLAIN_SIZE_EPIV4          55
#define PLAIN_SIZE_SCRYPT         55
#define PLAIN_SIZE_CISCO_SECRET8  55
#define PLAIN_SIZE_DJANGO_SHA256  55
#define PLAIN_SIZE_PLAIN          55

#define SALT_TYPE_NONE            1 << 1
#define SALT_TYPE_INCLUDED        1 << 2
#define SALT_TYPE_EXTERNAL        1 << 3
#define SALT_TYPE_EMBEDDED        1 << 4

#define SALT_SIZE_MIN_MD5           0
#define SALT_SIZE_MAX_MD5           54
#define SALT_SIZE_MIN_SHA1          0
#define SALT_SIZE_MAX_SHA1          54
#define SALT_SIZE_MIN_PHPASS        8
#define SALT_SIZE_MAX_PHPASS        8
#define SALT_SIZE_MIN_MD5UNIX       0
#define SALT_SIZE_MAX_MD5UNIX       8
#define SALT_SIZE_MIN_SHA1B64S      0
#define SALT_SIZE_MAX_SHA1B64S      32
#define SALT_SIZE_MIN_DCC           1
#define SALT_SIZE_MAX_DCC           54
#define SALT_SIZE_MIN_MD5CHAP       32
#define SALT_SIZE_MAX_MD5CHAP       32
#define SALT_SIZE_MIN_MSSQL2000     8
#define SALT_SIZE_MIN_MSSQL2005     8
#define SALT_SIZE_MAX_MSSQL2000     8
#define SALT_SIZE_MAX_MSSQL2005     8
#define SALT_SIZE_MIN_SHA256        0
#define SALT_SIZE_MAX_SHA256        54
#define SALT_SIZE_MIN_MD5APR        0
#define SALT_SIZE_MAX_MD5APR        8
#define SALT_SIZE_MIN_SHA512        0
#define SALT_SIZE_MAX_SHA512        54
#define SALT_SIZE_MIN_SHA512UNIX    0
#define SALT_SIZE_MAX_SHA512UNIX    54
#define SALT_SIZE_MIN_MD5SUN        1
#define SALT_SIZE_MAX_MD5SUN        17
#define SALT_SIZE_MIN_OSX1          8
#define SALT_SIZE_MAX_OSX1          8
#define SALT_SIZE_MIN_OSX512        8
#define SALT_SIZE_MAX_OSX512        8
#define SALT_SIZE_MIN_MSSQL2012     8
#define SALT_SIZE_MAX_MSSQL2012     8
#define SALT_SIZE_MIN_DESCRYPT      2
#define SALT_SIZE_MAX_DESCRYPT      2
#define SALT_SIZE_MIN_KECCAK        1
#define SALT_SIZE_MAX_KECCAK        54
#define SALT_SIZE_MIN_EPIV6         1
#define SALT_SIZE_MAX_EPIV6         44
#define SALT_SIZE_MIN_VS2012        1
#define SALT_SIZE_MAX_VS2012        44
#define SALT_SIZE_MIN_NETNTLMv1     16
#define SALT_SIZE_MAX_NETNTLMv1     16
#define SALT_SIZE_MIN_NETNTLMv2     ( 1 +  1 + 1 + 16 + 1 +    1)
#define SALT_SIZE_MAX_NETNTLMv2     (60 + 45 + 1 + 16 + 1 + 1024)
#define SALT_SIZE_MIN_MD5AIX        8
#define SALT_SIZE_MAX_MD5AIX        8
#define SALT_SIZE_MIN_SHA1AIX       16
#define SALT_SIZE_MAX_SHA1AIX       128
#define SALT_SIZE_MIN_SHA256AIX     16
#define SALT_SIZE_MAX_SHA256AIX     128
#define SALT_SIZE_MIN_SHA512AIX     16
#define SALT_SIZE_MAX_SHA512AIX     128
#define SALT_SIZE_SHA1FORTIGATE     12
#define SALT_SIZE_MIN_PBKDF2OSX     64
#define SALT_SIZE_MAX_PBKDF2OSX     64
#define SALT_SIZE_MIN_PBKDF2GRUB    1
#define SALT_SIZE_MAX_PBKDF2GRUB    1024
#define SALT_SIZE_MIN_SHA1ORACLE    20
#define SALT_SIZE_MAX_SHA1ORACLE    20
#define SALT_SIZE_MIN_HMACRAKP      64
#define SALT_SIZE_MAX_HMACRAKP      512
#define SALT_SIZE_MIN_BCRYPT        22
#define SALT_SIZE_MAX_BCRYPT        22
#define SALT_SIZE_MIN_SHA256UNIX    0
#define SALT_SIZE_MAX_SHA256UNIX    16
#define SALT_SIZE_MIN_EPIV6_4       24
#define SALT_SIZE_MAX_EPIV6_4       24
#define SALT_SIZE_MIN_SHA512B64S    0
#define SALT_SIZE_MAX_SHA512B64S    68
#define SALT_SIZE_MIN_EPIV4         60
#define SALT_SIZE_MAX_EPIV4         60
#define SALT_SIZE_MIN_SCRYPT        1
#define SALT_SIZE_MAX_SCRYPT        44
#define SALT_SIZE_CISCO_SECRET9     14
#define SALT_SIZE_MIN_DJANGOSHA1    0
#define SALT_SIZE_MAX_DJANGOSHA1    54
#define SALT_SIZE_HMAIL             6
#define SALT_SIZE_MIN_MEDIAWIKI_B   0
#define SALT_SIZE_MAX_MEDIAWIKI_B   54
#define SALT_SIZE_MIN_CISCO_SECRET8 14
#define SALT_SIZE_MAX_CISCO_SECRET8 14
#define SALT_SIZE_MIN_DJANGO_SHA256 0
#define SALT_SIZE_MAX_DJANGO_SHA256 128
#define SALT_SIZE_MIN_CRAM_MD5      12
#define SALT_SIZE_MAX_CRAM_MD5      76
#define SALT_SIZE_DRUPAL7           8
#define SALT_SIZE_MIN_MD5CISCO_ASA  0
#define SALT_SIZE_MAX_MD5CISCO_ASA  16
#define SALT_SIZE_MIN_SAP_H_SHA1    4
#define SALT_SIZE_MAX_SAP_H_SHA1    16
#define SALT_SIZE_MIN_PRESTASHOP    56
#define SALT_SIZE_MAX_PRESTASHOP    56
#define SALT_SIZE_POSTGRESQL_AUTH   8
#define SALT_SIZE_MYSQL_AUTH        40

#define PSAFE3_SIGN               4
#define PSAFE3_MAGIC              "PWS3"
#define PSAFE3_ROUNDS             2048

#define PHPASS_SIGN               3
#define PHPASS_ITER               1
#define PHPASS_MAGIC_P            "$P$"
#define PHPASS_MAGIC_H            "$H$"
#define PHPASS_ROUNDS             (1 << 11)

#define MD5UNIX_SIGN              3
#define MD5UNIX_MAGIC             "$1$"
#define MD5UNIX_ROUNDS            1000

#define MD5SUN_SIGN               4
#define MD5SUN_MAGIC              "$md5"
#define MD5SUN_ROUNDS_MIN         4096

#define MD5APR_SIGN               6
#define MD5APR_MAGIC              "$apr1$"
#define MD5APR_ROUNDS             1000

#define SHA512UNIX_SIGN           3
#define SHA512UNIX_MAGIC          "$6$"
#define SHA512UNIX_ROUNDS         5000

#define SHA1B64_SIGN              5
#define SHA1B64_MAGIC             "{SHA}"

#define SHA1B64S_SIGN             6
#define SHA1B64S_MAGIC            "{SSHA}"

#define MD5CHAP_IDBYTE            2

#define MSSQL_SIGN                6
#define MSSQL_MAGIC               "0x0100"

#define MSSQL2012_SIGN            6
#define MSSQL2012_MAGIC           "0x0200"

#define EPISERVERV6_SIGN          14
#define EPISERVERV6_MAGIC         "$episerver$*0*"

#define NETNTLMv1_SIGN            9
#define NETNTLMv1_MAGIC           "$NETNTLM$"

#define NETNTLMv2_SIGN            11
#define NETNTLMv2_MAGIC           "$NETNTLMv2$"

#define MD5AIX_SIGN               6
#define MD5AIX_MAGIC              "{smd5}"
#define MD5AIX_ROUNDS             1000

#define SHA1AIX_SIGN              7
#define SHA1AIX_MAGIC             "{ssha1}"
#define SHA1AIX_ROUNDS            (1 << 6)

#define SHA256AIX_SIGN            9
#define SHA256AIX_MAGIC           "{ssha256}"
#define SHA256AIX_ROUNDS          (1 << 6)

#define SHA512AIX_SIGN            9
#define SHA512AIX_MAGIC           "{ssha512}"
#define SHA512AIX_ROUNDS          (1 << 6)

#define FORTIGATE_SIGN            3
#define FORTIGATE_MAGIC           "AK1"
#define FORTIGATE_MAGIC_A         "\xa3\x88\xba\x2e\x42\x4c\xb0\x4a\x53\x79\x30\xc1\x31\x07\xcc\x3f\xa1\x32\x90\x29\xa9\x81\x5b\x70"

#define PBKDF2OSX_SIGN            4
#define PBKDF2OSX_MAGIC           "$ml$"
#define PBKDF2OSX_ROUNDS          35000

#define PBKDF2GRUB_SIGN           19
#define PBKDF2GRUB_MAGIC          "grub.pbkdf2.sha512."
#define PBKDF2GRUB_ROUNDS         10000

#define BCRYPT_SIGN               4
#define BCRYPT_MAGIC              "$2a$"
#define BCRYPT_ROUNDS             (1 << 5)

#define SHA256UNIX_SIGN           3
#define SHA256UNIX_MAGIC          "$5$"
#define SHA256UNIX_ROUNDS         5000

#define EPISERVERV6_4_SIGN        14
#define EPISERVERV6_4_MAGIC       "$episerver$*1*"

#define SHA512B64S_SIGN           9
#define SHA512B64S_MAGIC          "{SSHA512}"

#define EPISERVERV4_SIGN          2
#define EPISERVERV4_MAGIC         "0x"

#define SCRYPT_SIGN               6
#define SCRYPT_MAGIC              "SCRYPT"

#define CISCO_SECRET9_SIGN        3
#define CISCO_SECRET9_MAGIC       "$9$"

#define WPA2_ROUNDS               4096

#define ANDROID_PIN_ROUNDS        1024

#define PHPS_SIGN                 6
#define PHPS_MAGIC                "$PHPS$"

#define DJANGOSHA1_SIGN           5
#define DJANGOSHA1_MAGIC          "sha1$"

#define MEDIAWIKI_B_SIGN          3
#define MEDIAWIKI_B_MAGIC         "$B$"

#define CISCO_SECRET8_SIGN        3
#define CISCO_SECRET8_MAGIC       "$8$"
#define CISCO_SECRET8_ROUNDS      20000

#define DJANGO_SHA256_SIGN        14
#define DJANGO_SHA256_MAGIC       "pbkdf2_sha256$"
#define DJANGO_SHA256_ROUNDS      20000

#define CRAM_MD5_SIGN             10
#define CRAM_MD5_MAGIC            "$cram_md5$"

#define DRUPAL7_SIGN              3
#define DRUPAL7_MAGIC             "$S$"
#define DRUPAL7_ROUNDS            16384

#define SAP_H_SHA1_SIGN           10
#define SAP_H_SHA1_MAGIC          "{x-issha, "
#define SAP_H_SHA1_ROUNDS         1024

#define POSTGRESQL_AUTH_SIGN      10
#define POSTGRESQL_AUTH_MAGIC     "$postgres$"

#define MYSQL_AUTH_SIGN           9
#define MYSQL_AUTH_MAGIC          "$mysqlna$"

#define SIP_AUTH_SIGN             6
#define SIP_AUTH_MAGIC            "$sip$*"

/**
 * Strings
 */

#define HT_00000  "MD5"
#define HT_00010  "md5($pass.$salt)"
#define HT_00020  "md5($salt.$pass)"
#define HT_00030  "md5(unicode($pass).$salt)"
#define HT_00040  "md5($salt.unicode($pass))"
#define HT_00050  "HMAC-MD5 (key = $pass)"
#define HT_00060  "HMAC-MD5 (key = $salt)"
#define HT_00100  "SHA1"
#define HT_00110  "sha1($pass.$salt)"
#define HT_00120  "sha1($salt.$pass)"
#define HT_00130  "sha1(unicode($pass).$salt)"
#define HT_00140  "sha1($salt.unicode($pass))"
#define HT_00150  "HMAC-SHA1 (key = $pass)"
#define HT_00160  "HMAC-SHA1 (key = $salt)"
#define HT_00190  "sha1(LinkedIn)"
#define HT_00200  "MySQL323"
#define HT_00300  "MySQL4.1/MySQL5"
#define HT_00400  "phpass, MD5(Wordpress), MD5(phpBB3), MD5(Joomla)"
#define HT_00500  "md5crypt, MD5(Unix), FreeBSD MD5, Cisco-IOS MD5"
#define HT_00501  "Juniper IVE"
#define HT_00666  "Plaintext"
#define HT_00900  "MD4"
#define HT_01000  "NTLM"
#define HT_01100  "Domain Cached Credentials (DCC), MS Cache"
#define HT_01400  "SHA256"
#define HT_01410  "sha256($pass.$salt)"
#define HT_01420  "sha256($salt.$pass)"
#define HT_01430  "sha256(unicode($pass).$salt)"
#define HT_01431  "base64(sha256(unicode($pass)))"
#define HT_01440  "sha256($salt.$pass)"
#define HT_01450  "HMAC-SHA256 (key = $pass)"
#define HT_01460  "HMAC-SHA256 (key = $salt)"
#define HT_01500  "descrypt, DES(Unix), Traditional DES"
#define HT_01600  "md5apr1, MD5(APR), Apache MD5"
#define HT_01700  "SHA512"
#define HT_01710  "sha512($pass.$salt)"
#define HT_01720  "sha512($salt.$pass)"
#define HT_01730  "sha512(unicode($pass).$salt)"
#define HT_01740  "sha512($salt.unicode($pass))"
#define HT_01750  "HMAC-SHA512 (key = $pass)"
#define HT_01760  "HMAC-SHA512 (key = $salt)"
#define HT_01800  "sha512crypt, SHA512(Unix)"
#define HT_02400  "Cisco-PIX MD5"
#define HT_02410  "Cisco-ASA MD5"
#define HT_02500  "WPA/WPA2"
#define HT_02600  "Double MD5"
#define HT_03200  "bcrypt, Blowfish(OpenBSD)"
#define HT_03300  "MD5(Sun)"
#define HT_03500  "md5(md5(md5($pass)))"
#define HT_03610  "md5(md5($salt).$pass)"
#define HT_03710  "md5($salt.md5($pass))"
#define HT_03720  "md5($pass.md5($salt))"
#define HT_03800  "md5($salt.$pass.$salt)"
#define HT_03910  "md5(md5($pass).md5($salt))"
#define HT_04010  "md5($salt.md5($salt.$pass))"
#define HT_04110  "md5($salt.md5($pass.$salt))"
#define HT_04210  "md5($username.0.$pass)"
#define HT_04300  "md5(strtoupper(md5($pass)))"
#define HT_04400  "md5(sha1($pass))"
#define HT_04500  "Double SHA1"
#define HT_04600  "sha1(sha1(sha1($pass)))"
#define HT_04700  "sha1(md5($pass))"
#define HT_04800  "MD5(Chap), iSCSI CHAP authentication"
#define HT_04900  "sha1($salt.$pass.$salt)"
#define HT_05000  "SHA-3(Keccak)"
#define HT_05100  "Half MD5"
#define HT_05200  "Password Safe v3"
#define HT_05300  "IKE-PSK MD5"
#define HT_05400  "IKE-PSK SHA1"
#define HT_05500  "NetNTLMv1-VANILLA / NetNTLMv1+ESS"
#define HT_05600  "NetNTLMv2"
#define HT_05700  "Cisco-IOS SHA256"
#define HT_05800  "Android PIN"
#define HT_06300  "AIX {smd5}"
#define HT_06400  "AIX {ssha256}"
#define HT_06500  "AIX {ssha512}"
#define HT_06700  "AIX {ssha1}"
#define HT_06900  "GOST R 34.11-94"
#define HT_07000  "Fortigate (FortiOS)"
#define HT_07100  "OSX v10.8+"
#define HT_07200  "GRUB 2"
#define HT_07300  "IPMI2 RAKP HMAC-SHA1"
#define HT_07400  "sha256crypt, SHA256(Unix)"
#define HT_07900  "Drupal7"
#define HT_08400  "WBB3, Woltlab Burning Board 3"
#define HT_08900  "scrypt"
#define HT_09200  "Cisco $8$"
#define HT_09300  "Cisco $9$"
#define HT_09900  "Radmin2"
#define HT_10000  "Django (PBKDF2-SHA256)"
#define HT_10200  "Cram MD5"
#define HT_10300  "SAP CODVN H (PWDSALTEDHASH) iSSHA-1"
#define HT_11000  "PrestaShop"
#define HT_11100  "PostgreSQL Challenge-Response Authentication (MD5)"
#define HT_11200  "MySQL Challenge-Response Authentication (SHA1)"
#define HT_11400  "SIP digest authentication (MD5)"
#define HT_99999  "Plaintext"

#define HT_00011  "Joomla < 2.5.18"
#define HT_00012  "PostgreSQL"
#define HT_00021  "osCommerce, xt:Commerce"
#define HT_00023  "Skype"
#define HT_00101  "SHA-1(Base64), nsldap, Netscape LDAP SHA"
#define HT_00111  "SSHA-1(Base64), nsldaps, Netscape LDAP SSHA"
#define HT_00112  "Oracle S: Type (Oracle 11+)"
#define HT_00121  "SMF > v1.1"
#define HT_00122  "OSX v10.4, v10.5, v10.6"
#define HT_00123  "EPi"
#define HT_00124  "Django (SHA-1)"
#define HT_00131  "MSSQL(2000)"
#define HT_00132  "MSSQL(2005)"
#define HT_00133  "PeopleSoft"
#define HT_00141  "EPiServer 6.x < v4"
#define HT_01421  "hMailServer"
#define HT_01441  "EPiServer 6.x > v4"
#define HT_01711  "SSHA-512(Base64), LDAP {SSHA512}"
#define HT_01722  "OSX v10.7"
#define HT_01731  "MSSQL(2012)"
#define HT_02611  "vBulletin < v3.8.5"
#define HT_02612  "PHPS"
#define HT_02711  "vBulletin > v3.8.5"
#define HT_02811  "IPB2+, MyBB1.2+"
#define HT_03711  "Mediawiki B type"
#define HT_03721  "WebEdition CMS"
#define HT_07600  "Redmine Project Management Web App"

static const char constant_phrase[] =
  "To be, or not to be,--that is the question:--\n"
  "Whether 'tis nobler in the mind to suffer\n"
  "The slings and arrows of outrageous fortune\n"
  "Or to take arms against a sea of troubles,\n"
  "And by opposing end them?--To die,--to sleep,--\n"
  "No more; and by a sleep to say we end\n"
  "The heartache, and the thousand natural shocks\n"
  "That flesh is heir to,--'tis a consummation\n"
  "Devoutly to be wish'd. To die,--to sleep;--\n"
  "To sleep! perchance to dream:--ay, there's the rub;\n"
  "For in that sleep of death what dreams may come,\n"
  "When we have shuffled off this mortal coil,\n"
  "Must give us pause: there's the respect\n"
  "That makes calamity of so long life;\n"
  "For who would bear the whips and scorns of time,\n"
  "The oppressor's wrong, the proud man's contumely,\n"
  "The pangs of despis'd love, the law's delay,\n"
  "The insolence of office, and the spurns\n"
  "That patient merit of the unworthy takes,\n"
  "When he himself might his quietus make\n"
  "With a bare bodkin? who would these fardels bear,\n"
  "To grunt and sweat under a weary life,\n"
  "But that the dread of something after death,--\n"
  "The undiscover'd country, from whose bourn\n"
  "No traveller returns,--puzzles the will,\n"
  "And makes us rather bear those ills we have\n"
  "Than fly to others that we know not of?\n"
  "Thus conscience does make cowards of us all;\n"
  "And thus the native hue of resolution\n"
  "Is sicklied o'er with the pale cast of thought;\n"
  "And enterprises of great pith and moment,\n"
  "With this regard, their currents turn awry,\n"
  "And lose the name of action.--Soft you now!\n"
  "The fair Ophelia!--Nymph, in thy orisons\n"
  "Be all my sins remember'd.\n";

#define STATUS_STARTING 0
#define STATUS_INIT     1
#define STATUS_RUNNING  2
#define STATUS_PAUSED   3
#define STATUS_ABORTED  6
#define STATUS_QUIT     7
#define STATUS_BYPASS   8

uint64_t get_thread_words_total  (uint32_t num_threads);
uint64_t get_thread_plains_total (uint32_t num_threads);

void descrypt_decode (unsigned char digest[DIGEST_SIZE_DESCRYPT], unsigned char buf[HASH_SIZE_DESCRYPT]);
void descrypt_encode (unsigned char digest[DIGEST_SIZE_DESCRYPT], unsigned char buf[HASH_SIZE_DESCRYPT]);

void phpass_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_PHPASS]);
void phpass_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_PHPASS]);

void md5unix_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5UNIX]);
void md5unix_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5UNIX]);

void md5sun_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5SUN]);
void md5sun_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5SUN]);

void md5apr_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5APR]);
void md5apr_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5APR]);

void sha512unix_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512UNIX]);
void sha512unix_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512UNIX]);

void sha1b64_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1B64]);
void sha1b64_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1B64]);

void sha1b64s_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], uint32_t in_len, uint32_t *out_len, char *buf);
void sha1b64s_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], uint32_t salt_len, char *buf);

void sha256b64_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256B64]);
void sha256b64_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256B64]);

void sha1aix_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1AIX]);
void sha1aix_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1AIX]);

void sha256aix_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256AIX]);
void sha256aix_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256AIX]);

void sha512aix_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512AIX]);
void sha512aix_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512AIX]);

void sha1fortigate_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], char *buf);
void sha1fortigate_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], char *buf);

void sha256unix_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256UNIX]);
void sha256unix_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256UNIX]);

void md5cisco_decode (char in_buf[HASH_SIZE_MD5CISCO], uint32_t out_buf[4]);
void md5cisco_encode (uint32_t in_buf[4], unsigned char *out_buf);

void bcrypt_encode (char digest[DIGEST_SIZE_BCRYPT], char salt[16], char *bcrypt_str);
void bcrypt_decode (char digest[HASH_SIZE_BCRYPT], char salt[SALT_SIZE_MIN_BCRYPT], char *hash_buf, char *salt_buf);

void sha512b64s_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char salt[BLOCK_SIZE], uint32_t salt_len, char *buf);
void sha512b64s_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char salt[BLOCK_SIZE], uint32_t in_len, uint32_t *out_len, char *buf);

void drupal7_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_DRUPAL7]);
void drupal7_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_DRUPAL7]);

void format_plain  (FILE *fp, char *plain_ptr, uint plain_len, uint32_t output_authex);
void format_output (FILE *fp, engine_parameter_t *engine_parameter, char *out_buf, char *plain_ptr, uint plain_len, uint64_t pos);

int sort_by_pot (const void *v1, const void *v2);

void handle_show_request (FILE *out_fp, engine_parameter_t *engine_parameter, pot_t *pot, char *input_buf, int input_len, char *hash_buf, char *salt_buf, uint32_t salt_len, uint user_len);
void handle_left_request (FILE *out_fp, engine_parameter_t *engine_parameter, pot_t *pot, char *input_buf, int input_len, char *hash_buf, char *salt_buf, uint32_t salt_len);

char *strhashtype (const uint hash_mode);

uint is_valid_hex_char (const char c);

char hex_convert (char c);

char hex_to_char (char hex[2]);

char int_to_itoa64 (const char c);
char itoa64_to_int (const char c);

int base64_decode (char (*f) (const char), char *in_buf, int in_len, char *out_buf);
int base64_encode (char (*f) (const char), char *in_buf, int in_len, char *out_buf);

uint32_t hex_to_uint   (char hex[ 8]);
uint64_t hex_to_uint64 (char hex[16]);

void uint_to_hex_lower (uint32_t uint, char hex[8]);
void uint_to_hex_upper (uint32_t uint, char hex[8]);

void transform_netntlmv1_key (const uint8_t *nthash, uint8_t *key);

int compare_digest_plain      (const void *p1, const void *p2);
int compare_digest_md5        (const void *p1, const void *p2);
int compare_digest_sha1       (const void *p1, const void *p2);
int compare_digest_mysql      (const void *p1, const void *p2);
int compare_digest_md4        (const void *p1, const void *p2);
int compare_digest_sha256     (const void *p1, const void *p2);
int compare_digest_sha512     (const void *p1, const void *p2);
int compare_digest_descrypt   (const void *p1, const void *p2);
int compare_digest_keccak     (const void *p1, const void *p2);
int compare_digest_netntlmv1  (const void *p1, const void *p2);
int compare_digest_gost       (const void *p1, const void *p2);
int compare_digest_bcrypt     (const void *p1, const void *p2);

void descrypt_64    (plain_t *plains, digest_t *digests);
void keccak_64      (plain_t *plains, digest_t *digests);
void gost_64        (plain_t *plains, digest_t *digests);

void _des_keysetup (uint32_t data[2], uint32_t Kc[16], uint32_t Kd[16], const uint s_skb[8][64]);
void _des_encrypt  (uint32_t data[2], uint32_t Kc[16], uint32_t Kd[16], const uint s_SPtrans[8][64]);

void hashcat_md4_64    (__m128i digests[4], __m128i W[16]);
void hashcat_md5_64    (__m128i digests[4], __m128i W[16]);
void hashcat_sha1_64   (__m128i digests[5], __m128i W[16]);
void hashcat_sha256_64 (__m128i digests[8], __m128i W[16]);
void hashcat_sha512_64 (__m128i digests[8], __m128i W[16]);

void init_sse2 ();

void run_threads (engine_parameter_t *engine_parameter, db_t *db, void (*store_out) (plain_t *, digest_t *, salt_t *), void (*store_debug) (char *, int), void (*done) (), digest_t *quick_digest);

extern plain_t **plains_iteration;

#endif /* ENGINE_H */
