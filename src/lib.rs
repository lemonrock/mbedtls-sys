// This file is part of mbedtls-sys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls-sys/master/COPYRIGHT. No part of mbedtls-sys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls-sys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls-sys/master/COPYRIGHT.


#![allow(non_camel_case_types)]

extern crate core;
use ::core::default::Default;
use ::core::option::Option;
use ::core::mem::zeroed;
use ::core::mem::transmute;
use ::core::clone::Clone;
use ::std::os::raw::c_char;
use ::std::os::raw::c_uchar;
use ::std::os::raw::c_int;
use ::std::os::raw::c_uint;
use ::std::os::raw::c_void;

extern crate libc;
use self::libc::size_t;
use self::libc::time_t;
use self::libc::int64_t;
use self::libc::uint16_t;
use self::libc::uint32_t;
use self::libc::uint64_t;
use self::libc::FILE;
// Windows will have problems here
use self::libc::pthread_mutex_t;


#[link(name = "mbedcrypto")]
extern "C"
{
}

#[link(name = "mbedx509")]
extern "C"
{
}

#[link(name = "mbedtls")]
extern "C"
{
}

pub const MBEDTLS_ERR_MPI_FILE_IO_ERROR: c_int = -2;
pub const MBEDTLS_ERR_MPI_BAD_INPUT_DATA: c_int = -4;
pub const MBEDTLS_ERR_MPI_INVALID_CHARACTER: c_int = -6;
pub const MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL: c_int = -8;
pub const MBEDTLS_ERR_MPI_NEGATIVE_VALUE: c_int = -10;
pub const MBEDTLS_ERR_MPI_DIVISION_BY_ZERO: c_int = -12;
pub const MBEDTLS_ERR_MPI_NOT_ACCEPTABLE: c_int = -14;
pub const MBEDTLS_ERR_MPI_ALLOC_FAILED: c_int = -16;
pub const MBEDTLS_MPI_MAX_LIMBS: c_int = 10000;
pub const MBEDTLS_MPI_WINDOW_SIZE: c_int = 6;
pub const MBEDTLS_MPI_MAX_SIZE: c_int = 1024;
pub const MBEDTLS_MPI_MAX_BITS: c_int = 8192;
pub const MBEDTLS_MPI_MAX_BITS_SCALE100: c_int = 819200;
pub const MBEDTLS_LN_2_DIV_LN_10_SCALE100: c_int = 332;
pub const MBEDTLS_MPI_RW_BUFFER_SIZE: c_int = 2484;
pub const MBEDTLS_ERR_ECP_BAD_INPUT_DATA: c_int = -20352;
pub const MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL: c_int = -20224;
pub const MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE: c_int = -20096;
pub const MBEDTLS_ERR_ECP_VERIFY_FAILED: c_int = -19968;
pub const MBEDTLS_ERR_ECP_ALLOC_FAILED: c_int = -19840;
pub const MBEDTLS_ERR_ECP_RANDOM_FAILED: c_int = -19712;
pub const MBEDTLS_ERR_ECP_INVALID_KEY: c_int = -19584;
pub const MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH: c_int = -19456;
pub const MBEDTLS_ECP_DP_MAX: c_int = 12;
pub const MBEDTLS_ECP_MAX_BITS: c_int = 521;
pub const MBEDTLS_ECP_MAX_BYTES: c_int = 66;
pub const MBEDTLS_ECP_MAX_PT_LEN: c_int = 133;
pub const MBEDTLS_ECP_WINDOW_SIZE: c_int = 6;
pub const MBEDTLS_ECP_FIXED_POINT_OPTIM: c_int = 1;
pub const MBEDTLS_ECP_PF_UNCOMPRESSED: c_int = 0;
pub const MBEDTLS_ECP_PF_COMPRESSED: c_int = 1;
pub const MBEDTLS_ECP_TLS_NAMED_CURVE: c_int = 3;
pub const MBEDTLS_ERR_MD_FEATURE_UNAVAILABLE: c_int = -20608;
pub const MBEDTLS_ERR_MD_BAD_INPUT_DATA: c_int = -20736;
pub const MBEDTLS_ERR_MD_ALLOC_FAILED: c_int = -20864;
pub const MBEDTLS_ERR_MD_FILE_IO_ERROR: c_int = -20992;
pub const MBEDTLS_MD_MAX_SIZE: c_int = 64;
pub const MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE: c_int = -26;
pub const MBEDTLS_ERR_THREADING_BAD_INPUT_DATA: c_int = -28;
pub const MBEDTLS_ERR_THREADING_MUTEX_ERROR: c_int = -30;
pub const MBEDTLS_ERR_RSA_BAD_INPUT_DATA: c_int = -16512;
pub const MBEDTLS_ERR_RSA_INVALID_PADDING: c_int = -16640;
pub const MBEDTLS_ERR_RSA_KEY_GEN_FAILED: c_int = -16768;
pub const MBEDTLS_ERR_RSA_KEY_CHECK_FAILED: c_int = -16896;
pub const MBEDTLS_ERR_RSA_PUBLIC_FAILED: c_int = -17024;
pub const MBEDTLS_ERR_RSA_PRIVATE_FAILED: c_int = -17152;
pub const MBEDTLS_ERR_RSA_VERIFY_FAILED: c_int = -17280;
pub const MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE: c_int = -17408;
pub const MBEDTLS_ERR_RSA_RNG_FAILED: c_int = -17536;
pub const MBEDTLS_RSA_PUBLIC: c_int = 0;
pub const MBEDTLS_RSA_PRIVATE: c_int = 1;
pub const MBEDTLS_RSA_PKCS_V15: c_int = 0;
pub const MBEDTLS_RSA_PKCS_V21: c_int = 1;
pub const MBEDTLS_RSA_SIGN: c_int = 1;
pub const MBEDTLS_RSA_CRYPT: c_int = 2;
pub const MBEDTLS_RSA_SALT_LEN_ANY: c_int = -1;
pub const MBEDTLS_ECDSA_MAX_LEN: c_int = 141;
pub const MBEDTLS_ERR_PK_ALLOC_FAILED: c_int = -16256;
pub const MBEDTLS_ERR_PK_TYPE_MISMATCH: c_int = -16128;
pub const MBEDTLS_ERR_PK_BAD_INPUT_DATA: c_int = -16000;
pub const MBEDTLS_ERR_PK_FILE_IO_ERROR: c_int = -15872;
pub const MBEDTLS_ERR_PK_KEY_INVALID_VERSION: c_int = -15744;
pub const MBEDTLS_ERR_PK_KEY_INVALID_FORMAT: c_int = -15616;
pub const MBEDTLS_ERR_PK_UNKNOWN_PK_ALG: c_int = -15488;
pub const MBEDTLS_ERR_PK_PASSWORD_REQUIRED: c_int = -15360;
pub const MBEDTLS_ERR_PK_PASSWORD_MISMATCH: c_int = -15232;
pub const MBEDTLS_ERR_PK_INVALID_PUBKEY: c_int = -15104;
pub const MBEDTLS_ERR_PK_INVALID_ALG: c_int = -14976;
pub const MBEDTLS_ERR_PK_UNKNOWN_NAMED_CURVE: c_int = -14848;
pub const MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE: c_int = -14720;
pub const MBEDTLS_ERR_PK_SIG_LEN_MISMATCH: c_int = -14592;
pub const MBEDTLS_PK_DEBUG_MAX_ITEMS: c_int = 3;
pub const MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE: c_int = -24704;
pub const MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA: c_int = -24832;
pub const MBEDTLS_ERR_CIPHER_ALLOC_FAILED: c_int = -24960;
pub const MBEDTLS_ERR_CIPHER_INVALID_PADDING: c_int = -25088;
pub const MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED: c_int = -25216;
pub const MBEDTLS_ERR_CIPHER_AUTH_FAILED: c_int = -25344;
pub const MBEDTLS_ERR_CIPHER_INVALID_CONTEXT: c_int = -25472;
pub const MBEDTLS_CIPHER_VARIABLE_IV_LEN: c_int = 1;
pub const MBEDTLS_CIPHER_VARIABLE_KEY_LEN: c_int = 2;
pub const MBEDTLS_MAX_IV_LENGTH: c_int = 16;
pub const MBEDTLS_MAX_BLOCK_LENGTH: c_int = 16;
pub const MBEDTLS_TLS_RSA_WITH_NULL_MD5: c_int = 1;
pub const MBEDTLS_TLS_RSA_WITH_NULL_SHA: c_int = 2;
pub const MBEDTLS_TLS_RSA_WITH_RC4_128_MD5: c_int = 4;
pub const MBEDTLS_TLS_RSA_WITH_RC4_128_SHA: c_int = 5;
pub const MBEDTLS_TLS_RSA_WITH_DES_CBC_SHA: c_int = 9;
pub const MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA: c_int = 10;
pub const MBEDTLS_TLS_DHE_RSA_WITH_DES_CBC_SHA: c_int = 21;
pub const MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: c_int = 22;
pub const MBEDTLS_TLS_PSK_WITH_NULL_SHA: c_int = 44;
pub const MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA: c_int = 45;
pub const MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA: c_int = 46;
pub const MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA: c_int = 47;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA: c_int = 51;
pub const MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA: c_int = 53;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA: c_int = 57;
pub const MBEDTLS_TLS_RSA_WITH_NULL_SHA256: c_int = 59;
pub const MBEDTLS_TLS_RSA_WITH_AES_128_CBC_SHA256: c_int = 60;
pub const MBEDTLS_TLS_RSA_WITH_AES_256_CBC_SHA256: c_int = 61;
pub const MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA: c_int = 65;
pub const MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA: c_int = 69;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: c_int = 103;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: c_int = 107;
pub const MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA: c_int = 132;
pub const MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA: c_int = 136;
pub const MBEDTLS_TLS_PSK_WITH_RC4_128_SHA: c_int = 138;
pub const MBEDTLS_TLS_PSK_WITH_3DES_EDE_CBC_SHA: c_int = 139;
pub const MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA: c_int = 140;
pub const MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA: c_int = 141;
pub const MBEDTLS_TLS_DHE_PSK_WITH_RC4_128_SHA: c_int = 142;
pub const MBEDTLS_TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA: c_int = 143;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA: c_int = 144;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA: c_int = 145;
pub const MBEDTLS_TLS_RSA_PSK_WITH_RC4_128_SHA: c_int = 146;
pub const MBEDTLS_TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA: c_int = 147;
pub const MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA: c_int = 148;
pub const MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA: c_int = 149;
pub const MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256: c_int = 156;
pub const MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384: c_int = 157;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256: c_int = 158;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: c_int = 159;
pub const MBEDTLS_TLS_PSK_WITH_AES_128_GCM_SHA256: c_int = 168;
pub const MBEDTLS_TLS_PSK_WITH_AES_256_GCM_SHA384: c_int = 169;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256: c_int = 170;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384: c_int = 171;
pub const MBEDTLS_TLS_RSA_PSK_WITH_AES_128_GCM_SHA256: c_int = 172;
pub const MBEDTLS_TLS_RSA_PSK_WITH_AES_256_GCM_SHA384: c_int = 173;
pub const MBEDTLS_TLS_PSK_WITH_AES_128_CBC_SHA256: c_int = 174;
pub const MBEDTLS_TLS_PSK_WITH_AES_256_CBC_SHA384: c_int = 175;
pub const MBEDTLS_TLS_PSK_WITH_NULL_SHA256: c_int = 176;
pub const MBEDTLS_TLS_PSK_WITH_NULL_SHA384: c_int = 177;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256: c_int = 178;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384: c_int = 179;
pub const MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA256: c_int = 180;
pub const MBEDTLS_TLS_DHE_PSK_WITH_NULL_SHA384: c_int = 181;
pub const MBEDTLS_TLS_RSA_PSK_WITH_AES_128_CBC_SHA256: c_int = 182;
pub const MBEDTLS_TLS_RSA_PSK_WITH_AES_256_CBC_SHA384: c_int = 183;
pub const MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA256: c_int = 184;
pub const MBEDTLS_TLS_RSA_PSK_WITH_NULL_SHA384: c_int = 185;
pub const MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 186;
pub const MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 190;
pub const MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256: c_int = 192;
pub const MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256: c_int = 196;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_NULL_SHA: c_int = 49153;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_RC4_128_SHA: c_int = 49154;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA: c_int = 49155;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA: c_int = 49156;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA: c_int = 49157;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_NULL_SHA: c_int = 49158;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA: c_int = 49159;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: c_int = 49160;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: c_int = 49161;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: c_int = 49162;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_NULL_SHA: c_int = 49163;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_RC4_128_SHA: c_int = 49164;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA: c_int = 49165;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA: c_int = 49166;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA: c_int = 49167;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_NULL_SHA: c_int = 49168;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_RC4_128_SHA: c_int = 49169;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: c_int = 49170;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: c_int = 49171;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: c_int = 49172;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: c_int = 49187;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: c_int = 49188;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256: c_int = 49189;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384: c_int = 49190;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: c_int = 49191;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: c_int = 49192;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256: c_int = 49193;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384: c_int = 49194;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: c_int = 49195;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: c_int = 49196;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256: c_int = 49197;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384: c_int = 49198;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: c_int = 49199;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: c_int = 49200;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256: c_int = 49201;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384: c_int = 49202;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_RC4_128_SHA: c_int = 49203;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA: c_int = 49204;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA: c_int = 49205;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA: c_int = 49206;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256: c_int = 49207;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384: c_int = 49208;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA: c_int = 49209;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA256: c_int = 49210;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_NULL_SHA384: c_int = 49211;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 49266;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: c_int = 49267;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 49268;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384: c_int = 49269;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 49270;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384: c_int = 49271;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256: c_int = 49272;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384: c_int = 49273;
pub const MBEDTLS_TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49274;
pub const MBEDTLS_TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49275;
pub const MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49276;
pub const MBEDTLS_TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49277;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49286;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49287;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49288;
pub const MBEDTLS_TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49289;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49290;
pub const MBEDTLS_TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49291;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49292;
pub const MBEDTLS_TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49293;
pub const MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49294;
pub const MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49295;
pub const MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49296;
pub const MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49297;
pub const MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256: c_int = 49298;
pub const MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384: c_int = 49299;
pub const MBEDTLS_TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256: c_int = 49300;
pub const MBEDTLS_TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384: c_int = 49301;
pub const MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: c_int = 49302;
pub const MBEDTLS_TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: c_int = 49303;
pub const MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256: c_int = 49304;
pub const MBEDTLS_TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384: c_int = 49305;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256: c_int = 49306;
pub const MBEDTLS_TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384: c_int = 49307;
pub const MBEDTLS_TLS_RSA_WITH_AES_128_CCM: c_int = 49308;
pub const MBEDTLS_TLS_RSA_WITH_AES_256_CCM: c_int = 49309;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM: c_int = 49310;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM: c_int = 49311;
pub const MBEDTLS_TLS_RSA_WITH_AES_128_CCM_8: c_int = 49312;
pub const MBEDTLS_TLS_RSA_WITH_AES_256_CCM_8: c_int = 49313;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_128_CCM_8: c_int = 49314;
pub const MBEDTLS_TLS_DHE_RSA_WITH_AES_256_CCM_8: c_int = 49315;
pub const MBEDTLS_TLS_PSK_WITH_AES_128_CCM: c_int = 49316;
pub const MBEDTLS_TLS_PSK_WITH_AES_256_CCM: c_int = 49317;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM: c_int = 49318;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM: c_int = 49319;
pub const MBEDTLS_TLS_PSK_WITH_AES_128_CCM_8: c_int = 49320;
pub const MBEDTLS_TLS_PSK_WITH_AES_256_CCM_8: c_int = 49321;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_128_CCM_8: c_int = 49322;
pub const MBEDTLS_TLS_DHE_PSK_WITH_AES_256_CCM_8: c_int = 49323;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM: c_int = 49324;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM: c_int = 49325;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8: c_int = 49326;
pub const MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8: c_int = 49327;
pub const MBEDTLS_TLS_ECJPAKE_WITH_AES_128_CCM_8: c_int = 49407;
pub const MBEDTLS_CIPHERSUITE_WEAK: c_int = 1;
pub const MBEDTLS_CIPHERSUITE_SHORT_TAG: c_int = 2;
pub const MBEDTLS_CIPHERSUITE_NODTLS: c_int = 4;
pub const MBEDTLS_ERR_ASN1_OUT_OF_DATA: c_int = -96;
pub const MBEDTLS_ERR_ASN1_UNEXPECTED_TAG: c_int = -98;
pub const MBEDTLS_ERR_ASN1_INVALID_LENGTH: c_int = -100;
pub const MBEDTLS_ERR_ASN1_LENGTH_MISMATCH: c_int = -102;
pub const MBEDTLS_ERR_ASN1_INVALID_DATA: c_int = -104;
pub const MBEDTLS_ERR_ASN1_ALLOC_FAILED: c_int = -106;
pub const MBEDTLS_ERR_ASN1_BUF_TOO_SMALL: c_int = -108;
pub const MBEDTLS_ASN1_BOOLEAN: c_int = 1;
pub const MBEDTLS_ASN1_INTEGER: c_int = 2;
pub const MBEDTLS_ASN1_BIT_STRING: c_int = 3;
pub const MBEDTLS_ASN1_OCTET_STRING: c_int = 4;
pub const MBEDTLS_ASN1_NULL: c_int = 5;
pub const MBEDTLS_ASN1_OID: c_int = 6;
pub const MBEDTLS_ASN1_UTF8_STRING: c_int = 12;
pub const MBEDTLS_ASN1_SEQUENCE: c_int = 16;
pub const MBEDTLS_ASN1_SET: c_int = 17;
pub const MBEDTLS_ASN1_PRINTABLE_STRING: c_int = 19;
pub const MBEDTLS_ASN1_T61_STRING: c_int = 20;
pub const MBEDTLS_ASN1_IA5_STRING: c_int = 22;
pub const MBEDTLS_ASN1_UTC_TIME: c_int = 23;
pub const MBEDTLS_ASN1_GENERALIZED_TIME: c_int = 24;
pub const MBEDTLS_ASN1_UNIVERSAL_STRING: c_int = 28;
pub const MBEDTLS_ASN1_BMP_STRING: c_int = 30;
pub const MBEDTLS_ASN1_PRIMITIVE: c_int = 0;
pub const MBEDTLS_ASN1_CONSTRUCTED: c_int = 32;
pub const MBEDTLS_ASN1_CONTEXT_SPECIFIC: c_int = 128;
pub const MBEDTLS_X509_MAX_INTERMEDIATE_CA: c_int = 8;
pub const MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE: c_int = -8320;
pub const MBEDTLS_ERR_X509_UNKNOWN_OID: c_int = -8448;
pub const MBEDTLS_ERR_X509_INVALID_FORMAT: c_int = -8576;
pub const MBEDTLS_ERR_X509_INVALID_VERSION: c_int = -8704;
pub const MBEDTLS_ERR_X509_INVALID_SERIAL: c_int = -8832;
pub const MBEDTLS_ERR_X509_INVALID_ALG: c_int = -8960;
pub const MBEDTLS_ERR_X509_INVALID_NAME: c_int = -9088;
pub const MBEDTLS_ERR_X509_INVALID_DATE: c_int = -9216;
pub const MBEDTLS_ERR_X509_INVALID_SIGNATURE: c_int = -9344;
pub const MBEDTLS_ERR_X509_INVALID_EXTENSIONS: c_int = -9472;
pub const MBEDTLS_ERR_X509_UNKNOWN_VERSION: c_int = -9600;
pub const MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG: c_int = -9728;
pub const MBEDTLS_ERR_X509_SIG_MISMATCH: c_int = -9856;
pub const MBEDTLS_ERR_X509_CERT_VERIFY_FAILED: c_int = -9984;
pub const MBEDTLS_ERR_X509_CERT_UNKNOWN_FORMAT: c_int = -10112;
pub const MBEDTLS_ERR_X509_BAD_INPUT_DATA: c_int = -10240;
pub const MBEDTLS_ERR_X509_ALLOC_FAILED: c_int = -10368;
pub const MBEDTLS_ERR_X509_FILE_IO_ERROR: c_int = -10496;
pub const MBEDTLS_ERR_X509_BUFFER_TOO_SMALL: c_int = -10624;
pub const MBEDTLS_X509_BADCERT_EXPIRED: c_int = 1;
pub const MBEDTLS_X509_BADCERT_REVOKED: c_int = 2;
pub const MBEDTLS_X509_BADCERT_CN_MISMATCH: c_int = 4;
pub const MBEDTLS_X509_BADCERT_NOT_TRUSTED: c_int = 8;
pub const MBEDTLS_X509_BADCRL_NOT_TRUSTED: c_int = 16;
pub const MBEDTLS_X509_BADCRL_EXPIRED: c_int = 32;
pub const MBEDTLS_X509_BADCERT_MISSING: c_int = 64;
pub const MBEDTLS_X509_BADCERT_SKIP_VERIFY: c_int = 128;
pub const MBEDTLS_X509_BADCERT_OTHER: c_int = 256;
pub const MBEDTLS_X509_BADCERT_FUTURE: c_int = 512;
pub const MBEDTLS_X509_BADCRL_FUTURE: c_int = 1024;
pub const MBEDTLS_X509_BADCERT_KEY_USAGE: c_int = 2048;
pub const MBEDTLS_X509_BADCERT_EXT_KEY_USAGE: c_int = 4096;
pub const MBEDTLS_X509_BADCERT_NS_CERT_TYPE: c_int = 8192;
pub const MBEDTLS_X509_BADCERT_BAD_MD: c_int = 16384;
pub const MBEDTLS_X509_BADCERT_BAD_PK: c_int = 32768;
pub const MBEDTLS_X509_BADCERT_BAD_KEY: c_int = 65536;
pub const MBEDTLS_X509_BADCRL_BAD_MD: c_int = 131072;
pub const MBEDTLS_X509_BADCRL_BAD_PK: c_int = 262144;
pub const MBEDTLS_X509_BADCRL_BAD_KEY: c_int = 524288;
pub const MBEDTLS_X509_KU_DIGITAL_SIGNATURE: c_int = 128;
pub const MBEDTLS_X509_KU_NON_REPUDIATION: c_int = 64;
pub const MBEDTLS_X509_KU_KEY_ENCIPHERMENT: c_int = 32;
pub const MBEDTLS_X509_KU_DATA_ENCIPHERMENT: c_int = 16;
pub const MBEDTLS_X509_KU_KEY_AGREEMENT: c_int = 8;
pub const MBEDTLS_X509_KU_KEY_CERT_SIGN: c_int = 4;
pub const MBEDTLS_X509_KU_CRL_SIGN: c_int = 2;
pub const MBEDTLS_X509_KU_ENCIPHER_ONLY: c_int = 1;
pub const MBEDTLS_X509_KU_DECIPHER_ONLY: c_int = 32768;
pub const MBEDTLS_X509_NS_CERT_TYPE_SSL_CLIENT: c_int = 128;
pub const MBEDTLS_X509_NS_CERT_TYPE_SSL_SERVER: c_int = 64;
pub const MBEDTLS_X509_NS_CERT_TYPE_EMAIL: c_int = 32;
pub const MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING: c_int = 16;
pub const MBEDTLS_X509_NS_CERT_TYPE_RESERVED: c_int = 8;
pub const MBEDTLS_X509_NS_CERT_TYPE_SSL_CA: c_int = 4;
pub const MBEDTLS_X509_NS_CERT_TYPE_EMAIL_CA: c_int = 2;
pub const MBEDTLS_X509_NS_CERT_TYPE_OBJECT_SIGNING_CA: c_int = 1;
pub const MBEDTLS_X509_EXT_AUTHORITY_KEY_IDENTIFIER: c_int = 1;
pub const MBEDTLS_X509_EXT_SUBJECT_KEY_IDENTIFIER: c_int = 2;
pub const MBEDTLS_X509_EXT_KEY_USAGE: c_int = 4;
pub const MBEDTLS_X509_EXT_CERTIFICATE_POLICIES: c_int = 8;
pub const MBEDTLS_X509_EXT_POLICY_MAPPINGS: c_int = 16;
pub const MBEDTLS_X509_EXT_SUBJECT_ALT_NAME: c_int = 32;
pub const MBEDTLS_X509_EXT_ISSUER_ALT_NAME: c_int = 64;
pub const MBEDTLS_X509_EXT_SUBJECT_DIRECTORY_ATTRS: c_int = 128;
pub const MBEDTLS_X509_EXT_BASIC_CONSTRAINTS: c_int = 256;
pub const MBEDTLS_X509_EXT_NAME_CONSTRAINTS: c_int = 512;
pub const MBEDTLS_X509_EXT_POLICY_CONSTRAINTS: c_int = 1024;
pub const MBEDTLS_X509_EXT_EXTENDED_KEY_USAGE: c_int = 2048;
pub const MBEDTLS_X509_EXT_CRL_DISTRIBUTION_POINTS: c_int = 4096;
pub const MBEDTLS_X509_EXT_INIHIBIT_ANYPOLICY: c_int = 8192;
pub const MBEDTLS_X509_EXT_FRESHEST_CRL: c_int = 16384;
pub const MBEDTLS_X509_EXT_NS_CERT_TYPE: c_int = 65536;
pub const MBEDTLS_X509_FORMAT_DER: c_int = 1;
pub const MBEDTLS_X509_FORMAT_PEM: c_int = 2;
pub const MBEDTLS_X509_MAX_DN_NAME_SIZE: c_int = 256;
pub const MBEDTLS_X509_CRT_VERSION_1: c_int = 0;
pub const MBEDTLS_X509_CRT_VERSION_2: c_int = 1;
pub const MBEDTLS_X509_CRT_VERSION_3: c_int = 2;
pub const MBEDTLS_X509_RFC5280_MAX_SERIAL_LEN: c_int = 32;
pub const MBEDTLS_X509_RFC5280_UTC_TIME_LEN: c_int = 15;
pub const MBEDTLS_ERR_DHM_BAD_INPUT_DATA: c_int = -12416;
pub const MBEDTLS_ERR_DHM_READ_PARAMS_FAILED: c_int = -12544;
pub const MBEDTLS_ERR_DHM_MAKE_PARAMS_FAILED: c_int = -12672;
pub const MBEDTLS_ERR_DHM_READ_PUBLIC_FAILED: c_int = -12800;
pub const MBEDTLS_ERR_DHM_MAKE_PUBLIC_FAILED: c_int = -12928;
pub const MBEDTLS_ERR_DHM_CALC_SECRET_FAILED: c_int = -13056;
pub const MBEDTLS_ERR_DHM_INVALID_FORMAT: c_int = -13184;
pub const MBEDTLS_ERR_DHM_ALLOC_FAILED: c_int = -13312;
pub const MBEDTLS_ERR_DHM_FILE_IO_ERROR: c_int = -13440;
pub const MBEDTLS_ERR_SSL_FEATURE_UNAVAILABLE: c_int = -28800;
pub const MBEDTLS_ERR_SSL_BAD_INPUT_DATA: c_int = -28928;
pub const MBEDTLS_ERR_SSL_INVALID_MAC: c_int = -29056;
pub const MBEDTLS_ERR_SSL_INVALID_RECORD: c_int = -29184;
pub const MBEDTLS_ERR_SSL_CONN_EOF: c_int = -29312;
pub const MBEDTLS_ERR_SSL_UNKNOWN_CIPHER: c_int = -29440;
pub const MBEDTLS_ERR_SSL_NO_CIPHER_CHOSEN: c_int = -29568;
pub const MBEDTLS_ERR_SSL_NO_RNG: c_int = -29696;
pub const MBEDTLS_ERR_SSL_NO_CLIENT_CERTIFICATE: c_int = -29824;
pub const MBEDTLS_ERR_SSL_CERTIFICATE_TOO_LARGE: c_int = -29952;
pub const MBEDTLS_ERR_SSL_CERTIFICATE_REQUIRED: c_int = -30080;
pub const MBEDTLS_ERR_SSL_PRIVATE_KEY_REQUIRED: c_int = -30208;
pub const MBEDTLS_ERR_SSL_CA_CHAIN_REQUIRED: c_int = -30336;
pub const MBEDTLS_ERR_SSL_UNEXPECTED_MESSAGE: c_int = -30464;
pub const MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE: c_int = -30592;
pub const MBEDTLS_ERR_SSL_PEER_VERIFY_FAILED: c_int = -30720;
pub const MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY: c_int = -30848;
pub const MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO: c_int = -30976;
pub const MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO: c_int = -31104;
pub const MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE: c_int = -31232;
pub const MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_REQUEST: c_int = -31360;
pub const MBEDTLS_ERR_SSL_BAD_HS_SERVER_KEY_EXCHANGE: c_int = -31488;
pub const MBEDTLS_ERR_SSL_BAD_HS_SERVER_HELLO_DONE: c_int = -31616;
pub const MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE: c_int = -31744;
pub const MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_RP: c_int = -31872;
pub const MBEDTLS_ERR_SSL_BAD_HS_CLIENT_KEY_EXCHANGE_CS: c_int = -32000;
pub const MBEDTLS_ERR_SSL_BAD_HS_CERTIFICATE_VERIFY: c_int = -32128;
pub const MBEDTLS_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC: c_int = -32256;
pub const MBEDTLS_ERR_SSL_BAD_HS_FINISHED: c_int = -32384;
pub const MBEDTLS_ERR_SSL_ALLOC_FAILED: c_int = -32512;
pub const MBEDTLS_ERR_SSL_HW_ACCEL_FAILED: c_int = -32640;
pub const MBEDTLS_ERR_SSL_HW_ACCEL_FALLTHROUGH: c_int = -28544;
pub const MBEDTLS_ERR_SSL_COMPRESSION_FAILED: c_int = -28416;
pub const MBEDTLS_ERR_SSL_BAD_HS_PROTOCOL_VERSION: c_int = -28288;
pub const MBEDTLS_ERR_SSL_BAD_HS_NEW_SESSION_TICKET: c_int = -28160;
pub const MBEDTLS_ERR_SSL_SESSION_TICKET_EXPIRED: c_int = -28032;
pub const MBEDTLS_ERR_SSL_PK_TYPE_MISMATCH: c_int = -27904;
pub const MBEDTLS_ERR_SSL_UNKNOWN_IDENTITY: c_int = -27776;
pub const MBEDTLS_ERR_SSL_INTERNAL_ERROR: c_int = -27648;
pub const MBEDTLS_ERR_SSL_COUNTER_WRAPPING: c_int = -27520;
pub const MBEDTLS_ERR_SSL_WAITING_SERVER_HELLO_RENEGO: c_int = -27392;
pub const MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED: c_int = -27264;
pub const MBEDTLS_ERR_SSL_BUFFER_TOO_SMALL: c_int = -27136;
pub const MBEDTLS_ERR_SSL_NO_USABLE_CIPHERSUITE: c_int = -27008;
pub const MBEDTLS_ERR_SSL_WANT_READ: c_int = -26880;
pub const MBEDTLS_ERR_SSL_WANT_WRITE: c_int = -26752;
pub const MBEDTLS_ERR_SSL_TIMEOUT: c_int = -26624;
pub const MBEDTLS_ERR_SSL_CLIENT_RECONNECT: c_int = -26496;
pub const MBEDTLS_ERR_SSL_UNEXPECTED_RECORD: c_int = -26368;
pub const MBEDTLS_SSL_MAJOR_VERSION_3: c_int = 3;
pub const MBEDTLS_SSL_MINOR_VERSION_0: c_int = 0;
pub const MBEDTLS_SSL_MINOR_VERSION_1: c_int = 1;
pub const MBEDTLS_SSL_MINOR_VERSION_2: c_int = 2;
pub const MBEDTLS_SSL_MINOR_VERSION_3: c_int = 3;
pub const MBEDTLS_SSL_TRANSPORT_STREAM: c_int = 0;
pub const MBEDTLS_SSL_TRANSPORT_DATAGRAM: c_int = 1;
pub const MBEDTLS_SSL_MAX_HOST_NAME_LEN: c_int = 255;
pub const MBEDTLS_SSL_MAX_FRAG_LEN_NONE: c_int = 0;
pub const MBEDTLS_SSL_MAX_FRAG_LEN_512: c_int = 1;
pub const MBEDTLS_SSL_MAX_FRAG_LEN_1024: c_int = 2;
pub const MBEDTLS_SSL_MAX_FRAG_LEN_2048: c_int = 3;
pub const MBEDTLS_SSL_MAX_FRAG_LEN_4096: c_int = 4;
pub const MBEDTLS_SSL_MAX_FRAG_LEN_INVALID: c_int = 5;
pub const MBEDTLS_SSL_IS_CLIENT: c_int = 0;
pub const MBEDTLS_SSL_IS_SERVER: c_int = 1;
pub const MBEDTLS_SSL_IS_NOT_FALLBACK: c_int = 0;
pub const MBEDTLS_SSL_IS_FALLBACK: c_int = 1;
pub const MBEDTLS_SSL_EXTENDED_MS_DISABLED: c_int = 0;
pub const MBEDTLS_SSL_EXTENDED_MS_ENABLED: c_int = 1;
pub const MBEDTLS_SSL_ETM_DISABLED: c_int = 0;
pub const MBEDTLS_SSL_ETM_ENABLED: c_int = 1;
pub const MBEDTLS_SSL_COMPRESS_NULL: c_int = 0;
pub const MBEDTLS_SSL_COMPRESS_DEFLATE: c_int = 1;
pub const MBEDTLS_SSL_VERIFY_NONE: c_int = 0;
pub const MBEDTLS_SSL_VERIFY_OPTIONAL: c_int = 1;
pub const MBEDTLS_SSL_VERIFY_REQUIRED: c_int = 2;
pub const MBEDTLS_SSL_VERIFY_UNSET: c_int = 3;
pub const MBEDTLS_SSL_LEGACY_RENEGOTIATION: c_int = 0;
pub const MBEDTLS_SSL_SECURE_RENEGOTIATION: c_int = 1;
pub const MBEDTLS_SSL_RENEGOTIATION_DISABLED: c_int = 0;
pub const MBEDTLS_SSL_RENEGOTIATION_ENABLED: c_int = 1;
pub const MBEDTLS_SSL_ANTI_REPLAY_DISABLED: c_char = 0;
pub const MBEDTLS_SSL_ANTI_REPLAY_ENABLED: c_char = 1;
pub const MBEDTLS_SSL_RENEGOTIATION_NOT_ENFORCED: c_int = -1;
pub const MBEDTLS_SSL_RENEGO_MAX_RECORDS_DEFAULT: c_int = 16;
pub const MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION: c_int = 0;
pub const MBEDTLS_SSL_LEGACY_ALLOW_RENEGOTIATION: c_int = 1;
pub const MBEDTLS_SSL_LEGACY_BREAK_HANDSHAKE: c_int = 2;
pub const MBEDTLS_SSL_TRUNC_HMAC_DISABLED: c_int = 0;
pub const MBEDTLS_SSL_TRUNC_HMAC_ENABLED: c_int = 1;
pub const MBEDTLS_SSL_TRUNCATED_HMAC_LEN: c_int = 10;
pub const MBEDTLS_SSL_SESSION_TICKETS_DISABLED: c_int = 0;
pub const MBEDTLS_SSL_SESSION_TICKETS_ENABLED: c_int = 1;
pub const MBEDTLS_SSL_CBC_RECORD_SPLITTING_DISABLED: c_int = 0;
pub const MBEDTLS_SSL_CBC_RECORD_SPLITTING_ENABLED: c_int = 1;
pub const MBEDTLS_SSL_ARC4_ENABLED: c_int = 0;
pub const MBEDTLS_SSL_ARC4_DISABLED: c_int = 1;
pub const MBEDTLS_SSL_PRESET_DEFAULT: c_int = 0;
pub const MBEDTLS_SSL_PRESET_SUITEB: c_int = 2;
pub const MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN: c_int = 1000;
pub const MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX: c_int = 60000;
pub const MBEDTLS_SSL_DEFAULT_TICKET_LIFETIME: c_int = 86400;
pub const MBEDTLS_SSL_MAX_CONTENT_LEN: c_int = 16384;
pub const MBEDTLS_SSL_VERIFY_DATA_MAX_LEN: c_int = 12;
pub const MBEDTLS_SSL_EMPTY_RENEGOTIATION_INFO: c_int = 255;
pub const MBEDTLS_SSL_FALLBACK_SCSV_VALUE: c_int = 22016;
pub const MBEDTLS_SSL_HASH_NONE: c_int = 0;
pub const MBEDTLS_SSL_HASH_MD5: c_int = 1;
pub const MBEDTLS_SSL_HASH_SHA1: c_int = 2;
pub const MBEDTLS_SSL_HASH_SHA224: c_int = 3;
pub const MBEDTLS_SSL_HASH_SHA256: c_int = 4;
pub const MBEDTLS_SSL_HASH_SHA384: c_int = 5;
pub const MBEDTLS_SSL_HASH_SHA512: c_int = 6;
pub const MBEDTLS_SSL_SIG_ANON: c_int = 0;
pub const MBEDTLS_SSL_SIG_RSA: c_int = 1;
pub const MBEDTLS_SSL_SIG_ECDSA: c_int = 3;
pub const MBEDTLS_SSL_CERT_TYPE_RSA_SIGN: c_int = 1;
pub const MBEDTLS_SSL_CERT_TYPE_ECDSA_SIGN: c_int = 64;
pub const MBEDTLS_SSL_MSG_CHANGE_CIPHER_SPEC: c_int = 20;
pub const MBEDTLS_SSL_MSG_ALERT: c_int = 21;
pub const MBEDTLS_SSL_MSG_HANDSHAKE: c_int = 22;
pub const MBEDTLS_SSL_MSG_APPLICATION_DATA: c_int = 23;
pub const MBEDTLS_SSL_ALERT_LEVEL_WARNING: c_int = 1;
pub const MBEDTLS_SSL_ALERT_LEVEL_FATAL: c_int = 2;
pub const MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY: c_int = 0;
pub const MBEDTLS_SSL_ALERT_MSG_UNEXPECTED_MESSAGE: c_int = 10;
pub const MBEDTLS_SSL_ALERT_MSG_BAD_RECORD_MAC: c_int = 20;
pub const MBEDTLS_SSL_ALERT_MSG_DECRYPTION_FAILED: c_int = 21;
pub const MBEDTLS_SSL_ALERT_MSG_RECORD_OVERFLOW: c_int = 22;
pub const MBEDTLS_SSL_ALERT_MSG_DECOMPRESSION_FAILURE: c_int = 30;
pub const MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE: c_int = 40;
pub const MBEDTLS_SSL_ALERT_MSG_NO_CERT: c_int = 41;
pub const MBEDTLS_SSL_ALERT_MSG_BAD_CERT: c_int = 42;
pub const MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT: c_int = 43;
pub const MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED: c_int = 44;
pub const MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED: c_int = 45;
pub const MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN: c_int = 46;
pub const MBEDTLS_SSL_ALERT_MSG_ILLEGAL_PARAMETER: c_int = 47;
pub const MBEDTLS_SSL_ALERT_MSG_UNKNOWN_CA: c_int = 48;
pub const MBEDTLS_SSL_ALERT_MSG_ACCESS_DENIED: c_int = 49;
pub const MBEDTLS_SSL_ALERT_MSG_DECODE_ERROR: c_int = 50;
pub const MBEDTLS_SSL_ALERT_MSG_DECRYPT_ERROR: c_int = 51;
pub const MBEDTLS_SSL_ALERT_MSG_EXPORT_RESTRICTION: c_int = 60;
pub const MBEDTLS_SSL_ALERT_MSG_PROTOCOL_VERSION: c_int = 70;
pub const MBEDTLS_SSL_ALERT_MSG_INSUFFICIENT_SECURITY: c_int = 71;
pub const MBEDTLS_SSL_ALERT_MSG_INTERNAL_ERROR: c_int = 80;
pub const MBEDTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK: c_int = 86;
pub const MBEDTLS_SSL_ALERT_MSG_USER_CANCELED: c_int = 90;
pub const MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION: c_int = 100;
pub const MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT: c_int = 110;
pub const MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME: c_int = 112;
pub const MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY: c_int = 115;
pub const MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL: c_int = 120;
pub const MBEDTLS_SSL_HS_HELLO_REQUEST: c_int = 0;
pub const MBEDTLS_SSL_HS_CLIENT_HELLO: c_int = 1;
pub const MBEDTLS_SSL_HS_SERVER_HELLO: c_int = 2;
pub const MBEDTLS_SSL_HS_HELLO_VERIFY_REQUEST: c_int = 3;
pub const MBEDTLS_SSL_HS_NEW_SESSION_TICKET: c_int = 4;
pub const MBEDTLS_SSL_HS_CERTIFICATE: c_int = 11;
pub const MBEDTLS_SSL_HS_SERVER_KEY_EXCHANGE: c_int = 12;
pub const MBEDTLS_SSL_HS_CERTIFICATE_REQUEST: c_int = 13;
pub const MBEDTLS_SSL_HS_SERVER_HELLO_DONE: c_int = 14;
pub const MBEDTLS_SSL_HS_CERTIFICATE_VERIFY: c_int = 15;
pub const MBEDTLS_SSL_HS_CLIENT_KEY_EXCHANGE: c_int = 16;
pub const MBEDTLS_SSL_HS_FINISHED: c_int = 20;
pub const MBEDTLS_TLS_EXT_SERVERNAME: c_int = 0;
pub const MBEDTLS_TLS_EXT_SERVERNAME_HOSTNAME: c_int = 0;
pub const MBEDTLS_TLS_EXT_MAX_FRAGMENT_LENGTH: c_int = 1;
pub const MBEDTLS_TLS_EXT_TRUNCATED_HMAC: c_int = 4;
pub const MBEDTLS_TLS_EXT_SUPPORTED_ELLIPTIC_CURVES: c_int = 10;
pub const MBEDTLS_TLS_EXT_SUPPORTED_POINT_FORMATS: c_int = 11;
pub const MBEDTLS_TLS_EXT_SIG_ALG: c_int = 13;
pub const MBEDTLS_TLS_EXT_ALPN: c_int = 16;
pub const MBEDTLS_TLS_EXT_ENCRYPT_THEN_MAC: c_int = 22;
pub const MBEDTLS_TLS_EXT_EXTENDED_MASTER_SECRET: c_int = 23;
pub const MBEDTLS_TLS_EXT_SESSION_TICKET: c_int = 35;
pub const MBEDTLS_TLS_EXT_ECJPAKE_KKPP: c_int = 256;
pub const MBEDTLS_TLS_EXT_RENEGOTIATION_INFO: c_int = 65281;
pub const MBEDTLS_PSK_MAX_LEN: c_int = 32;
pub const MBEDTLS_SSL_CHANNEL_OUTBOUND: c_int = 0;
pub const MBEDTLS_SSL_CHANNEL_INBOUND: c_int = 1;
pub type mbedtls_iso_c_forbids_empty_translation_units = c_int;

pub type mbedtls_mpi_sint = int64_t;

pub type mbedtls_mpi_uint = uint64_t;

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
#[cfg(all(unix, target_pointer_width = "64"))]
pub struct u128
{
	pub a: uint64_t,
	pub b: uint64_t,
}

impl Default for u128
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[cfg(windows)]
pub type mbedtls_t_udbl = uint64_t;

#[cfg(all(unix, target_pointer_width = "64"))]
pub type mbedtls_t_udbl = u128;

#[cfg(all(unix, target_pointer_width = "32"))]
pub type mbedtls_t_udbl = uint64_t;

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_mpi
{
	pub s: c_int,
	pub n: size_t,
	pub p: *mut mbedtls_mpi_uint,
}

impl Default for mbedtls_mpi
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_ecp_group_id
{
	MBEDTLS_ECP_DP_NONE = 0,
	MBEDTLS_ECP_DP_SECP192R1 = 1,
	MBEDTLS_ECP_DP_SECP224R1 = 2,
	MBEDTLS_ECP_DP_SECP256R1 = 3,
	MBEDTLS_ECP_DP_SECP384R1 = 4,
	MBEDTLS_ECP_DP_SECP521R1 = 5,
	MBEDTLS_ECP_DP_BP256R1 = 6,
	MBEDTLS_ECP_DP_BP384R1 = 7,
	MBEDTLS_ECP_DP_BP512R1 = 8,
	MBEDTLS_ECP_DP_CURVE25519 = 9,
	MBEDTLS_ECP_DP_SECP192K1 = 10,
	MBEDTLS_ECP_DP_SECP224K1 = 11,
	MBEDTLS_ECP_DP_SECP256K1 = 12,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_ecp_curve_info
{
	pub grp_id: mbedtls_ecp_group_id,
	pub tls_id: uint16_t,
	pub bit_size: uint16_t,
	pub name: *const c_char,
}

impl Default for mbedtls_ecp_curve_info
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_ecp_point
{
	pub X: mbedtls_mpi,
	pub Y: mbedtls_mpi,
	pub Z: mbedtls_mpi,
}

impl Default for mbedtls_ecp_point
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_ecp_group
{
	pub id: mbedtls_ecp_group_id,
	pub P: mbedtls_mpi,
	pub A: mbedtls_mpi,
	pub B: mbedtls_mpi,
	pub G: mbedtls_ecp_point,
	pub N: mbedtls_mpi,
	pub pbits: size_t,
	pub nbits: size_t,
	pub h: c_uint,
	pub modp: Option<unsafe extern "C" fn(arg1: *mut mbedtls_mpi) -> c_int>,
	pub t_pre: Option<unsafe extern "C" fn(arg1: *mut mbedtls_ecp_point, arg2: *mut c_void) -> c_int>,
	pub t_post: Option<unsafe extern "C" fn(arg1: *mut mbedtls_ecp_point, arg2: *mut c_void) -> c_int>,
	pub t_data: *mut c_void,
	pub T: *mut mbedtls_ecp_point,
	pub T_size: size_t,
}

impl Default for mbedtls_ecp_group
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_ecp_keypair
{
	pub grp: mbedtls_ecp_group,
	pub d: mbedtls_mpi,
	pub Q: mbedtls_ecp_point,
}

impl Default for mbedtls_ecp_keypair
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_md_type_t
{
	MBEDTLS_MD_NONE = 0,
	MBEDTLS_MD_MD2 = 1,
	MBEDTLS_MD_MD4 = 2,
	MBEDTLS_MD_MD5 = 3,
	MBEDTLS_MD_SHA1 = 4,
	MBEDTLS_MD_SHA224 = 5,
	MBEDTLS_MD_SHA256 = 6,
	MBEDTLS_MD_SHA384 = 7,
	MBEDTLS_MD_SHA512 = 8,
	MBEDTLS_MD_RIPEMD160 = 9,
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub enum mbedtls_md_info_t
{
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_md_context_t
{
	pub md_info: *const mbedtls_md_info_t,
	pub md_ctx: *mut c_void,
	pub hmac_ctx: *mut c_void,
}

impl Default for mbedtls_md_context_t
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(missing_debug_implementations)]
pub struct mbedtls_threading_mutex_t
{
	pub mutex: pthread_mutex_t,
	pub is_valid: c_char,
	_bindgen_padding_0_: [u8; 7usize],
}

impl Default for mbedtls_threading_mutex_t
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[allow(missing_debug_implementations)]
pub struct mbedtls_rsa_context
{
	pub ver: c_int,
	pub len: size_t,
	pub N: mbedtls_mpi,
	pub E: mbedtls_mpi,
	pub D: mbedtls_mpi,
	pub P: mbedtls_mpi,
	pub Q: mbedtls_mpi,
	pub DP: mbedtls_mpi,
	pub DQ: mbedtls_mpi,
	pub QP: mbedtls_mpi,
	pub RN: mbedtls_mpi,
	pub RP: mbedtls_mpi,
	pub RQ: mbedtls_mpi,
	pub Vi: mbedtls_mpi,
	pub Vf: mbedtls_mpi,
	pub padding: c_int,
	pub hash_id: c_int,
	pub mutex: mbedtls_threading_mutex_t,
}

impl Default for mbedtls_rsa_context
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

pub type mbedtls_ecdsa_context = mbedtls_ecp_keypair;

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_pk_type_t
{
	MBEDTLS_PK_NONE = 0,
	MBEDTLS_PK_RSA = 1,
	MBEDTLS_PK_ECKEY = 2,
	MBEDTLS_PK_ECKEY_DH = 3,
	MBEDTLS_PK_ECDSA = 4,
	MBEDTLS_PK_RSA_ALT = 5,
	MBEDTLS_PK_RSASSA_PSS = 6,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_pk_rsassa_pss_options
{
	pub mgf1_hash_id: mbedtls_md_type_t,
	pub expected_salt_len: c_int,
}

impl Default for mbedtls_pk_rsassa_pss_options
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_pk_debug_type
{
	MBEDTLS_PK_DEBUG_NONE = 0,
	MBEDTLS_PK_DEBUG_MPI = 1,
	MBEDTLS_PK_DEBUG_ECP = 2,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_pk_debug_item
{
	pub type_: mbedtls_pk_debug_type,
	pub name: *const c_char,
	pub value: *mut c_void,
}

impl Default for mbedtls_pk_debug_item
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub enum mbedtls_pk_info_t
{
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_pk_context
{
	pub pk_info: *const mbedtls_pk_info_t,
	pub pk_ctx: *mut c_void,
}

impl Default for mbedtls_pk_context
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

pub type mbedtls_pk_rsa_alt_decrypt_func = Option<unsafe extern "C" fn(ctx: *mut c_void, mode: c_int, olen: *mut size_t, input: *const c_uchar, output: *mut c_uchar, output_max_len: size_t) -> c_int>;

pub type mbedtls_pk_rsa_alt_sign_func = Option<unsafe extern "C" fn(ctx: *mut c_void, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, md_alg: mbedtls_md_type_t, hashlen: c_uint, hash: *const c_uchar, sig: *mut c_uchar) -> c_int>;

pub type mbedtls_pk_rsa_alt_key_len_func = Option<unsafe extern "C" fn(ctx: *mut c_void) -> size_t>;

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_cipher_id_t
{
	MBEDTLS_CIPHER_ID_NONE = 0,
	MBEDTLS_CIPHER_ID_NULL = 1,
	MBEDTLS_CIPHER_ID_AES = 2,
	MBEDTLS_CIPHER_ID_DES = 3,
	MBEDTLS_CIPHER_ID_3DES = 4,
	MBEDTLS_CIPHER_ID_CAMELLIA = 5,
	MBEDTLS_CIPHER_ID_BLOWFISH = 6,
	MBEDTLS_CIPHER_ID_ARC4 = 7,
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_cipher_type_t
{
	MBEDTLS_CIPHER_NONE = 0,
	MBEDTLS_CIPHER_NULL = 1,
	MBEDTLS_CIPHER_AES_128_ECB = 2,
	MBEDTLS_CIPHER_AES_192_ECB = 3,
	MBEDTLS_CIPHER_AES_256_ECB = 4,
	MBEDTLS_CIPHER_AES_128_CBC = 5,
	MBEDTLS_CIPHER_AES_192_CBC = 6,
	MBEDTLS_CIPHER_AES_256_CBC = 7,
	MBEDTLS_CIPHER_AES_128_CFB128 = 8,
	MBEDTLS_CIPHER_AES_192_CFB128 = 9,
	MBEDTLS_CIPHER_AES_256_CFB128 = 10,
	MBEDTLS_CIPHER_AES_128_CTR = 11,
	MBEDTLS_CIPHER_AES_192_CTR = 12,
	MBEDTLS_CIPHER_AES_256_CTR = 13,
	MBEDTLS_CIPHER_AES_128_GCM = 14,
	MBEDTLS_CIPHER_AES_192_GCM = 15,
	MBEDTLS_CIPHER_AES_256_GCM = 16,
	MBEDTLS_CIPHER_CAMELLIA_128_ECB = 17,
	MBEDTLS_CIPHER_CAMELLIA_192_ECB = 18,
	MBEDTLS_CIPHER_CAMELLIA_256_ECB = 19,
	MBEDTLS_CIPHER_CAMELLIA_128_CBC = 20,
	MBEDTLS_CIPHER_CAMELLIA_192_CBC = 21,
	MBEDTLS_CIPHER_CAMELLIA_256_CBC = 22,
	MBEDTLS_CIPHER_CAMELLIA_128_CFB128 = 23,
	MBEDTLS_CIPHER_CAMELLIA_192_CFB128 = 24,
	MBEDTLS_CIPHER_CAMELLIA_256_CFB128 = 25,
	MBEDTLS_CIPHER_CAMELLIA_128_CTR = 26,
	MBEDTLS_CIPHER_CAMELLIA_192_CTR = 27,
	MBEDTLS_CIPHER_CAMELLIA_256_CTR = 28,
	MBEDTLS_CIPHER_CAMELLIA_128_GCM = 29,
	MBEDTLS_CIPHER_CAMELLIA_192_GCM = 30,
	MBEDTLS_CIPHER_CAMELLIA_256_GCM = 31,
	MBEDTLS_CIPHER_DES_ECB = 32,
	MBEDTLS_CIPHER_DES_CBC = 33,
	MBEDTLS_CIPHER_DES_EDE_ECB = 34,
	MBEDTLS_CIPHER_DES_EDE_CBC = 35,
	MBEDTLS_CIPHER_DES_EDE3_ECB = 36,
	MBEDTLS_CIPHER_DES_EDE3_CBC = 37,
	MBEDTLS_CIPHER_BLOWFISH_ECB = 38,
	MBEDTLS_CIPHER_BLOWFISH_CBC = 39,
	MBEDTLS_CIPHER_BLOWFISH_CFB64 = 40,
	MBEDTLS_CIPHER_BLOWFISH_CTR = 41,
	MBEDTLS_CIPHER_ARC4_128 = 42,
	MBEDTLS_CIPHER_AES_128_CCM = 43,
	MBEDTLS_CIPHER_AES_192_CCM = 44,
	MBEDTLS_CIPHER_AES_256_CCM = 45,
	MBEDTLS_CIPHER_CAMELLIA_128_CCM = 46,
	MBEDTLS_CIPHER_CAMELLIA_192_CCM = 47,
	MBEDTLS_CIPHER_CAMELLIA_256_CCM = 48,
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_cipher_mode_t
{
	MBEDTLS_MODE_NONE = 0,
	MBEDTLS_MODE_ECB = 1,
	MBEDTLS_MODE_CBC = 2,
	MBEDTLS_MODE_CFB = 3,
	MBEDTLS_MODE_OFB = 4,
	MBEDTLS_MODE_CTR = 5,
	MBEDTLS_MODE_GCM = 6,
	MBEDTLS_MODE_STREAM = 7,
	MBEDTLS_MODE_CCM = 8,
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_cipher_padding_t
{
	MBEDTLS_PADDING_PKCS7 = 0,
	MBEDTLS_PADDING_ONE_AND_ZEROS = 1,
	MBEDTLS_PADDING_ZEROS_AND_LEN = 2,
	MBEDTLS_PADDING_ZEROS = 3,
	MBEDTLS_PADDING_NONE = 4,
}

#[derive(Copy, Clone)]
#[repr(i32)]
#[derive(Debug)]
pub enum mbedtls_operation_t
{
	MBEDTLS_OPERATION_NONE = -1,
	MBEDTLS_DECRYPT = 0,
	MBEDTLS_ENCRYPT = 1,
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum Enum_Unnamed1
{
	MBEDTLS_KEY_LENGTH_NONE = 0,
	MBEDTLS_KEY_LENGTH_DES = 64,
	MBEDTLS_KEY_LENGTH_DES_EDE = 128,
	MBEDTLS_KEY_LENGTH_DES_EDE3 = 192,
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub enum mbedtls_cipher_base_t
{
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_cipher_info_t
{
	pub type_: mbedtls_cipher_type_t,
	pub mode: mbedtls_cipher_mode_t,
	pub key_bitlen: c_uint,
	pub name: *const c_char,
	pub iv_size: c_uint,
	pub flags: c_int,
	pub block_size: c_uint,
	pub base: *const mbedtls_cipher_base_t,
}

impl Default for mbedtls_cipher_info_t
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_cipher_context_t
{
	pub cipher_info: *const mbedtls_cipher_info_t,
	pub key_bitlen: c_int,
	pub operation: mbedtls_operation_t,
	pub add_padding: Option<unsafe extern "C" fn(output: *mut c_uchar, olen: size_t, data_len: size_t)>,
	pub get_padding: Option<unsafe extern "C" fn(input: *mut c_uchar, ilen: size_t, data_len: *mut size_t) -> c_int>,
	pub unprocessed_data: [c_uchar; 16usize],
	pub unprocessed_len: size_t,
	pub iv: [c_uchar; 16usize],
	pub iv_size: size_t,
	pub cipher_ctx: *mut c_void,
}

impl Default for mbedtls_cipher_context_t
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_key_exchange_type_t
{
	MBEDTLS_KEY_EXCHANGE_NONE = 0,
	MBEDTLS_KEY_EXCHANGE_RSA = 1,
	MBEDTLS_KEY_EXCHANGE_DHE_RSA = 2,
	MBEDTLS_KEY_EXCHANGE_ECDHE_RSA = 3,
	MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA = 4,
	MBEDTLS_KEY_EXCHANGE_PSK = 5,
	MBEDTLS_KEY_EXCHANGE_DHE_PSK = 6,
	MBEDTLS_KEY_EXCHANGE_RSA_PSK = 7,
	MBEDTLS_KEY_EXCHANGE_ECDHE_PSK = 8,
	MBEDTLS_KEY_EXCHANGE_ECDH_RSA = 9,
	MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA = 10,
	MBEDTLS_KEY_EXCHANGE_ECJPAKE = 11,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_ssl_ciphersuite_t
{
	pub id: c_int,
	pub name: *const c_char,
	pub cipher: mbedtls_cipher_type_t,
	pub mac: mbedtls_md_type_t,
	pub key_exchange: mbedtls_key_exchange_type_t,
	pub min_major_ver: c_int,
	pub min_minor_ver: c_int,
	pub max_major_ver: c_int,
	pub max_minor_ver: c_int,
	pub flags: c_uchar,
	_bindgen_padding_0_: [u8; 3usize],
}

impl Default for mbedtls_ssl_ciphersuite_t
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_asn1_buf
{
	pub tag: c_int,
	pub len: size_t,
	pub p: *mut c_uchar,
}

impl Default for mbedtls_asn1_buf
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_asn1_bitstring
{
	pub len: size_t,
	pub unused_bits: c_uchar,
	pub p: *mut c_uchar,
}

impl Default for mbedtls_asn1_bitstring
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_asn1_sequence
{
	pub buf: mbedtls_asn1_buf,
	pub next: *mut mbedtls_asn1_sequence,
}

impl Default for mbedtls_asn1_sequence
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_asn1_named_data
{
	pub oid: mbedtls_asn1_buf,
	pub val: mbedtls_asn1_buf,
	pub next: *mut mbedtls_asn1_named_data,
	pub next_merged: c_uchar,
	_bindgen_padding_0_: [u8; 7usize],
}

impl Default for mbedtls_asn1_named_data
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

pub type mbedtls_x509_buf = mbedtls_asn1_buf;

pub type mbedtls_x509_bitstring = mbedtls_asn1_bitstring;

pub type mbedtls_x509_name = mbedtls_asn1_named_data;

pub type mbedtls_x509_sequence = mbedtls_asn1_sequence;

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_x509_time
{
	pub year: c_int,
	pub mon: c_int,
	pub day: c_int,
	pub hour: c_int,
	pub min: c_int,
	pub sec: c_int,
}

impl Default for mbedtls_x509_time
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_x509_crl_entry
{
	pub raw: mbedtls_x509_buf,
	pub serial: mbedtls_x509_buf,
	pub revocation_date: mbedtls_x509_time,
	pub entry_ext: mbedtls_x509_buf,
	pub next: *mut mbedtls_x509_crl_entry,
}

impl Default for mbedtls_x509_crl_entry
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_x509_crl
{
	pub raw: mbedtls_x509_buf,
	pub tbs: mbedtls_x509_buf,
	pub version: c_int,
	pub sig_oid: mbedtls_x509_buf,
	pub issuer_raw: mbedtls_x509_buf,
	pub issuer: mbedtls_x509_name,
	pub this_update: mbedtls_x509_time,
	pub next_update: mbedtls_x509_time,
	pub entry: mbedtls_x509_crl_entry,
	pub crl_ext: mbedtls_x509_buf,
	pub sig_oid2: mbedtls_x509_buf,
	pub sig: mbedtls_x509_buf,
	pub sig_md: mbedtls_md_type_t,
	pub sig_pk: mbedtls_pk_type_t,
	pub sig_opts: *mut c_void,
	pub next: *mut mbedtls_x509_crl,
}

impl Default for mbedtls_x509_crl
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_x509_crt
{
	pub raw: mbedtls_x509_buf,
	pub tbs: mbedtls_x509_buf,
	pub version: c_int,
	pub serial: mbedtls_x509_buf,
	pub sig_oid: mbedtls_x509_buf,
	pub issuer_raw: mbedtls_x509_buf,
	pub subject_raw: mbedtls_x509_buf,
	pub issuer: mbedtls_x509_name,
	pub subject: mbedtls_x509_name,
	pub valid_from: mbedtls_x509_time,
	pub valid_to: mbedtls_x509_time,
	pub pk: mbedtls_pk_context,
	pub issuer_id: mbedtls_x509_buf,
	pub subject_id: mbedtls_x509_buf,
	pub v3_ext: mbedtls_x509_buf,
	pub subject_alt_names: mbedtls_x509_sequence,
	pub ext_types: c_int,
	pub ca_istrue: c_int,
	pub max_pathlen: c_int,
	pub key_usage: c_uint,
	pub ext_key_usage: mbedtls_x509_sequence,
	pub ns_cert_type: c_uchar,
	pub sig: mbedtls_x509_buf,
	pub sig_md: mbedtls_md_type_t,
	pub sig_pk: mbedtls_pk_type_t,
	pub sig_opts: *mut c_void,
	pub next: *mut mbedtls_x509_crt,
}

impl Default for mbedtls_x509_crt
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_x509_crt_profile
{
	pub allowed_mds: uint32_t,
	pub allowed_pks: uint32_t,
	pub allowed_curves: uint32_t,
	pub rsa_min_bitlen: uint32_t,
}

impl Default for mbedtls_x509_crt_profile
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_x509write_cert
{
	pub version: c_int,
	pub serial: mbedtls_mpi,
	pub subject_key: *mut mbedtls_pk_context,
	pub issuer_key: *mut mbedtls_pk_context,
	pub subject: *mut mbedtls_asn1_named_data,
	pub issuer: *mut mbedtls_asn1_named_data,
	pub md_alg: mbedtls_md_type_t,
	pub not_before: [c_char; 16usize],
	pub not_after: [c_char; 16usize],
	pub extensions: *mut mbedtls_asn1_named_data,
}

impl Default for mbedtls_x509write_cert
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_dhm_context
{
	pub len: size_t,
	pub P: mbedtls_mpi,
	pub G: mbedtls_mpi,
	pub X: mbedtls_mpi,
	pub GX: mbedtls_mpi,
	pub GY: mbedtls_mpi,
	pub K: mbedtls_mpi,
	pub RP: mbedtls_mpi,
	pub Vi: mbedtls_mpi,
	pub Vf: mbedtls_mpi,
	pub pX: mbedtls_mpi,
}

impl Default for mbedtls_dhm_context
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_ecdh_side
{
	MBEDTLS_ECDH_OURS = 0,
	MBEDTLS_ECDH_THEIRS = 1,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_ecdh_context
{
	pub grp: mbedtls_ecp_group,
	pub d: mbedtls_mpi,
	pub Q: mbedtls_ecp_point,
	pub Qp: mbedtls_ecp_point,
	pub z: mbedtls_mpi,
	pub point_format: c_int,
	pub Vi: mbedtls_ecp_point,
	pub Vf: mbedtls_ecp_point,
	pub _d: mbedtls_mpi,
}

impl Default for mbedtls_ecdh_context
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

pub type mbedtls_time_t = time_t;

#[repr(C)]
#[derive(Copy)]
#[allow(missing_debug_implementations)]
pub struct mbedtls_ssl_premaster_secret
{
	pub _bindgen_data_: [u8; 1060usize],
}

impl mbedtls_ssl_premaster_secret
{
	pub unsafe fn _pms_rsa(&mut self) -> *mut [c_uchar; 48usize]
	{
		let raw: *mut u8 = transmute(&self._bindgen_data_);
		transmute(raw.offset(0))
	}
	pub unsafe fn _pms_dhm(&mut self) -> *mut [c_uchar; 1024usize]
	{
		let raw: *mut u8 = transmute(&self._bindgen_data_);
		transmute(raw.offset(0))
	}
	pub unsafe fn _pms_ecdh(&mut self) -> *mut [c_uchar; 66usize]
	{
		let raw: *mut u8 = transmute(&self._bindgen_data_);
		transmute(raw.offset(0))
	}
	pub unsafe fn _pms_psk(&mut self) -> *mut [c_uchar; 68usize]
	{
		let raw: *mut u8 = transmute(&self._bindgen_data_);
		transmute(raw.offset(0))
	}
	pub unsafe fn _pms_dhe_psk(&mut self) -> *mut [c_uchar; 1060usize]
	{
		let raw: *mut u8 = transmute(&self._bindgen_data_);
		transmute(raw.offset(0))
	}
	pub unsafe fn _pms_rsa_psk(&mut self) -> *mut [c_uchar; 84usize]
	{
		let raw: *mut u8 = transmute(&self._bindgen_data_);
		transmute(raw.offset(0))
	}
	pub unsafe fn _pms_ecdhe_psk(&mut self) -> *mut [c_uchar; 102usize]
	{
		let raw: *mut u8 = transmute(&self._bindgen_data_);
		transmute(raw.offset(0))
	}
}

impl Clone for mbedtls_ssl_premaster_secret
{
	fn clone(&self) -> Self
	{
		*self
	}
}

impl Default for mbedtls_ssl_premaster_secret
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[derive(Copy, Clone)]
#[repr(u32)]
#[derive(Debug)]
pub enum mbedtls_ssl_states
{
	MBEDTLS_SSL_HELLO_REQUEST = 0,
	MBEDTLS_SSL_CLIENT_HELLO = 1,
	MBEDTLS_SSL_SERVER_HELLO = 2,
	MBEDTLS_SSL_SERVER_CERTIFICATE = 3,
	MBEDTLS_SSL_SERVER_KEY_EXCHANGE = 4,
	MBEDTLS_SSL_CERTIFICATE_REQUEST = 5,
	MBEDTLS_SSL_SERVER_HELLO_DONE = 6,
	MBEDTLS_SSL_CLIENT_CERTIFICATE = 7,
	MBEDTLS_SSL_CLIENT_KEY_EXCHANGE = 8,
	MBEDTLS_SSL_CERTIFICATE_VERIFY = 9,
	MBEDTLS_SSL_CLIENT_CHANGE_CIPHER_SPEC = 10,
	MBEDTLS_SSL_CLIENT_FINISHED = 11,
	MBEDTLS_SSL_SERVER_CHANGE_CIPHER_SPEC = 12,
	MBEDTLS_SSL_SERVER_FINISHED = 13,
	MBEDTLS_SSL_FLUSH_BUFFERS = 14,
	MBEDTLS_SSL_HANDSHAKE_WRAPUP = 15,
	MBEDTLS_SSL_HANDSHAKE_OVER = 16,
	MBEDTLS_SSL_SERVER_NEW_SESSION_TICKET = 17,
	MBEDTLS_SSL_SERVER_HELLO_VERIFY_REQUEST_SENT = 18,
}

pub type mbedtls_ssl_send_t = Option<unsafe extern "C" fn(ctx: *mut c_void, buf: *const c_uchar, len: size_t) -> c_int>;

pub type mbedtls_ssl_recv_t = Option<unsafe extern "C" fn(ctx: *mut c_void, buf: *mut c_uchar, len: size_t) -> c_int>;

pub type mbedtls_ssl_recv_timeout_t = Option<unsafe extern "C" fn(ctx: *mut c_void, buf: *mut c_uchar, len: size_t, timeout: uint32_t) -> c_int>;

pub type mbedtls_ssl_set_timer_t = Option<unsafe extern "C" fn(ctx: *mut c_void, int_ms: uint32_t, fin_ms: uint32_t)>;

pub type mbedtls_ssl_get_timer_t = Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>;

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub enum mbedtls_ssl_transform
{
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub enum mbedtls_ssl_handshake_params
{
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub enum mbedtls_ssl_key_cert
{
}

#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub enum mbedtls_ssl_flight_item
{
}

#[repr(C)]
#[derive(Copy)]
#[allow(missing_debug_implementations)]
pub struct mbedtls_ssl_session
{
	pub start: mbedtls_time_t,
	pub ciphersuite: c_int,
	pub compression: c_int,
	pub id_len: size_t,
	pub id: [c_uchar; 32usize],
	pub master: [c_uchar; 48usize],
	pub peer_cert: *mut mbedtls_x509_crt,
	pub verify_result: uint32_t,
	pub ticket: *mut c_uchar,
	pub ticket_len: size_t,
	pub ticket_lifetime: uint32_t,
	pub mfl_code: c_uchar,
	pub encrypt_then_mac: c_int,
}

impl Clone for mbedtls_ssl_session
{
	fn clone(&self) -> Self
	{
		*self
	}
}

impl Default for mbedtls_ssl_session
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_ssl_config
{
	pub ciphersuite_list: [*const c_int; 4usize],
	pub f_dbg: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: c_int, arg3: *const c_char, arg4: c_int, arg5: *const c_char)>,
	pub p_dbg: *mut c_void,
	pub f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>,
	pub p_rng: *mut c_void,
	pub f_get_cache: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_ssl_session) -> c_int>,
	pub f_set_cache: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *const mbedtls_ssl_session) -> c_int>,
	pub p_cache: *mut c_void,
	pub f_sni: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_ssl_context, arg3: *const c_uchar, arg4: size_t) -> c_int>,
	pub p_sni: *mut c_void,
	pub f_vrfy: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_x509_crt, arg3: c_int, arg4: *mut uint32_t) -> c_int>,
	pub p_vrfy: *mut c_void,
	pub f_psk: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_ssl_context, arg3: *const c_uchar, arg4: size_t) -> c_int>,
	pub p_psk: *mut c_void,
	pub f_cookie_write: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut *mut c_uchar, arg3: *mut c_uchar, arg4: *const c_uchar, arg5: size_t) -> c_int>,
	pub f_cookie_check: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *const c_uchar, arg3: size_t, arg4: *const c_uchar, arg5: size_t) -> c_int>,
	pub p_cookie: *mut c_void,
	pub f_ticket_write: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *const mbedtls_ssl_session, arg3: *mut c_uchar, arg4: *const c_uchar, arg5: *mut size_t, arg6: *mut uint32_t) -> c_int>,
	pub f_ticket_parse: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_ssl_session, arg3: *mut c_uchar, arg4: size_t) -> c_int>,
	pub p_ticket: *mut c_void,
	pub cert_profile: *const mbedtls_x509_crt_profile,
	pub key_cert: *mut mbedtls_ssl_key_cert,
	pub ca_chain: *mut mbedtls_x509_crt,
	pub ca_crl: *mut mbedtls_x509_crl,
	pub sig_hashes: *const c_int,
	pub curve_list: *const mbedtls_ecp_group_id,
	pub dhm_P: mbedtls_mpi,
	pub dhm_G: mbedtls_mpi,
	pub psk: *mut c_uchar,
	pub psk_len: size_t,
	pub psk_identity: *mut c_uchar,
	pub psk_identity_len: size_t,
	pub alpn_list: *mut *const c_char,
	pub read_timeout: uint32_t,
	pub hs_timeout_min: uint32_t,
	pub hs_timeout_max: uint32_t,
	pub badmac_limit: c_uint,
	pub dhm_min_bitlen: c_uint,
	pub max_major_ver: c_uchar,
	pub max_minor_ver: c_uchar,
	pub min_major_ver: c_uchar,
	pub min_minor_ver: c_uchar,
	pub _bindgen_bitfield_1_: c_uint,
}

impl Default for mbedtls_ssl_config
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_ssl_context
{
	pub conf: *const mbedtls_ssl_config,
	pub state: c_int,
	pub major_ver: c_int,
	pub minor_ver: c_int,
	pub badmac_seen: c_uint,
	pub f_send: mbedtls_ssl_send_t,
	pub f_recv: mbedtls_ssl_recv_t,
	pub f_recv_timeout: mbedtls_ssl_recv_timeout_t,
	pub p_bio: *mut c_void,
	pub session_in: *mut mbedtls_ssl_session,
	pub session_out: *mut mbedtls_ssl_session,
	pub session: *mut mbedtls_ssl_session,
	pub session_negotiate: *mut mbedtls_ssl_session,
	pub handshake: *mut mbedtls_ssl_handshake_params,
	pub transform_in: *mut mbedtls_ssl_transform,
	pub transform_out: *mut mbedtls_ssl_transform,
	pub transform: *mut mbedtls_ssl_transform,
	pub transform_negotiate: *mut mbedtls_ssl_transform,
	pub p_timer: *mut c_void,
	pub f_set_timer: mbedtls_ssl_set_timer_t,
	pub f_get_timer: mbedtls_ssl_get_timer_t,
	pub in_buf: *mut c_uchar,
	pub in_ctr: *mut c_uchar,
	pub in_hdr: *mut c_uchar,
	pub in_len: *mut c_uchar,
	pub in_iv: *mut c_uchar,
	pub in_msg: *mut c_uchar,
	pub in_offt: *mut c_uchar,
	pub in_msgtype: c_int,
	pub in_msglen: size_t,
	pub in_left: size_t,
	pub in_epoch: uint16_t,
	pub next_record_offset: size_t,
	pub in_window_top: uint64_t,
	pub in_window: uint64_t,
	pub in_hslen: size_t,
	pub nb_zero: c_int,
	pub record_read: c_int,
	pub out_buf: *mut c_uchar,
	pub out_ctr: *mut c_uchar,
	pub out_hdr: *mut c_uchar,
	pub out_len: *mut c_uchar,
	pub out_iv: *mut c_uchar,
	pub out_msg: *mut c_uchar,
	pub out_msgtype: c_int,
	pub out_msglen: size_t,
	pub out_left: size_t,
	pub client_auth: c_int,
	pub hostname: *mut c_char,
	pub alpn_chosen: *const c_char,
	pub cli_id: *mut c_uchar,
	pub cli_id_len: size_t,
	pub secure_renegotiation: c_int,
	_bindgen_padding_0_: [u8; 4usize],
}

impl Default for mbedtls_ssl_context
{
	fn default() -> Self
	{
		unsafe { zeroed() }
	}
}

pub type mbedtls_ssl_ticket_write_t = Option<unsafe extern "C" fn(p_ticket: *mut c_void, session: *const mbedtls_ssl_session, start: *mut c_uchar, end: *const c_uchar, tlen: *mut size_t, lifetime: *mut uint32_t) -> c_int>;

pub type mbedtls_ssl_ticket_parse_t = Option<unsafe extern "C" fn(p_ticket: *mut c_void, session: *mut mbedtls_ssl_session, buf: *mut c_uchar, len: size_t) -> c_int>;

pub type mbedtls_ssl_cookie_write_t = Option<unsafe extern "C" fn(ctx: *mut c_void, p: *mut *mut c_uchar, end: *mut c_uchar, info: *const c_uchar, ilen: size_t) -> c_int>;

pub type mbedtls_ssl_cookie_check_t = Option<unsafe extern "C" fn(ctx: *mut c_void, cookie: *const c_uchar, clen: size_t, info: *const c_uchar, ilen: size_t) -> c_int>;

extern "C"
{
	pub static mut mbedtls_mutex_init: Option<unsafe extern "C" fn(mutex: *mut mbedtls_threading_mutex_t)>;
	pub static mut mbedtls_mutex_free: Option<unsafe extern "C" fn(mutex: *mut mbedtls_threading_mutex_t)>;
	pub static mut mbedtls_mutex_lock: Option<unsafe extern "C" fn(mutex: *mut mbedtls_threading_mutex_t) -> c_int>;
	pub static mut mbedtls_mutex_unlock: Option<unsafe extern "C" fn(mutex: *mut mbedtls_threading_mutex_t) -> c_int>;
	pub static mut mbedtls_threading_readdir_mutex: mbedtls_threading_mutex_t;
	pub static mut mbedtls_threading_gmtime_mutex: mbedtls_threading_mutex_t;
	pub static mbedtls_x509_crt_profile_default: mbedtls_x509_crt_profile;
	pub static mbedtls_x509_crt_profile_next: mbedtls_x509_crt_profile;
	pub static mbedtls_x509_crt_profile_suiteb: mbedtls_x509_crt_profile;
	pub static mut mbedtls_ssl_hw_record_init: Option<unsafe extern "C" fn(ssl: *mut mbedtls_ssl_context, key_enc: *const c_uchar, key_dec: *const c_uchar, keylen: size_t, iv_enc: *const c_uchar, iv_dec: *const c_uchar, ivlen: size_t, mac_enc: *const c_uchar, mac_dec: *const c_uchar, maclen: size_t) -> c_int>;
	pub static mut mbedtls_ssl_hw_record_activate: Option<unsafe extern "C" fn(ssl: *mut mbedtls_ssl_context, direction: c_int) -> c_int>;
	pub static mut mbedtls_ssl_hw_record_reset: Option<unsafe extern "C" fn(ssl: *mut mbedtls_ssl_context) -> c_int>;
	pub static mut mbedtls_ssl_hw_record_write: Option<unsafe extern "C" fn(ssl: *mut mbedtls_ssl_context) -> c_int>;
	pub static mut mbedtls_ssl_hw_record_read: Option<unsafe extern "C" fn(ssl: *mut mbedtls_ssl_context) -> c_int>;
	pub static mut mbedtls_ssl_hw_record_finish: Option<unsafe extern "C" fn(ssl: *mut mbedtls_ssl_context) -> c_int>;
}

extern "C"
{
	pub fn mbedtls_mpi_init(X: *mut mbedtls_mpi);
	pub fn mbedtls_mpi_free(X: *mut mbedtls_mpi);
	pub fn mbedtls_mpi_grow(X: *mut mbedtls_mpi, nblimbs: size_t) -> c_int;
	pub fn mbedtls_mpi_shrink(X: *mut mbedtls_mpi, nblimbs: size_t) -> c_int;
	pub fn mbedtls_mpi_copy(X: *mut mbedtls_mpi, Y: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_swap(X: *mut mbedtls_mpi, Y: *mut mbedtls_mpi);
	pub fn mbedtls_mpi_safe_cond_assign(X: *mut mbedtls_mpi, Y: *const mbedtls_mpi, assign: c_uchar) -> c_int;
	pub fn mbedtls_mpi_safe_cond_swap(X: *mut mbedtls_mpi, Y: *mut mbedtls_mpi, assign: c_uchar) -> c_int;
	pub fn mbedtls_mpi_lset(X: *mut mbedtls_mpi, z: mbedtls_mpi_sint) -> c_int;
	pub fn mbedtls_mpi_get_bit(X: *const mbedtls_mpi, pos: size_t) -> c_int;
	pub fn mbedtls_mpi_set_bit(X: *mut mbedtls_mpi, pos: size_t, val: c_uchar) -> c_int;
	pub fn mbedtls_mpi_lsb(X: *const mbedtls_mpi) -> size_t;
	pub fn mbedtls_mpi_bitlen(X: *const mbedtls_mpi) -> size_t;
	pub fn mbedtls_mpi_size(X: *const mbedtls_mpi) -> size_t;
	pub fn mbedtls_mpi_read_string(X: *mut mbedtls_mpi, radix: c_int, s: *const c_char) -> c_int;
	pub fn mbedtls_mpi_write_string(X: *const mbedtls_mpi, radix: c_int, buf: *mut c_char, buflen: size_t, olen: *mut size_t) -> c_int;
	pub fn mbedtls_mpi_read_file(X: *mut mbedtls_mpi, radix: c_int, fin: *mut FILE) -> c_int;
	pub fn mbedtls_mpi_write_file(p: *const c_char, X: *const mbedtls_mpi, radix: c_int, fout: *mut FILE) -> c_int;
	pub fn mbedtls_mpi_read_binary(X: *mut mbedtls_mpi, buf: *const c_uchar, buflen: size_t) -> c_int;
	pub fn mbedtls_mpi_write_binary(X: *const mbedtls_mpi, buf: *mut c_uchar, buflen: size_t) -> c_int;
	pub fn mbedtls_mpi_shift_l(X: *mut mbedtls_mpi, count: size_t) -> c_int;
	pub fn mbedtls_mpi_shift_r(X: *mut mbedtls_mpi, count: size_t) -> c_int;
	pub fn mbedtls_mpi_cmp_abs(X: *const mbedtls_mpi, Y: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_cmp_mpi(X: *const mbedtls_mpi, Y: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_cmp_int(X: *const mbedtls_mpi, z: mbedtls_mpi_sint) -> c_int;
	pub fn mbedtls_mpi_add_abs(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, B: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_sub_abs(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, B: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_add_mpi(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, B: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_sub_mpi(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, B: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_add_int(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, b: mbedtls_mpi_sint) -> c_int;
	pub fn mbedtls_mpi_sub_int(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, b: mbedtls_mpi_sint) -> c_int;
	pub fn mbedtls_mpi_mul_mpi(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, B: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_mul_int(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, b: mbedtls_mpi_uint) -> c_int;
	pub fn mbedtls_mpi_div_mpi(Q: *mut mbedtls_mpi, R: *mut mbedtls_mpi, A: *const mbedtls_mpi, B: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_div_int(Q: *mut mbedtls_mpi, R: *mut mbedtls_mpi, A: *const mbedtls_mpi, b: mbedtls_mpi_sint) -> c_int;
	pub fn mbedtls_mpi_mod_mpi(R: *mut mbedtls_mpi, A: *const mbedtls_mpi, B: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_mod_int(r: *mut mbedtls_mpi_uint, A: *const mbedtls_mpi, b: mbedtls_mpi_sint) -> c_int;
	pub fn mbedtls_mpi_exp_mod(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, E: *const mbedtls_mpi, N: *const mbedtls_mpi, _RR: *mut mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_fill_random(X: *mut mbedtls_mpi, size: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_mpi_gcd(G: *mut mbedtls_mpi, A: *const mbedtls_mpi, B: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_inv_mod(X: *mut mbedtls_mpi, A: *const mbedtls_mpi, N: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_mpi_is_prime(X: *const mbedtls_mpi, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_mpi_gen_prime(X: *mut mbedtls_mpi, nbits: size_t, dh_flag: c_int, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_mpi_self_test(verbose: c_int) -> c_int;
	pub fn mbedtls_ecp_curve_list() -> *const mbedtls_ecp_curve_info;
	pub fn mbedtls_ecp_grp_id_list() -> *const mbedtls_ecp_group_id;
	pub fn mbedtls_ecp_curve_info_from_grp_id(grp_id: mbedtls_ecp_group_id) -> *const mbedtls_ecp_curve_info;
	pub fn mbedtls_ecp_curve_info_from_tls_id(tls_id: uint16_t) -> *const mbedtls_ecp_curve_info;
	pub fn mbedtls_ecp_curve_info_from_name(name: *const c_char) -> *const mbedtls_ecp_curve_info;
	pub fn mbedtls_ecp_point_init(pt: *mut mbedtls_ecp_point);
	pub fn mbedtls_ecp_group_init(grp: *mut mbedtls_ecp_group);
	pub fn mbedtls_ecp_keypair_init(key: *mut mbedtls_ecp_keypair);
	pub fn mbedtls_ecp_point_free(pt: *mut mbedtls_ecp_point);
	pub fn mbedtls_ecp_group_free(grp: *mut mbedtls_ecp_group);
	pub fn mbedtls_ecp_keypair_free(key: *mut mbedtls_ecp_keypair);
	pub fn mbedtls_ecp_copy(P: *mut mbedtls_ecp_point, Q: *const mbedtls_ecp_point) -> c_int;
	pub fn mbedtls_ecp_group_copy(dst: *mut mbedtls_ecp_group, src: *const mbedtls_ecp_group) -> c_int;
	pub fn mbedtls_ecp_set_zero(pt: *mut mbedtls_ecp_point) -> c_int;
	pub fn mbedtls_ecp_is_zero(pt: *mut mbedtls_ecp_point) -> c_int;
	pub fn mbedtls_ecp_point_cmp(P: *const mbedtls_ecp_point, Q: *const mbedtls_ecp_point) -> c_int;
	pub fn mbedtls_ecp_point_read_string(P: *mut mbedtls_ecp_point, radix: c_int, x: *const c_char, y: *const c_char) -> c_int;
	pub fn mbedtls_ecp_point_write_binary(grp: *const mbedtls_ecp_group, P: *const mbedtls_ecp_point, format: c_int, olen: *mut size_t, buf: *mut c_uchar, buflen: size_t) -> c_int;
	pub fn mbedtls_ecp_point_read_binary(grp: *const mbedtls_ecp_group, P: *mut mbedtls_ecp_point, buf: *const c_uchar, ilen: size_t) -> c_int;
	pub fn mbedtls_ecp_tls_read_point(grp: *const mbedtls_ecp_group, pt: *mut mbedtls_ecp_point, buf: *mut *const c_uchar, len: size_t) -> c_int;
	pub fn mbedtls_ecp_tls_write_point(grp: *const mbedtls_ecp_group, pt: *const mbedtls_ecp_point, format: c_int, olen: *mut size_t, buf: *mut c_uchar, blen: size_t) -> c_int;
	pub fn mbedtls_ecp_group_load(grp: *mut mbedtls_ecp_group, index: mbedtls_ecp_group_id) -> c_int;
	pub fn mbedtls_ecp_tls_read_group(grp: *mut mbedtls_ecp_group, buf: *mut *const c_uchar, len: size_t) -> c_int;
	pub fn mbedtls_ecp_tls_write_group(grp: *const mbedtls_ecp_group, olen: *mut size_t, buf: *mut c_uchar, blen: size_t) -> c_int;
	pub fn mbedtls_ecp_mul(grp: *mut mbedtls_ecp_group, R: *mut mbedtls_ecp_point, m: *const mbedtls_mpi, P: *const mbedtls_ecp_point, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecp_muladd(grp: *mut mbedtls_ecp_group, R: *mut mbedtls_ecp_point, m: *const mbedtls_mpi, P: *const mbedtls_ecp_point, n: *const mbedtls_mpi, Q: *const mbedtls_ecp_point) -> c_int;
	pub fn mbedtls_ecp_check_pubkey(grp: *const mbedtls_ecp_group, pt: *const mbedtls_ecp_point) -> c_int;
	pub fn mbedtls_ecp_check_privkey(grp: *const mbedtls_ecp_group, d: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_ecp_gen_keypair_base(grp: *mut mbedtls_ecp_group, G: *const mbedtls_ecp_point, d: *mut mbedtls_mpi, Q: *mut mbedtls_ecp_point, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecp_gen_keypair(grp: *mut mbedtls_ecp_group, d: *mut mbedtls_mpi, Q: *mut mbedtls_ecp_point, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecp_gen_key(grp_id: mbedtls_ecp_group_id, key: *mut mbedtls_ecp_keypair, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecp_check_pub_priv(pub_: *const mbedtls_ecp_keypair, prv: *const mbedtls_ecp_keypair) -> c_int;
	pub fn mbedtls_ecp_self_test(verbose: c_int) -> c_int;
	pub fn mbedtls_md_list() -> *const c_int;
	pub fn mbedtls_md_info_from_string(md_name: *const c_char) -> *const mbedtls_md_info_t;
	pub fn mbedtls_md_info_from_type(md_type: mbedtls_md_type_t) -> *const mbedtls_md_info_t;
	pub fn mbedtls_md_init(ctx: *mut mbedtls_md_context_t);
	pub fn mbedtls_md_free(ctx: *mut mbedtls_md_context_t);
	pub fn mbedtls_md_setup(ctx: *mut mbedtls_md_context_t, md_info: *const mbedtls_md_info_t, hmac: c_int) -> c_int;
	pub fn mbedtls_md_clone(dst: *mut mbedtls_md_context_t, src: *const mbedtls_md_context_t) -> c_int;
	pub fn mbedtls_md_get_size(md_info: *const mbedtls_md_info_t) -> c_uchar;
	pub fn mbedtls_md_get_type(md_info: *const mbedtls_md_info_t) -> mbedtls_md_type_t;
	pub fn mbedtls_md_get_name(md_info: *const mbedtls_md_info_t) -> *const c_char;
	pub fn mbedtls_md_starts(ctx: *mut mbedtls_md_context_t) -> c_int;
	pub fn mbedtls_md_update(ctx: *mut mbedtls_md_context_t, input: *const c_uchar, ilen: size_t) -> c_int;
	pub fn mbedtls_md_finish(ctx: *mut mbedtls_md_context_t, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_md(md_info: *const mbedtls_md_info_t, input: *const c_uchar, ilen: size_t, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_md_file(md_info: *const mbedtls_md_info_t, path: *const c_char, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_md_hmac_starts(ctx: *mut mbedtls_md_context_t, key: *const c_uchar, keylen: size_t) -> c_int;
	pub fn mbedtls_md_hmac_update(ctx: *mut mbedtls_md_context_t, input: *const c_uchar, ilen: size_t) -> c_int;
	pub fn mbedtls_md_hmac_finish(ctx: *mut mbedtls_md_context_t, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_md_hmac_reset(ctx: *mut mbedtls_md_context_t) -> c_int;
	pub fn mbedtls_md_hmac(md_info: *const mbedtls_md_info_t, key: *const c_uchar, keylen: size_t, input: *const c_uchar, ilen: size_t, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_md_process(ctx: *mut mbedtls_md_context_t, data: *const c_uchar) -> c_int;
	pub fn mbedtls_rsa_init(ctx: *mut mbedtls_rsa_context, padding: c_int, hash_id: c_int);
	pub fn mbedtls_rsa_set_padding(ctx: *mut mbedtls_rsa_context, padding: c_int, hash_id: c_int);
	pub fn mbedtls_rsa_gen_key(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, nbits: c_uint, exponent: c_int) -> c_int;
	pub fn mbedtls_rsa_check_pubkey(ctx: *const mbedtls_rsa_context) -> c_int;
	pub fn mbedtls_rsa_check_privkey(ctx: *const mbedtls_rsa_context) -> c_int;
	pub fn mbedtls_rsa_check_pub_priv(pub_: *const mbedtls_rsa_context, prv: *const mbedtls_rsa_context) -> c_int;
	pub fn mbedtls_rsa_public(ctx: *mut mbedtls_rsa_context, input: *const c_uchar, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_rsa_private(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, input: *const c_uchar, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_rsa_pkcs1_encrypt(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, ilen: size_t, input: *const c_uchar, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_rsa_rsaes_pkcs1_v15_encrypt(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, ilen: size_t, input: *const c_uchar, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_rsa_rsaes_oaep_encrypt(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, label: *const c_uchar, label_len: size_t, ilen: size_t, input: *const c_uchar, output: *mut c_uchar) -> c_int;
	pub fn mbedtls_rsa_pkcs1_decrypt(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, olen: *mut size_t, input: *const c_uchar, output: *mut c_uchar, output_max_len: size_t) -> c_int;
	pub fn mbedtls_rsa_rsaes_pkcs1_v15_decrypt(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, olen: *mut size_t, input: *const c_uchar, output: *mut c_uchar, output_max_len: size_t) -> c_int;
	pub fn mbedtls_rsa_rsaes_oaep_decrypt(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, label: *const c_uchar, label_len: size_t, olen: *mut size_t, input: *const c_uchar, output: *mut c_uchar, output_max_len: size_t) -> c_int;
	pub fn mbedtls_rsa_pkcs1_sign(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, md_alg: mbedtls_md_type_t, hashlen: c_uint, hash: *const c_uchar, sig: *mut c_uchar) -> c_int;
	pub fn mbedtls_rsa_rsassa_pkcs1_v15_sign(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, md_alg: mbedtls_md_type_t, hashlen: c_uint, hash: *const c_uchar, sig: *mut c_uchar) -> c_int;
	pub fn mbedtls_rsa_rsassa_pss_sign(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, md_alg: mbedtls_md_type_t, hashlen: c_uint, hash: *const c_uchar, sig: *mut c_uchar) -> c_int;
	pub fn mbedtls_rsa_pkcs1_verify(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, md_alg: mbedtls_md_type_t, hashlen: c_uint, hash: *const c_uchar, sig: *const c_uchar) -> c_int;
	pub fn mbedtls_rsa_rsassa_pkcs1_v15_verify(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, md_alg: mbedtls_md_type_t, hashlen: c_uint, hash: *const c_uchar, sig: *const c_uchar) -> c_int;
	pub fn mbedtls_rsa_rsassa_pss_verify(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, md_alg: mbedtls_md_type_t, hashlen: c_uint, hash: *const c_uchar, sig: *const c_uchar) -> c_int;
	pub fn mbedtls_rsa_rsassa_pss_verify_ext(ctx: *mut mbedtls_rsa_context, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void, mode: c_int, md_alg: mbedtls_md_type_t, hashlen: c_uint, hash: *const c_uchar, mgf1_hash_id: mbedtls_md_type_t, expected_salt_len: c_int, sig: *const c_uchar) -> c_int;
	pub fn mbedtls_rsa_copy(dst: *mut mbedtls_rsa_context, src: *const mbedtls_rsa_context) -> c_int;
	pub fn mbedtls_rsa_free(ctx: *mut mbedtls_rsa_context);
	pub fn mbedtls_rsa_self_test(verbose: c_int) -> c_int;
	pub fn mbedtls_ecdsa_sign(grp: *mut mbedtls_ecp_group, r: *mut mbedtls_mpi, s: *mut mbedtls_mpi, d: *const mbedtls_mpi, buf: *const c_uchar, blen: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecdsa_sign_det(grp: *mut mbedtls_ecp_group, r: *mut mbedtls_mpi, s: *mut mbedtls_mpi, d: *const mbedtls_mpi, buf: *const c_uchar, blen: size_t, md_alg: mbedtls_md_type_t) -> c_int;
	pub fn mbedtls_ecdsa_verify(grp: *mut mbedtls_ecp_group, buf: *const c_uchar, blen: size_t, Q: *const mbedtls_ecp_point, r: *const mbedtls_mpi, s: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_ecdsa_write_signature(ctx: *mut mbedtls_ecdsa_context, md_alg: mbedtls_md_type_t, hash: *const c_uchar, hlen: size_t, sig: *mut c_uchar, slen: *mut size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecdsa_read_signature(ctx: *mut mbedtls_ecdsa_context, hash: *const c_uchar, hlen: size_t, sig: *const c_uchar, slen: size_t) -> c_int;
	pub fn mbedtls_ecdsa_genkey(ctx: *mut mbedtls_ecdsa_context, gid: mbedtls_ecp_group_id, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecdsa_from_keypair(ctx: *mut mbedtls_ecdsa_context, key: *const mbedtls_ecp_keypair) -> c_int;
	pub fn mbedtls_ecdsa_init(ctx: *mut mbedtls_ecdsa_context);
	pub fn mbedtls_ecdsa_free(ctx: *mut mbedtls_ecdsa_context);
	pub fn mbedtls_pk_info_from_type(pk_type: mbedtls_pk_type_t) -> *const mbedtls_pk_info_t;
	pub fn mbedtls_pk_init(ctx: *mut mbedtls_pk_context);
	pub fn mbedtls_pk_free(ctx: *mut mbedtls_pk_context);
	pub fn mbedtls_pk_setup(ctx: *mut mbedtls_pk_context, info: *const mbedtls_pk_info_t) -> c_int;
	pub fn mbedtls_pk_setup_rsa_alt(ctx: *mut mbedtls_pk_context, key: *mut c_void, decrypt_func: mbedtls_pk_rsa_alt_decrypt_func, sign_func: mbedtls_pk_rsa_alt_sign_func, key_len_func: mbedtls_pk_rsa_alt_key_len_func) -> c_int;
	pub fn mbedtls_pk_get_bitlen(ctx: *const mbedtls_pk_context) -> size_t;
	pub fn mbedtls_pk_can_do(ctx: *const mbedtls_pk_context, type_: mbedtls_pk_type_t) -> c_int;
	pub fn mbedtls_pk_verify(ctx: *mut mbedtls_pk_context, md_alg: mbedtls_md_type_t, hash: *const c_uchar, hash_len: size_t, sig: *const c_uchar, sig_len: size_t) -> c_int;
	pub fn mbedtls_pk_verify_ext(type_: mbedtls_pk_type_t, options: *const c_void, ctx: *mut mbedtls_pk_context, md_alg: mbedtls_md_type_t, hash: *const c_uchar, hash_len: size_t, sig: *const c_uchar, sig_len: size_t) -> c_int;
	pub fn mbedtls_pk_sign(ctx: *mut mbedtls_pk_context, md_alg: mbedtls_md_type_t, hash: *const c_uchar, hash_len: size_t, sig: *mut c_uchar, sig_len: *mut size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_pk_decrypt(ctx: *mut mbedtls_pk_context, input: *const c_uchar, ilen: size_t, output: *mut c_uchar, olen: *mut size_t, osize: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_pk_encrypt(ctx: *mut mbedtls_pk_context, input: *const c_uchar, ilen: size_t, output: *mut c_uchar, olen: *mut size_t, osize: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_pk_check_pair(pub_: *const mbedtls_pk_context, prv: *const mbedtls_pk_context) -> c_int;
	pub fn mbedtls_pk_debug(ctx: *const mbedtls_pk_context, items: *mut mbedtls_pk_debug_item) -> c_int;
	pub fn mbedtls_pk_get_name(ctx: *const mbedtls_pk_context) -> *const c_char;
	pub fn mbedtls_pk_get_type(ctx: *const mbedtls_pk_context) -> mbedtls_pk_type_t;
	pub fn mbedtls_pk_parse_key(ctx: *mut mbedtls_pk_context, key: *const c_uchar, keylen: size_t, pwd: *const c_uchar, pwdlen: size_t) -> c_int;
	pub fn mbedtls_pk_parse_public_key(ctx: *mut mbedtls_pk_context, key: *const c_uchar, keylen: size_t) -> c_int;
	pub fn mbedtls_pk_parse_keyfile(ctx: *mut mbedtls_pk_context, path: *const c_char, password: *const c_char) -> c_int;
	pub fn mbedtls_pk_parse_public_keyfile(ctx: *mut mbedtls_pk_context, path: *const c_char) -> c_int;
	pub fn mbedtls_pk_write_key_der(ctx: *mut mbedtls_pk_context, buf: *mut c_uchar, size: size_t) -> c_int;
	pub fn mbedtls_pk_write_pubkey_der(ctx: *mut mbedtls_pk_context, buf: *mut c_uchar, size: size_t) -> c_int;
	pub fn mbedtls_pk_write_pubkey_pem(ctx: *mut mbedtls_pk_context, buf: *mut c_uchar, size: size_t) -> c_int;
	pub fn mbedtls_pk_write_key_pem(ctx: *mut mbedtls_pk_context, buf: *mut c_uchar, size: size_t) -> c_int;
	pub fn mbedtls_pk_parse_subpubkey(p: *mut *mut c_uchar, end: *const c_uchar, pk: *mut mbedtls_pk_context) -> c_int;
	pub fn mbedtls_pk_write_pubkey(p: *mut *mut c_uchar, start: *mut c_uchar, key: *const mbedtls_pk_context) -> c_int;
	pub fn mbedtls_pk_load_file(path: *const c_char, buf: *mut *mut c_uchar, n: *mut size_t) -> c_int;
	pub fn mbedtls_cipher_list() -> *const c_int;
	pub fn mbedtls_cipher_info_from_string(cipher_name: *const c_char) -> *const mbedtls_cipher_info_t;
	pub fn mbedtls_cipher_info_from_type(cipher_type: mbedtls_cipher_type_t) -> *const mbedtls_cipher_info_t;
	pub fn mbedtls_cipher_info_from_values(cipher_id: mbedtls_cipher_id_t, key_bitlen: c_int, mode: mbedtls_cipher_mode_t) -> *const mbedtls_cipher_info_t;
	pub fn mbedtls_cipher_init(ctx: *mut mbedtls_cipher_context_t);
	pub fn mbedtls_cipher_free(ctx: *mut mbedtls_cipher_context_t);
	pub fn mbedtls_cipher_setup(ctx: *mut mbedtls_cipher_context_t, cipher_info: *const mbedtls_cipher_info_t) -> c_int;
	pub fn mbedtls_cipher_setkey(ctx: *mut mbedtls_cipher_context_t, key: *const c_uchar, key_bitlen: c_int, operation: mbedtls_operation_t) -> c_int;
	pub fn mbedtls_cipher_set_padding_mode(ctx: *mut mbedtls_cipher_context_t, mode: mbedtls_cipher_padding_t) -> c_int;
	pub fn mbedtls_cipher_set_iv(ctx: *mut mbedtls_cipher_context_t, iv: *const c_uchar, iv_len: size_t) -> c_int;
	pub fn mbedtls_cipher_reset(ctx: *mut mbedtls_cipher_context_t) -> c_int;
	pub fn mbedtls_cipher_update_ad(ctx: *mut mbedtls_cipher_context_t, ad: *const c_uchar, ad_len: size_t) -> c_int;
	pub fn mbedtls_cipher_update(ctx: *mut mbedtls_cipher_context_t, input: *const c_uchar, ilen: size_t, output: *mut c_uchar, olen: *mut size_t) -> c_int;
	pub fn mbedtls_cipher_finish(ctx: *mut mbedtls_cipher_context_t, output: *mut c_uchar, olen: *mut size_t) -> c_int;
	pub fn mbedtls_cipher_write_tag(ctx: *mut mbedtls_cipher_context_t, tag: *mut c_uchar, tag_len: size_t) -> c_int;
	pub fn mbedtls_cipher_check_tag(ctx: *mut mbedtls_cipher_context_t, tag: *const c_uchar, tag_len: size_t) -> c_int;
	pub fn mbedtls_cipher_crypt(ctx: *mut mbedtls_cipher_context_t, iv: *const c_uchar, iv_len: size_t, input: *const c_uchar, ilen: size_t, output: *mut c_uchar, olen: *mut size_t) -> c_int;
	pub fn mbedtls_cipher_auth_encrypt(ctx: *mut mbedtls_cipher_context_t, iv: *const c_uchar, iv_len: size_t, ad: *const c_uchar, ad_len: size_t, input: *const c_uchar, ilen: size_t, output: *mut c_uchar, olen: *mut size_t, tag: *mut c_uchar, tag_len: size_t) -> c_int;
	pub fn mbedtls_cipher_auth_decrypt(ctx: *mut mbedtls_cipher_context_t, iv: *const c_uchar, iv_len: size_t, ad: *const c_uchar, ad_len: size_t, input: *const c_uchar, ilen: size_t, output: *mut c_uchar, olen: *mut size_t, tag: *const c_uchar, tag_len: size_t) -> c_int;
	pub fn mbedtls_ssl_list_ciphersuites() -> *const c_int;
	pub fn mbedtls_ssl_ciphersuite_from_string(ciphersuite_name: *const c_char) -> *const mbedtls_ssl_ciphersuite_t;
	pub fn mbedtls_ssl_ciphersuite_from_id(ciphersuite_id: c_int) -> *const mbedtls_ssl_ciphersuite_t;
	pub fn mbedtls_ssl_get_ciphersuite_sig_pk_alg(info: *const mbedtls_ssl_ciphersuite_t) -> mbedtls_pk_type_t;
	pub fn mbedtls_ssl_ciphersuite_uses_ec(info: *const mbedtls_ssl_ciphersuite_t) -> c_int;
	pub fn mbedtls_ssl_ciphersuite_uses_psk(info: *const mbedtls_ssl_ciphersuite_t) -> c_int;
	pub fn mbedtls_asn1_get_len(p: *mut *mut c_uchar, end: *const c_uchar, len: *mut size_t) -> c_int;
	pub fn mbedtls_asn1_get_tag(p: *mut *mut c_uchar, end: *const c_uchar, len: *mut size_t, tag: c_int) -> c_int;
	pub fn mbedtls_asn1_get_bool(p: *mut *mut c_uchar, end: *const c_uchar, val: *mut c_int) -> c_int;
	pub fn mbedtls_asn1_get_int(p: *mut *mut c_uchar, end: *const c_uchar, val: *mut c_int) -> c_int;
	pub fn mbedtls_asn1_get_bitstring(p: *mut *mut c_uchar, end: *const c_uchar, bs: *mut mbedtls_asn1_bitstring) -> c_int;
	pub fn mbedtls_asn1_get_bitstring_null(p: *mut *mut c_uchar, end: *const c_uchar, len: *mut size_t) -> c_int;
	pub fn mbedtls_asn1_get_sequence_of(p: *mut *mut c_uchar, end: *const c_uchar, cur: *mut mbedtls_asn1_sequence, tag: c_int) -> c_int;
	pub fn mbedtls_asn1_get_mpi(p: *mut *mut c_uchar, end: *const c_uchar, X: *mut mbedtls_mpi) -> c_int;
	pub fn mbedtls_asn1_get_alg(p: *mut *mut c_uchar, end: *const c_uchar, alg: *mut mbedtls_asn1_buf, params: *mut mbedtls_asn1_buf) -> c_int;
	pub fn mbedtls_asn1_get_alg_null(p: *mut *mut c_uchar, end: *const c_uchar, alg: *mut mbedtls_asn1_buf) -> c_int;
	pub fn mbedtls_asn1_find_named_data(list: *mut mbedtls_asn1_named_data, oid: *const c_char, len: size_t) -> *mut mbedtls_asn1_named_data;
	pub fn mbedtls_asn1_free_named_data(entry: *mut mbedtls_asn1_named_data);
	pub fn mbedtls_asn1_free_named_data_list(head: *mut *mut mbedtls_asn1_named_data);
	pub fn mbedtls_x509_dn_gets(buf: *mut c_char, size: size_t, dn: *const mbedtls_x509_name) -> c_int;
	pub fn mbedtls_x509_serial_gets(buf: *mut c_char, size: size_t, serial: *const mbedtls_x509_buf) -> c_int;
	pub fn mbedtls_x509_time_is_past(time: *const mbedtls_x509_time) -> c_int;
	pub fn mbedtls_x509_time_is_future(time: *const mbedtls_x509_time) -> c_int;
	pub fn mbedtls_x509_self_test(verbose: c_int) -> c_int;
	pub fn mbedtls_x509_get_name(p: *mut *mut c_uchar, end: *const c_uchar, cur: *mut mbedtls_x509_name) -> c_int;
	pub fn mbedtls_x509_get_alg_null(p: *mut *mut c_uchar, end: *const c_uchar, alg: *mut mbedtls_x509_buf) -> c_int;
	pub fn mbedtls_x509_get_alg(p: *mut *mut c_uchar, end: *const c_uchar, alg: *mut mbedtls_x509_buf, params: *mut mbedtls_x509_buf) -> c_int;
	pub fn mbedtls_x509_get_rsassa_pss_params(params: *const mbedtls_x509_buf, md_alg: *mut mbedtls_md_type_t, mgf_md: *mut mbedtls_md_type_t, salt_len: *mut c_int) -> c_int;
	pub fn mbedtls_x509_get_sig(p: *mut *mut c_uchar, end: *const c_uchar, sig: *mut mbedtls_x509_buf) -> c_int;
	pub fn mbedtls_x509_get_sig_alg(sig_oid: *const mbedtls_x509_buf, sig_params: *const mbedtls_x509_buf, md_alg: *mut mbedtls_md_type_t, pk_alg: *mut mbedtls_pk_type_t, sig_opts: *mut *mut c_void) -> c_int;
	pub fn mbedtls_x509_get_time(p: *mut *mut c_uchar, end: *const c_uchar, time: *mut mbedtls_x509_time) -> c_int;
	pub fn mbedtls_x509_get_serial(p: *mut *mut c_uchar, end: *const c_uchar, serial: *mut mbedtls_x509_buf) -> c_int;
	pub fn mbedtls_x509_get_ext(p: *mut *mut c_uchar, end: *const c_uchar, ext: *mut mbedtls_x509_buf, tag: c_int) -> c_int;
	pub fn mbedtls_x509_sig_alg_gets(buf: *mut c_char, size: size_t, sig_oid: *const mbedtls_x509_buf, pk_alg: mbedtls_pk_type_t, md_alg: mbedtls_md_type_t, sig_opts: *const c_void) -> c_int;
	pub fn mbedtls_x509_key_size_helper(buf: *mut c_char, buf_size: size_t, name: *const c_char) -> c_int;
	pub fn mbedtls_x509_string_to_names(head: *mut *mut mbedtls_asn1_named_data, name: *const c_char) -> c_int;
	pub fn mbedtls_x509_set_extension(head: *mut *mut mbedtls_asn1_named_data, oid: *const c_char, oid_len: size_t, critical: c_int, val: *const c_uchar, val_len: size_t) -> c_int;
	pub fn mbedtls_x509_write_extensions(p: *mut *mut c_uchar, start: *mut c_uchar, first: *mut mbedtls_asn1_named_data) -> c_int;
	pub fn mbedtls_x509_write_names(p: *mut *mut c_uchar, start: *mut c_uchar, first: *mut mbedtls_asn1_named_data) -> c_int;
	pub fn mbedtls_x509_write_sig(p: *mut *mut c_uchar, start: *mut c_uchar, oid: *const c_char, oid_len: size_t, sig: *mut c_uchar, size: size_t) -> c_int;
	pub fn mbedtls_x509_crl_parse_der(chain: *mut mbedtls_x509_crl, buf: *const c_uchar, buflen: size_t) -> c_int;
	pub fn mbedtls_x509_crl_parse(chain: *mut mbedtls_x509_crl, buf: *const c_uchar, buflen: size_t) -> c_int;
	pub fn mbedtls_x509_crl_parse_file(chain: *mut mbedtls_x509_crl, path: *const c_char) -> c_int;
	pub fn mbedtls_x509_crl_info(buf: *mut c_char, size: size_t, prefix: *const c_char, crl: *const mbedtls_x509_crl) -> c_int;
	pub fn mbedtls_x509_crl_init(crl: *mut mbedtls_x509_crl);
	pub fn mbedtls_x509_crl_free(crl: *mut mbedtls_x509_crl);
	pub fn mbedtls_x509_crt_parse_der(chain: *mut mbedtls_x509_crt, buf: *const c_uchar, buflen: size_t) -> c_int;
	pub fn mbedtls_x509_crt_parse(chain: *mut mbedtls_x509_crt, buf: *const c_uchar, buflen: size_t) -> c_int;
	pub fn mbedtls_x509_crt_parse_file(chain: *mut mbedtls_x509_crt, path: *const c_char) -> c_int;
	pub fn mbedtls_x509_crt_parse_path(chain: *mut mbedtls_x509_crt, path: *const c_char) -> c_int;
	pub fn mbedtls_x509_crt_info(buf: *mut c_char, size: size_t, prefix: *const c_char, crt: *const mbedtls_x509_crt) -> c_int;
	pub fn mbedtls_x509_crt_verify_info(buf: *mut c_char, size: size_t, prefix: *const c_char, flags: uint32_t) -> c_int;
	pub fn mbedtls_x509_crt_verify(crt: *mut mbedtls_x509_crt, trust_ca: *mut mbedtls_x509_crt, ca_crl: *mut mbedtls_x509_crl, cn: *const c_char, flags: *mut uint32_t, f_vrfy: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_x509_crt, arg3: c_int, arg4: *mut uint32_t) -> c_int>, p_vrfy: *mut c_void) -> c_int;
	pub fn mbedtls_x509_crt_verify_with_profile(crt: *mut mbedtls_x509_crt, trust_ca: *mut mbedtls_x509_crt, ca_crl: *mut mbedtls_x509_crl, profile: *const mbedtls_x509_crt_profile, cn: *const c_char, flags: *mut uint32_t, f_vrfy: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_x509_crt, arg3: c_int, arg4: *mut uint32_t) -> c_int>, p_vrfy: *mut c_void) -> c_int;
	pub fn mbedtls_x509_crt_check_key_usage(crt: *const mbedtls_x509_crt, usage: c_uint) -> c_int;
	pub fn mbedtls_x509_crt_check_extended_key_usage(crt: *const mbedtls_x509_crt, usage_oid: *const c_char, usage_len: size_t) -> c_int;
	pub fn mbedtls_x509_crt_is_revoked(crt: *const mbedtls_x509_crt, crl: *const mbedtls_x509_crl) -> c_int;
	pub fn mbedtls_x509_crt_init(crt: *mut mbedtls_x509_crt);
	pub fn mbedtls_x509_crt_free(crt: *mut mbedtls_x509_crt);
	pub fn mbedtls_x509write_crt_init(ctx: *mut mbedtls_x509write_cert);
	pub fn mbedtls_x509write_crt_set_version(ctx: *mut mbedtls_x509write_cert, version: c_int);
	pub fn mbedtls_x509write_crt_set_serial(ctx: *mut mbedtls_x509write_cert, serial: *const mbedtls_mpi) -> c_int;
	pub fn mbedtls_x509write_crt_set_validity(ctx: *mut mbedtls_x509write_cert, not_before: *const c_char, not_after: *const c_char) -> c_int;
	pub fn mbedtls_x509write_crt_set_issuer_name(ctx: *mut mbedtls_x509write_cert, issuer_name: *const c_char) -> c_int;
	pub fn mbedtls_x509write_crt_set_subject_name(ctx: *mut mbedtls_x509write_cert, subject_name: *const c_char) -> c_int;
	pub fn mbedtls_x509write_crt_set_subject_key(ctx: *mut mbedtls_x509write_cert, key: *mut mbedtls_pk_context);
	pub fn mbedtls_x509write_crt_set_issuer_key(ctx: *mut mbedtls_x509write_cert, key: *mut mbedtls_pk_context);
	pub fn mbedtls_x509write_crt_set_md_alg(ctx: *mut mbedtls_x509write_cert, md_alg: mbedtls_md_type_t);
	pub fn mbedtls_x509write_crt_set_extension(ctx: *mut mbedtls_x509write_cert, oid: *const c_char, oid_len: size_t, critical: c_int, val: *const c_uchar, val_len: size_t) -> c_int;
	pub fn mbedtls_x509write_crt_set_basic_constraints(ctx: *mut mbedtls_x509write_cert, is_ca: c_int, max_pathlen: c_int) -> c_int;
	pub fn mbedtls_x509write_crt_set_subject_key_identifier(ctx: *mut mbedtls_x509write_cert) -> c_int;
	pub fn mbedtls_x509write_crt_set_authority_key_identifier(ctx: *mut mbedtls_x509write_cert) -> c_int;
	pub fn mbedtls_x509write_crt_set_key_usage(ctx: *mut mbedtls_x509write_cert, key_usage: c_uint) -> c_int;
	pub fn mbedtls_x509write_crt_set_ns_cert_type(ctx: *mut mbedtls_x509write_cert, ns_cert_type: c_uchar) -> c_int;
	pub fn mbedtls_x509write_crt_free(ctx: *mut mbedtls_x509write_cert);
	pub fn mbedtls_x509write_crt_der(ctx: *mut mbedtls_x509write_cert, buf: *mut c_uchar, size: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_x509write_crt_pem(ctx: *mut mbedtls_x509write_cert, buf: *mut c_uchar, size: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_dhm_init(ctx: *mut mbedtls_dhm_context);
	pub fn mbedtls_dhm_read_params(ctx: *mut mbedtls_dhm_context, p: *mut *mut c_uchar, end: *const c_uchar) -> c_int;
	pub fn mbedtls_dhm_make_params(ctx: *mut mbedtls_dhm_context, x_size: c_int, output: *mut c_uchar, olen: *mut size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_dhm_read_public(ctx: *mut mbedtls_dhm_context, input: *const c_uchar, ilen: size_t) -> c_int;
	pub fn mbedtls_dhm_make_public(ctx: *mut mbedtls_dhm_context, x_size: c_int, output: *mut c_uchar, olen: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_dhm_calc_secret(ctx: *mut mbedtls_dhm_context, output: *mut c_uchar, output_size: size_t, olen: *mut size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_dhm_free(ctx: *mut mbedtls_dhm_context);
	pub fn mbedtls_dhm_parse_dhm(dhm: *mut mbedtls_dhm_context, dhmin: *const c_uchar, dhminlen: size_t) -> c_int;
	pub fn mbedtls_dhm_parse_dhmfile(dhm: *mut mbedtls_dhm_context, path: *const c_char) -> c_int;
	pub fn mbedtls_dhm_self_test(verbose: c_int) -> c_int;
	pub fn mbedtls_ecdh_gen_public(grp: *mut mbedtls_ecp_group, d: *mut mbedtls_mpi, Q: *mut mbedtls_ecp_point, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecdh_compute_shared(grp: *mut mbedtls_ecp_group, z: *mut mbedtls_mpi, Q: *const mbedtls_ecp_point, d: *const mbedtls_mpi, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecdh_init(ctx: *mut mbedtls_ecdh_context);
	pub fn mbedtls_ecdh_free(ctx: *mut mbedtls_ecdh_context);
	pub fn mbedtls_ecdh_make_params(ctx: *mut mbedtls_ecdh_context, olen: *mut size_t, buf: *mut c_uchar, blen: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecdh_read_params(ctx: *mut mbedtls_ecdh_context, buf: *mut *const c_uchar, end: *const c_uchar) -> c_int;
	pub fn mbedtls_ecdh_get_params(ctx: *mut mbedtls_ecdh_context, key: *const mbedtls_ecp_keypair, side: mbedtls_ecdh_side) -> c_int;
	pub fn mbedtls_ecdh_make_public(ctx: *mut mbedtls_ecdh_context, olen: *mut size_t, buf: *mut c_uchar, blen: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ecdh_read_public(ctx: *mut mbedtls_ecdh_context, buf: *const c_uchar, blen: size_t) -> c_int;
	pub fn mbedtls_ecdh_calc_secret(ctx: *mut mbedtls_ecdh_context, olen: *mut size_t, buf: *mut c_uchar, blen: size_t, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void) -> c_int;
	pub fn mbedtls_ssl_get_ciphersuite_name(ciphersuite_id: c_int) -> *const c_char;
	pub fn mbedtls_ssl_get_ciphersuite_id(ciphersuite_name: *const c_char) -> c_int;
	pub fn mbedtls_ssl_init(ssl: *mut mbedtls_ssl_context);
	pub fn mbedtls_ssl_setup(ssl: *mut mbedtls_ssl_context, conf: *const mbedtls_ssl_config) -> c_int;
	pub fn mbedtls_ssl_session_reset(ssl: *mut mbedtls_ssl_context) -> c_int;
	pub fn mbedtls_ssl_conf_endpoint(conf: *mut mbedtls_ssl_config, endpoint: c_int);
	pub fn mbedtls_ssl_conf_transport(conf: *mut mbedtls_ssl_config, transport: c_int);
	pub fn mbedtls_ssl_conf_authmode(conf: *mut mbedtls_ssl_config, authmode: c_int);
	pub fn mbedtls_ssl_conf_verify(conf: *mut mbedtls_ssl_config, f_vrfy: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_x509_crt, arg3: c_int, arg4: *mut uint32_t) -> c_int>, p_vrfy: *mut c_void);
	pub fn mbedtls_ssl_conf_rng(conf: *mut mbedtls_ssl_config, f_rng: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut c_uchar, arg3: size_t) -> c_int>, p_rng: *mut c_void);
	pub fn mbedtls_ssl_conf_dbg(conf: *mut mbedtls_ssl_config, f_dbg: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: c_int, arg3: *const c_char, arg4: c_int, arg5: *const c_char)>, p_dbg: *mut c_void);
	pub fn mbedtls_ssl_set_bio(ssl: *mut mbedtls_ssl_context, p_bio: *mut c_void, f_send: mbedtls_ssl_send_t, f_recv: mbedtls_ssl_recv_t, f_recv_timeout: mbedtls_ssl_recv_timeout_t);
	pub fn mbedtls_ssl_conf_read_timeout(conf: *mut mbedtls_ssl_config, timeout: uint32_t);
	pub fn mbedtls_ssl_set_timer_cb(ssl: *mut mbedtls_ssl_context, p_timer: *mut c_void, f_set_timer: mbedtls_ssl_set_timer_t, f_get_timer: mbedtls_ssl_get_timer_t);
	pub fn mbedtls_ssl_conf_session_tickets_cb(conf: *mut mbedtls_ssl_config, f_ticket_write: mbedtls_ssl_ticket_write_t, f_ticket_parse: mbedtls_ssl_ticket_parse_t, p_ticket: *mut c_void);
	pub fn mbedtls_ssl_conf_dtls_cookies(conf: *mut mbedtls_ssl_config, f_cookie_write: mbedtls_ssl_cookie_write_t, f_cookie_check: mbedtls_ssl_cookie_check_t, p_cookie: *mut c_void);
	pub fn mbedtls_ssl_set_client_transport_id(ssl: *mut mbedtls_ssl_context, info: *const c_uchar, ilen: size_t) -> c_int;
	pub fn mbedtls_ssl_conf_dtls_anti_replay(conf: *mut mbedtls_ssl_config, mode: c_char);
	pub fn mbedtls_ssl_conf_dtls_badmac_limit(conf: *mut mbedtls_ssl_config, limit: c_uint);
	pub fn mbedtls_ssl_conf_handshake_timeout(conf: *mut mbedtls_ssl_config, min: uint32_t, max: uint32_t);
	pub fn mbedtls_ssl_conf_session_cache(conf: *mut mbedtls_ssl_config, p_cache: *mut c_void, f_get_cache: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_ssl_session) -> c_int>, f_set_cache: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *const mbedtls_ssl_session) -> c_int>);
	pub fn mbedtls_ssl_set_session(ssl: *mut mbedtls_ssl_context, session: *const mbedtls_ssl_session) -> c_int;
	pub fn mbedtls_ssl_conf_ciphersuites(conf: *mut mbedtls_ssl_config, ciphersuites: *const c_int);
	pub fn mbedtls_ssl_conf_ciphersuites_for_version(conf: *mut mbedtls_ssl_config, ciphersuites: *const c_int, major: c_int, minor: c_int);
	pub fn mbedtls_ssl_conf_cert_profile(conf: *mut mbedtls_ssl_config, profile: *const mbedtls_x509_crt_profile);
	pub fn mbedtls_ssl_conf_ca_chain(conf: *mut mbedtls_ssl_config, ca_chain: *mut mbedtls_x509_crt, ca_crl: *mut mbedtls_x509_crl);
	pub fn mbedtls_ssl_conf_own_cert(conf: *mut mbedtls_ssl_config, own_cert: *mut mbedtls_x509_crt, pk_key: *mut mbedtls_pk_context) -> c_int;
	pub fn mbedtls_ssl_conf_psk(conf: *mut mbedtls_ssl_config, psk: *const c_uchar, psk_len: size_t, psk_identity: *const c_uchar, psk_identity_len: size_t) -> c_int;
	pub fn mbedtls_ssl_set_hs_psk(ssl: *mut mbedtls_ssl_context, psk: *const c_uchar, psk_len: size_t) -> c_int;
	pub fn mbedtls_ssl_conf_psk_cb(conf: *mut mbedtls_ssl_config, f_psk: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_ssl_context, arg3: *const c_uchar, arg4: size_t) -> c_int>, p_psk: *mut c_void);
	pub fn mbedtls_ssl_conf_dh_param(conf: *mut mbedtls_ssl_config, dhm_P: *const c_char, dhm_G: *const c_char) -> c_int;
	pub fn mbedtls_ssl_conf_dh_param_ctx(conf: *mut mbedtls_ssl_config, dhm_ctx: *mut mbedtls_dhm_context) -> c_int;
	pub fn mbedtls_ssl_conf_dhm_min_bitlen(conf: *mut mbedtls_ssl_config, bitlen: c_uint);
	pub fn mbedtls_ssl_conf_curves(conf: *mut mbedtls_ssl_config, curves: *const mbedtls_ecp_group_id);
	pub fn mbedtls_ssl_conf_sig_hashes(conf: *mut mbedtls_ssl_config, hashes: *const c_int);
	pub fn mbedtls_ssl_set_hostname(ssl: *mut mbedtls_ssl_context, hostname: *const c_char) -> c_int;
	pub fn mbedtls_ssl_set_hs_own_cert(ssl: *mut mbedtls_ssl_context, own_cert: *mut mbedtls_x509_crt, pk_key: *mut mbedtls_pk_context) -> c_int;
	pub fn mbedtls_ssl_set_hs_ca_chain(ssl: *mut mbedtls_ssl_context, ca_chain: *mut mbedtls_x509_crt, ca_crl: *mut mbedtls_x509_crl);
	pub fn mbedtls_ssl_set_hs_authmode(ssl: *mut mbedtls_ssl_context, authmode: c_int);
	pub fn mbedtls_ssl_conf_sni(conf: *mut mbedtls_ssl_config, f_sni: Option<unsafe extern "C" fn(arg1: *mut c_void, arg2: *mut mbedtls_ssl_context, arg3: *const c_uchar, arg4: size_t) -> c_int>, p_sni: *mut c_void);
	pub fn mbedtls_ssl_conf_alpn_protocols(conf: *mut mbedtls_ssl_config, protos: *mut *const c_char) -> c_int;
	pub fn mbedtls_ssl_get_alpn_protocol(ssl: *const mbedtls_ssl_context) -> *const c_char;
	pub fn mbedtls_ssl_conf_max_version(conf: *mut mbedtls_ssl_config, major: c_int, minor: c_int);
	pub fn mbedtls_ssl_conf_min_version(conf: *mut mbedtls_ssl_config, major: c_int, minor: c_int);
	pub fn mbedtls_ssl_conf_encrypt_then_mac(conf: *mut mbedtls_ssl_config, etm: c_char);
	pub fn mbedtls_ssl_conf_extended_master_secret(conf: *mut mbedtls_ssl_config, ems: c_char);
	pub fn mbedtls_ssl_conf_max_frag_len(conf: *mut mbedtls_ssl_config, mfl_code: c_uchar) -> c_int;
	pub fn mbedtls_ssl_conf_session_tickets(conf: *mut mbedtls_ssl_config, use_tickets: c_int);
	pub fn mbedtls_ssl_conf_legacy_renegotiation(conf: *mut mbedtls_ssl_config, allow_legacy: c_int);
	pub fn mbedtls_ssl_get_bytes_avail(ssl: *const mbedtls_ssl_context) -> size_t;
	pub fn mbedtls_ssl_get_verify_result(ssl: *const mbedtls_ssl_context) -> uint32_t;
	pub fn mbedtls_ssl_get_ciphersuite(ssl: *const mbedtls_ssl_context) -> *const c_char;
	pub fn mbedtls_ssl_get_version(ssl: *const mbedtls_ssl_context) -> *const c_char;
	pub fn mbedtls_ssl_get_record_expansion(ssl: *const mbedtls_ssl_context) -> c_int;
	pub fn mbedtls_ssl_get_max_frag_len(ssl: *const mbedtls_ssl_context) -> size_t;
	pub fn mbedtls_ssl_get_peer_cert(ssl: *const mbedtls_ssl_context) -> *const mbedtls_x509_crt;
	pub fn mbedtls_ssl_get_session(ssl: *const mbedtls_ssl_context, session: *mut mbedtls_ssl_session) -> c_int;
	pub fn mbedtls_ssl_handshake(ssl: *mut mbedtls_ssl_context) -> c_int;
	pub fn mbedtls_ssl_handshake_step(ssl: *mut mbedtls_ssl_context) -> c_int;
	pub fn mbedtls_ssl_read(ssl: *mut mbedtls_ssl_context, buf: *mut c_uchar, len: size_t) -> c_int;
	pub fn mbedtls_ssl_write(ssl: *mut mbedtls_ssl_context, buf: *const c_uchar, len: size_t) -> c_int;
	pub fn mbedtls_ssl_send_alert_message(ssl: *mut mbedtls_ssl_context, level: c_uchar, message: c_uchar) -> c_int;
	pub fn mbedtls_ssl_close_notify(ssl: *mut mbedtls_ssl_context) -> c_int;
	pub fn mbedtls_ssl_free(ssl: *mut mbedtls_ssl_context);
	pub fn mbedtls_ssl_config_init(conf: *mut mbedtls_ssl_config);
	pub fn mbedtls_ssl_config_defaults(conf: *mut mbedtls_ssl_config, endpoint: c_int, transport: c_int, preset: c_int) -> c_int;
	pub fn mbedtls_ssl_config_free(conf: *mut mbedtls_ssl_config);
	pub fn mbedtls_ssl_session_init(session: *mut mbedtls_ssl_session);
	pub fn mbedtls_ssl_session_free(session: *mut mbedtls_ssl_session);
}

