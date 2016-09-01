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
