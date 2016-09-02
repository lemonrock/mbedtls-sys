[](This file is part of mbedtls-sys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls-sys/master/COPYRIGHT. No part of mbedtls-sys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.)
[](Copyright © 2016 The developers of mbedtls-sys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls-sys/master/COPYRIGHT.)

# mbedtls-sys

[![Clippy Linting Result](https://clippy.bashy.io/github/lemonrock/mbedtls-sys/master/badge.svg?style=plastic)](https://clippy.bashy.io/github/lemonrock/mbedtls-sys/master/log) [![](https://img.shields.io/badge/Code%20Style-rustfmt-brightgreen.svg?style=plastic)](https://github.com/rust-lang-nursery/rustfmt#configuring-rustfmt)

[mbedtls-sys] is a rust crate that has bindings to the [mbedtls] C library. It currently generates them for version 2.3.0.


## Licensing

The license for this project is MIT.


## Recompilation

To recompile, use `./bindgen-wrapper`. This only works on Mac OS X, and you will need Homebrew installed (as `brew`). It assumes `brew` and `cargo` are in your path, and will install `bindgen` and `rustfmt` as needed. We don't use the `bindgen` plugin as we have to munge the output from bindgen extensively.

## Extras

* Generating Mac OS X Developer docsets suitable for [dash] for [mbedtls] is supported. Just run `tools/generate-dash-docset`. The generated docset will be ` ~/Library/Developer/Shared/Documentation/DocSets/com.kapeli.dash.mbedtls.docset`. This may not be visible in [dash]'s file chooser.

## Known Issues

* At this time, the wrapper will not compile on Windows due to the use of `pthread_mutex_t`. This is probably fixable.
* [mbedtls] has extensive compile-time configuration options, and it's quite possible that a function we define isn't compiled in. The `config.h` we used is in `bindgen/include-fixes/config.h`


[mbedtls-sys]: https://github.com/lemonrock/mbedtls-sys "mbedtls-sys GitHub page"
[mbedtls]: https://tls.mbed.org/ "mbedtls home page"
