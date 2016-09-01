# bindgen-wrapper

This small git module makes it easier to generate FFI bindings for rust using [bindgen]. is intended to be used as a git submodule inside a `-sys` module, to make it easier to work with [bindgen] on Mac OS X and with more complex FFI wrappers. It installs all required dependencies using `cargo`, and, on Mac OS X, `brew` (Homebrew), except for Rust, `cargo` and `brew` itself.

It checks for any essential dependencies by looking in the `PATH`; a standard Mac OS X `PATH` with an additional to find binaries installed by cargo should be sufficient.

As an example, check out [mbedtls-sys] on GitHub.

## Installation

At the terminal, do the following:-

```bash
# my-crate-repo should already contain a `.git` folder or file
cd my-crate-repo

mkdir -m 0755 -p tools
git submodule add https://github.com/lemonrock/bindgen-wrapper.git tools/bindgen-wrapper
git submodule update --init --recursive
ln -s tools/bindgen-wrapper/generate-bindings

cd -
```

## Configuration

To use `bindgen-wrapper` we need to create some files.

At the terminal, do the following:-
```bash
# my-crate-repo should already contain a `.git` folder or file
cd my-crate-repo

mkdir -m 0755 bindgen-wrapper.conf.d

# Place any header (*.h) files in here that add to or replace ones shipped by your library
mkdir -m 0755 bindgen-wrapper.conf.d/header-overrides

# Rust code snippet prepended to bindgen output. Add crate-level attributes, copyright statements, etc, here
touch bindgen-wrapper.conf.d/preamble.rs

# Rust code snippet interjected between `use` statements and remainder of generated code. Place additional `use` statements here,
# #[link] extern crate "C" {} statements, etc
touch bindgen-wrapper.conf.d/extra-includes.rs

# General configuation (does not need to executable)
touch bindgen-wrapper.conf.d/configuration.sh
```

See [mbedtls-sys] for an example of `configuration.sh`. As a minimum, you should define `bindingsName`, `rootIncludeFileName`, `macosXHomebrewPackageName` and `alpineLinuxPackageName` (if known). The functions `postprocess_after_generation` and `postprocess_after_rustfmt` default to empty. The statement `generate_binding_addTacFallbackIfNotPresent` is only necessary if either `postprocess_after_generation` or `postprocess_after_rustfmt` need to use the `tac` binary.

## Extras

* On Mac OS X, a shell function compatible version of `tac` is available inside your `configuration.sh`. Do `generate_binding_addTacFallbackIfNotPresent` outside of any function. See [mbedtls-sys] for an example.
* On Mac OS X, `bindgen-macosx` can be used standalone instead of `bindgen`; it sets paths correctly for use with `brew`. However, you'll have to pass `-- -U__BLOCKS__` (an option to clang) to get it to work on El Capitan if any of the header files you use in generation have `#include <stdlib.h>` in them (directly or indirectly via their includes).


## Known Issues

* This wrapper is untested on anything but Mac OS X El Capitan, but with modification, should work on Alpine Linux, Debian-derivatives and Red Hat derivatives
* `sed` is somewhat broken on Mac OS X, and we try to work around it.
* On Mac OS X, if you already installed `llvm` with `brew` make sure you have installed it as `brew install --shared-`


[mbedtls-sys]: https://github.com/lemonrock/mbedtls-sys "mbedtls-sys GitHub page"
[mbedtls]: https://tls.mbed.org/ "mbedtls home page"