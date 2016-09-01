# This file is part of mbedtls-sys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls-sys/master/COPYRIGHT. No part of mbedtls-sys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
# Copyright © 2016 The developers of mbedtls-sys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls-sys/master/COPYRIGHT.


bindingsName='mbedtls'
rootIncludeFileName='ssl.h'
macosXHomebrewPackageName='mbedtls'
alpineLinuxPackageName='mbedtls-dev'


postprocess_after_generation()
{
	generate_binding_addTacFallbackIfNotPresent
	
	local newline='\'$'\n'
	
	# First sed
	# 1 - make u128 only exist on 64-bit unix platforms
	# 2 - adjust mbedtls_t_udbl so that it is correctly sized on Windows and 32-bit unix (note that it is uint64_t even on 64-bit Windows)
	# Second sed lines explanation - remove lines BEFORE expression:-
	# 1 - remove #[derive(Debug)] from pub struct mbedtls_threading_mutex_t, as it contains a field of type pthread_mutex_t on Unix, which is opaque (via previous line sed expression)
	# 2 - remove #[derive(Debug)] from pub struct mbedtls_rsa_context, as it contains a field of type mbedtls_threading_mutex_t (via previous line sed expression)\
	# Third sed lines explanation - remove lines BEFORE expression:-
	# 1 - add #[allow(missing_debug_implementations)] instead for pub struct mbedtls_threading_mutex_t
	# 2 - add #[allow(missing_debug_implementations)] instead for pub struct mbedtls_rsa_context
	# 3 - add #[allow(missing_debug_implementations)] as contains a fixed-size array for pub struct mbedtls_ssl_premaster_secret
	# 4 - add #[allow(missing_debug_implementations)] as contains a fixed-size array for pub struct mbedtls_ssl_session
	
	sed \
		-e 's/^pub struct u128/#[cfg(all(unix, target_pointer_width = "64"))]'"$newline"'pub struct u128/g' \
		-e 's/^pub type mbedtls_t_udbl = u128;$/#[cfg(windows)] pub type mbedtls_t_udbl = uint64_t;'"$newline"'#[cfg(all(unix, target_pointer_width = "64"))] pub type mbedtls_t_udbl = u128;'"$newline"'#[cfg(all(unix, target_pointer_width = "32"))] pub type mbedtls_t_udbl = uint64_t;/g' \
	| \
	tac \
	| \
		sed \
			-e '/pub struct mbedtls_threading_mutex_t {/{n; d;}' \
			-e '/pub struct mbedtls_rsa_context {/{n; d;}' \
			| \
		sed \
			-e 's/pub struct mbedtls_threading_mutex_t {/pub struct mbedtls_threading_mutex_t {'"$newline"'#[allow(missing_debug_implementations)]/g' \
			-e 's/pub struct mbedtls_rsa_context {/pub struct mbedtls_rsa_context {'"$newline"'#[allow(missing_debug_implementations)]/g' \
			-e 's/pub struct mbedtls_ssl_premaster_secret {/pub struct mbedtls_ssl_premaster_secret {'"$newline"'#[allow(missing_debug_implementations)]/g' \
			-e 's/pub struct mbedtls_ssl_session {/pub struct mbedtls_ssl_session {'"$newline"'#[allow(missing_debug_implementations)]/g' \
	| \
	tac
}

postprocess_after_rustfmt()
{
	local newline='\'$'\n'
	
	# Sed line explanations
	# 1 - space out better
	# 2 - Make MBEDTLS_SSL_ANTI_REPLAY_DISABLED & MBEDTLS_SSL_ANTI_REPLAY_ENABLED c_char
	sed \
		-e 's/pub const MBEDTLS_SSL_CHANNEL_INBOUND: c_uchar = 1;/pub const MBEDTLS_SSL_CHANNEL_INBOUND: c_uchar = 1;'"$newline"'/g' \
		-e 's/MBEDTLS_SSL_ANTI_REPLAY_DISABLED: c_int/MBEDTLS_SSL_ANTI_REPLAY_DISABLED: c_char/g' -e 's/MBEDTLS_SSL_ANTI_REPLAY_ENABLED: c_int/MBEDTLS_SSL_ANTI_REPLAY_ENABLED: c_char/g'
}
