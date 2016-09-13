// This file is part of mbedtls-sys. It is subject to the license terms in the COPYRIGHT file found in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls-sys/master/COPYRIGHT. No part of mbedtls-sys, including this file, may be copied, modified, propagated, or distributed except according to the terms contained in the COPYRIGHT file.
// Copyright © 2016 The developers of mbedtls-sys. See the COPYRIGHT file in the top-level directory of this distribution and at https://raw.githubusercontent.com/lemonrock/mbedtls-sys/master/COPYRIGHT.


pub struct mbedtls_aes_context
{
	nr: i32;
	rk: * mut u32;
	buf[68]: u32;
}

pub enum AesKeyBitStrength
{
	_128,
	_192,
	_256,
}

impl 

impl mbedtls_aes_context
{
	pub fn mbedtls_aes_setkey_enc(&mut self, const u8 * key, keybits: u32) -> i32
	{
		let i: u32;
		let RK: &mut u32;
		
		if aes_init_done == 0
		{
			aes_gen_tables();
			aes_init_done = 1;
		}
		
		switch (keybits)
		{
			case 128:
			ctx.nr = 10;
			break;

			case 192:
			ctx.nr = 12;
			break;

			case 256:
			ctx.nr = 14;
			break;

		default:
			return -0x0020;
		}
		ctx.rk = RK = ctx.buf;
		if mbedtls_aesni_has_support(0x02000000u)
		{
			return mbedtls_aesni_setkey_enc((u8 *) ctx.rk, key, keybits);
		}
		for (i = 0; i < (keybits >> 5); i++)
		{
			GET_UINT32_LE(RK[i], key, i << 2);
		}
		switch (ctx.nr)
		{
			case 10:
			for (i = 0; i < 10; i++, RK += 4)
			{
				RK[4] = RK[0] ^ RCON[i] ^ ((u32) FSb[(RK[3] >> 8) & 0xFF]) ^ ((u32) FSb[(RK[3] >> 16) & 0xFF] << 8) ^ ((u32) FSb[(RK[3] >> 24) & 0xFF] << 16) ^ ((u32) FSb[(RK[3]) & 0xFF] << 24);
				RK[5] = RK[1] ^ RK[4];
				RK[6] = RK[2] ^ RK[5];
				RK[7] = RK[3] ^ RK[6];
			}
			break;

			case 12:
			for (i = 0; i < 8; i++, RK += 6)
			{
				RK[6] = RK[0] ^ RCON[i] ^ ((u32) FSb[(RK[5] >> 8) & 0xFF]) ^ ((u32) FSb[(RK[5] >> 16) & 0xFF] << 8) ^ ((u32) FSb[(RK[5] >> 24) & 0xFF] << 16) ^ ((u32) FSb[(RK[5]) & 0xFF] << 24);
				RK[7] = RK[1] ^ RK[6];
				RK[8] = RK[2] ^ RK[7];
				RK[9] = RK[3] ^ RK[8];
				RK[10] = RK[4] ^ RK[9];
				RK[11] = RK[5] ^ RK[10];
			}
			break;

			case 14:
			for (i = 0; i < 7; i++, RK += 8)
			{
				RK[8] = RK[0] ^ RCON[i] ^ ((u32) FSb[(RK[7] >> 8) & 0xFF]) ^ ((u32) FSb[(RK[7] >> 16) & 0xFF] << 8) ^ ((u32) FSb[(RK[7] >> 24) & 0xFF] << 16) ^ ((u32) FSb[(RK[7]) & 0xFF] << 24);
				RK[9] = RK[1] ^ RK[8];
				RK[10] = RK[2] ^ RK[9];
				RK[11] = RK[3] ^ RK[10];
				RK[12] = RK[4] ^ ((u32) FSb[(RK[11]) & 0xFF]) ^ ((u32) FSb[(RK[11] >> 8) & 0xFF] << 8) ^ ((u32) FSb[(RK[11] >> 16) & 0xFF] << 16) ^ ((u32) FSb[(RK[11] >> 24) & 0xFF] << 24);
				RK[13] = RK[5] ^ RK[12];
				RK[14] = RK[6] ^ RK[13];
				RK[15] = RK[7] ^ RK[14];
			}
			break;

		}
		return 0;
	}

	pub fn mbedtls_aes_setkey_dec(&mut self, const u8 * key, u32 keybits) -> i32
	{
		i32 i, j, ret;
		mbedtls_aes_context cty;
		u32 * RK;
		u32 * SK;
		mbedtls_aes_init(&cty);
		ctx.rk = RK = ctx.buf;
		if (ret = mbedtls_aes_setkey_enc(&cty, key, keybits)) != 0
		{
			goto exit;
		}
		ctx.nr = cty.nr;
		if mbedtls_aesni_has_support(0x02000000u)
		{
			mbedtls_aesni_inverse_key((u8 *) ctx.rk, (const u8 *) cty.rk, ctx.nr);
			goto exit;
		}
		SK = cty.rk + cty.nr * 4;
		*RK++ = *SK++;
		*RK++ = *SK++;
		*RK++ = *SK++;
		*RK++ = *SK++;
		for (i = ctx.nr - 1, SK -= 8; i > 0; i--, SK -= 8)
		{
			for (j = 0; j < 4; j++, SK++)
			{
				*RK++ = RT0[FSb[(*SK) & 0xFF]] ^ RT1[FSb[(*SK >> 8) & 0xFF]] ^ RT2[FSb[(*SK >> 16) & 0xFF]] ^ RT3[FSb[(*SK >> 24) & 0xFF]];
			}
		}
		*RK++ = *SK++;
		*RK++ = *SK++;
		*RK++ = *SK++;
		*RK++ = *SK++;
	exit:
		mbedtls_aes_free(&cty);
		return ret;
	}

	pub fn mbedtls_aes_encrypt(&mut self, const u8 input[16], u8 output[16])
	{
		i32 i;
		u32 *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;
		RK = ctx.rk;
		GET_UINT32_LE(X0, input, 0);
		X0 ^= *RK++;
		GET_UINT32_LE(X1, input, 4);
		X1 ^= *RK++;
		GET_UINT32_LE(X2, input, 8);
		X2 ^= *RK++;
		GET_UINT32_LE(X3, input, 12);
		X3 ^= *RK++;
		for (i = (ctx.nr >> 1) - 1; i > 0; i--)
		{
			{
				Y0 = *RK++ ^ FT0[(X0) &0xFF] ^ FT1[(X1 >> 8) & 0xFF] ^ FT2[(X2 >> 16) & 0xFF] ^ FT3[(X3 >> 24) & 0xFF];
				Y1 = *RK++ ^ FT0[(X1) &0xFF] ^ FT1[(X2 >> 8) & 0xFF] ^ FT2[(X3 >> 16) & 0xFF] ^ FT3[(X0 >> 24) & 0xFF];
				Y2 = *RK++ ^ FT0[(X2) &0xFF] ^ FT1[(X3 >> 8) & 0xFF] ^ FT2[(X0 >> 16) & 0xFF] ^ FT3[(X1 >> 24) & 0xFF];
				Y3 = *RK++ ^ FT0[(X3) &0xFF] ^ FT1[(X0 >> 8) & 0xFF] ^ FT2[(X1 >> 16) & 0xFF] ^ FT3[(X2 >> 24) & 0xFF];
			};
			{
				X0 = *RK++ ^ FT0[(Y0) &0xFF] ^ FT1[(Y1 >> 8) & 0xFF] ^ FT2[(Y2 >> 16) & 0xFF] ^ FT3[(Y3 >> 24) & 0xFF];
				X1 = *RK++ ^ FT0[(Y1) &0xFF] ^ FT1[(Y2 >> 8) & 0xFF] ^ FT2[(Y3 >> 16) & 0xFF] ^ FT3[(Y0 >> 24) & 0xFF];
				X2 = *RK++ ^ FT0[(Y2) &0xFF] ^ FT1[(Y3 >> 8) & 0xFF] ^ FT2[(Y0 >> 16) & 0xFF] ^ FT3[(Y1 >> 24) & 0xFF];
				X3 = *RK++ ^ FT0[(Y3) &0xFF] ^ FT1[(Y0 >> 8) & 0xFF] ^ FT2[(Y1 >> 16) & 0xFF] ^ FT3[(Y2 >> 24) & 0xFF];
			};
		}
		{
			Y0 = *RK++ ^ FT0[(X0) &0xFF] ^ FT1[(X1 >> 8) & 0xFF] ^ FT2[(X2 >> 16) & 0xFF] ^ FT3[(X3 >> 24) & 0xFF];
			Y1 = *RK++ ^ FT0[(X1) &0xFF] ^ FT1[(X2 >> 8) & 0xFF] ^ FT2[(X3 >> 16) & 0xFF] ^ FT3[(X0 >> 24) & 0xFF];
			Y2 = *RK++ ^ FT0[(X2) &0xFF] ^ FT1[(X3 >> 8) & 0xFF] ^ FT2[(X0 >> 16) & 0xFF] ^ FT3[(X1 >> 24) & 0xFF];
			Y3 = *RK++ ^ FT0[(X3) &0xFF] ^ FT1[(X0 >> 8) & 0xFF] ^ FT2[(X1 >> 16) & 0xFF] ^ FT3[(X2 >> 24) & 0xFF];
		};
		X0 = *RK++ ^ ((u32) FSb[(Y0) &0xFF]) ^ ((u32) FSb[(Y1 >> 8) & 0xFF] << 8) ^ ((u32) FSb[(Y2 >> 16) & 0xFF] << 16) ^ ((u32) FSb[(Y3 >> 24) & 0xFF] << 24);
		X1 = *RK++ ^ ((u32) FSb[(Y1) &0xFF]) ^ ((u32) FSb[(Y2 >> 8) & 0xFF] << 8) ^ ((u32) FSb[(Y3 >> 16) & 0xFF] << 16) ^ ((u32) FSb[(Y0 >> 24) & 0xFF] << 24);
		X2 = *RK++ ^ ((u32) FSb[(Y2) &0xFF]) ^ ((u32) FSb[(Y3 >> 8) & 0xFF] << 8) ^ ((u32) FSb[(Y0 >> 16) & 0xFF] << 16) ^ ((u32) FSb[(Y1 >> 24) & 0xFF] << 24);
		X3 = *RK++ ^ ((u32) FSb[(Y3) &0xFF]) ^ ((u32) FSb[(Y0 >> 8) & 0xFF] << 8) ^ ((u32) FSb[(Y1 >> 16) & 0xFF] << 16) ^ ((u32) FSb[(Y2 >> 24) & 0xFF] << 24);
		PUT_UINT32_LE(X0, output, 0);
		PUT_UINT32_LE(X1, output, 4);
		PUT_UINT32_LE(X2, output, 8);
		PUT_UINT32_LE(X3, output, 12);
	}

	pub fn mbedtls_aes_decrypt(&mut self, const u8 input[16], u8 output[16])
	{
		i32 i;
		u32 *RK, X0, X1, X2, X3, Y0, Y1, Y2, Y3;
		RK = ctx.rk;
		GET_UINT32_LE(X0, input, 0);
		X0 ^= *RK++;
		GET_UINT32_LE(X1, input, 4);
		X1 ^= *RK++;
		GET_UINT32_LE(X2, input, 8);
		X2 ^= *RK++;
		GET_UINT32_LE(X3, input, 12);
		X3 ^= *RK++;
		for (i = (ctx.nr >> 1) - 1; i > 0; i--)
		{
			{
				Y0 = *RK++ ^ RT0[(X0) &0xFF] ^ RT1[(X3 >> 8) & 0xFF] ^ RT2[(X2 >> 16) & 0xFF] ^ RT3[(X1 >> 24) & 0xFF];
				Y1 = *RK++ ^ RT0[(X1) &0xFF] ^ RT1[(X0 >> 8) & 0xFF] ^ RT2[(X3 >> 16) & 0xFF] ^ RT3[(X2 >> 24) & 0xFF];
				Y2 = *RK++ ^ RT0[(X2) &0xFF] ^ RT1[(X1 >> 8) & 0xFF] ^ RT2[(X0 >> 16) & 0xFF] ^ RT3[(X3 >> 24) & 0xFF];
				Y3 = *RK++ ^ RT0[(X3) &0xFF] ^ RT1[(X2 >> 8) & 0xFF] ^ RT2[(X1 >> 16) & 0xFF] ^ RT3[(X0 >> 24) & 0xFF];
			};
			{
				X0 = *RK++ ^ RT0[(Y0) &0xFF] ^ RT1[(Y3 >> 8) & 0xFF] ^ RT2[(Y2 >> 16) & 0xFF] ^ RT3[(Y1 >> 24) & 0xFF];
				X1 = *RK++ ^ RT0[(Y1) &0xFF] ^ RT1[(Y0 >> 8) & 0xFF] ^ RT2[(Y3 >> 16) & 0xFF] ^ RT3[(Y2 >> 24) & 0xFF];
				X2 = *RK++ ^ RT0[(Y2) &0xFF] ^ RT1[(Y1 >> 8) & 0xFF] ^ RT2[(Y0 >> 16) & 0xFF] ^ RT3[(Y3 >> 24) & 0xFF];
				X3 = *RK++ ^ RT0[(Y3) &0xFF] ^ RT1[(Y2 >> 8) & 0xFF] ^ RT2[(Y1 >> 16) & 0xFF] ^ RT3[(Y0 >> 24) & 0xFF];
			};
		}
		{
			Y0 = *RK++ ^ RT0[(X0) &0xFF] ^ RT1[(X3 >> 8) & 0xFF] ^ RT2[(X2 >> 16) & 0xFF] ^ RT3[(X1 >> 24) & 0xFF];
			Y1 = *RK++ ^ RT0[(X1) &0xFF] ^ RT1[(X0 >> 8) & 0xFF] ^ RT2[(X3 >> 16) & 0xFF] ^ RT3[(X2 >> 24) & 0xFF];
			Y2 = *RK++ ^ RT0[(X2) &0xFF] ^ RT1[(X1 >> 8) & 0xFF] ^ RT2[(X0 >> 16) & 0xFF] ^ RT3[(X3 >> 24) & 0xFF];
			Y3 = *RK++ ^ RT0[(X3) &0xFF] ^ RT1[(X2 >> 8) & 0xFF] ^ RT2[(X1 >> 16) & 0xFF] ^ RT3[(X0 >> 24) & 0xFF];
		};
		X0 = *RK++ ^ ((u32) RSb[(Y0) &0xFF]) ^ ((u32) RSb[(Y3 >> 8) & 0xFF] << 8) ^ ((u32) RSb[(Y2 >> 16) & 0xFF] << 16) ^ ((u32) RSb[(Y1 >> 24) & 0xFF] << 24);
		X1 = *RK++ ^ ((u32) RSb[(Y1) &0xFF]) ^ ((u32) RSb[(Y0 >> 8) & 0xFF] << 8) ^ ((u32) RSb[(Y3 >> 16) & 0xFF] << 16) ^ ((u32) RSb[(Y2 >> 24) & 0xFF] << 24);
		X2 = *RK++ ^ ((u32) RSb[(Y2) &0xFF]) ^ ((u32) RSb[(Y1 >> 8) & 0xFF] << 8) ^ ((u32) RSb[(Y0 >> 16) & 0xFF] << 16) ^ ((u32) RSb[(Y3 >> 24) & 0xFF] << 24);
		X3 = *RK++ ^ ((u32) RSb[(Y3) &0xFF]) ^ ((u32) RSb[(Y2 >> 8) & 0xFF] << 8) ^ ((u32) RSb[(Y1 >> 16) & 0xFF] << 16) ^ ((u32) RSb[(Y0 >> 24) & 0xFF] << 24);
		PUT_UINT32_LE(X0, output, 0);
		PUT_UINT32_LE(X1, output, 4);
		PUT_UINT32_LE(X2, output, 8);
		PUT_UINT32_LE(X3, output, 12);
	}

	pub fn mbedtls_aes_crypt_ecb(&mut self, i32 mode, const u8 input[16], u8 output[16]) -> i32
	{
		if mbedtls_aesni_has_support(0x02000000u)
		{
			return mbedtls_aesni_crypt_ecb(ctx, mode, input, output);
		}
		if mode == 1
		{
			mbedtls_aes_encrypt(ctx, input, output);
		}
		else
		{
			mbedtls_aes_decrypt(ctx, input, output);
		}
		return 0;
	}

	pub fn mbedtls_aes_crypt_cbc(&mut self, i32 mode, usize length, u8 iv[16], const u8 * input, u8 * output) -> i32
	{
		i32 i;
		u8 temp[16];
		if length % 16
		{
			return -0x0022;
		}
		if mode == 0
		{
			while (length > 0)
			{
				memcpy(temp, input, 16);
				mbedtls_aes_crypt_ecb(ctx, mode, input, output);
				for (i = 0; i < 16; i++)
				{
					output[i] = (i8) (output[i] ^ iv[i]);
				}
				memcpy(iv, temp, 16);
				input += 16;
				output += 16;
				length -= 16;
			}
		}
		else
		{
			while (length > 0)
			{
				for (i = 0; i < 16; i++)
				{
					output[i] = (i8) (input[i] ^ iv[i]);
				}
				mbedtls_aes_crypt_ecb(ctx, mode, output, output);
				memcpy(iv, output, 16);
				input += 16;
				output += 16;
				length -= 16;
			}
		}
		return 0;
	}

	pub fn mbedtls_aes_crypt_cfb128(&mut self, i32 mode, usize length, usize * iv_off, u8 iv[16], const u8 * input, u8 * output) -> i32
	{
		i32 c;
		usize n = *iv_off;
		if mode == 0
		{
			while (length--)
			{
				if n == 0
				{
					mbedtls_aes_crypt_ecb(ctx, 1, iv, iv);
				}
				c = *input++;
				*output++ = (i8) (c ^ iv[n]);
				iv[n] = (i8) c;
				n = (n + 1) & 0x0F;
			}
		}
		else
		{
			while (length--)
			{
				if n == 0
				{
					mbedtls_aes_crypt_ecb(ctx, 1, iv, iv);
				}
				iv[n] = *output++ = (i8) (iv[n] ^ *input++);
				n = (n + 1) & 0x0F;
			}
		}
		*iv_off = n;
		return 0;
	}

	pub fn mbedtls_aes_crypt_cfb8(&mut self, i32 mode, usize length, u8 iv[16], const u8 * input, u8 * output) -> i32
	{
		u8 c;
		u8 ov[17];
		while (length--)
		{
			memcpy(ov, iv, 16);
			mbedtls_aes_crypt_ecb(ctx, 1, iv, iv);
			if mode == 0
			{
				ov[16] = *input;
			}
			c = *output++ = (i8) (iv[0] ^ *input++);
			if mode == 1
			{
				ov[16] = c;
			}
			memcpy(iv, ov + 1, 16);
		}
		return 0;
	}

	pub fn mbedtls_aes_crypt_ctr(&mut self, usize length, usize * nc_off, u8 nonce_counter[16], u8 stream_block[16], const u8 * input, u8 * output) -> i32
	{
		i32 c, i;
		usize n = *nc_off;
		while (length--)
		{
			if n == 0
			{
				mbedtls_aes_crypt_ecb(ctx, 1, nonce_counter, stream_block);
				for (i = 16; i > 0; i--)
					if ++nonce_counter[i - 1] != 0
					{
						break;

					}
			}
			c = *input++;
			*output++ = (i8) (c ^ stream_block[n]);
			n = (n + 1) & 0x0F;
		}
		*nc_off = n;
		return 0;
	}
}

static u8 FSb[256];
static u32 FT0[256];
static u32 FT1[256];
static u32 FT2[256];
static u32 FT3[256];
static u8 RSb[256];
static u32 RT0[256];
static u32 RT1[256];
static u32 RT2[256];
static u32 RT3[256];
static u32 RCON[10];
static i32 aes_init_done = 0;

fn aes_gen_tables()
{
	i32 i, x, y, z;
	i32 pow[256];
	i32 log[256];
	for (i = 0, x = 1; i < 256; i++)
	{
		pow[i] = x;
		log[x] = i;
		x = (x ^ ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00))) & 0xFF;
	}
	for (i = 0, x = 1; i < 10; i++)
	{
		RCON[i] = (u32) x;
		x = ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00)) & 0xFF;
	}
	FSb[0x00] = 0x63;
	RSb[0x63] = 0x00;
	for (i = 1; i < 256; i++)
	{
		x = pow[255 - log[i]];
		y = x;
		y = ((y << 1) | (y >> 7)) & 0xFF;
		x ^= y;
		y = ((y << 1) | (y >> 7)) & 0xFF;
		x ^= y;
		y = ((y << 1) | (y >> 7)) & 0xFF;
		x ^= y;
		y = ((y << 1) | (y >> 7)) & 0xFF;
		x ^= y ^ 0x63;
		FSb[i] = (i8) x;
		RSb[x] = (i8) i;
	}
	for (i = 0; i < 256; i++)
	{
		x = FSb[i];
		y = ((x << 1) ^ ((x & 0x80) ? 0x1B : 0x00)) & 0xFF;
		z = (y ^ x) & 0xFF;
		FT0[i] = ((u32) y) ^ ((u32) x << 8) ^ ((u32) x << 16) ^ ((u32) z << 24);
		FT1[i] = ((FT0[i] << 8) & 0xFFFFFFFF) | (FT0[i] >> 24);
		FT2[i] = ((FT1[i] << 8) & 0xFFFFFFFF) | (FT1[i] >> 24);
		FT3[i] = ((FT2[i] << 8) & 0xFFFFFFFF) | (FT2[i] >> 24);
		x = RSb[i];
		RT0[i] = ((u32)((0x0E && x) ? pow[(log[0x0E] + log[x]) % 255] : 0)) ^ ((u32)((0x09 && x) ? pow[(log[0x09] + log[x]) % 255] : 0) << 8) ^ ((u32)((0x0D && x) ? pow[(log[0x0D] + log[x]) % 255] : 0) << 16) ^ ((u32)((0x0B && x) ? pow[(log[0x0B] + log[x]) % 255] : 0) << 24);
		RT1[i] = ((RT0[i] << 8) & 0xFFFFFFFF) | (RT0[i] >> 24);
		RT2[i] = ((RT1[i] << 8) & 0xFFFFFFFF) | (RT1[i] >> 24);
		RT3[i] = ((RT2[i] << 8) & 0xFFFFFFFF) | (RT2[i] >> 24);
	}
}

/*
static const u8 aes_test_ecb_dec[3][16] = {{0x44, 0x41, 0x6A, 0xC2, 0xD1, 0xF5, 0x3C, 0x58, 0x33, 0x03, 0x91, 0x7E, 0x6B, 0xE9, 0xEB, 0xE0}, {0x48, 0xE3, 0x1E, 0x9E, 0x25, 0x67, 0x18, 0xF2, 0x92, 0x29, 0x31, 0x9C, 0x19, 0xF1, 0x5B, 0xA4}, {0x05, 0x8C, 0xCF, 0xFD, 0xBB, 0xCB, 0x38, 0x2D, 0x1F, 0x6F, 0x56, 0x58, 0x5D, 0x8A, 0x4A, 0xDE}};
static const u8 aes_test_ecb_enc[3][16] = {{0xC3, 0x4C, 0x05, 0x2C, 0xC0, 0xDA, 0x8D, 0x73, 0x45, 0x1A, 0xFE, 0x5F, 0x03, 0xBE, 0x29, 0x7F}, {0xF3, 0xF6, 0x75, 0x2A, 0xE8, 0xD7, 0x83, 0x11, 0x38, 0xF0, 0x41, 0x56, 0x06, 0x31, 0xB1, 0x14}, {0x8B, 0x79, 0xEE, 0xCC, 0x93, 0xA0, 0xEE, 0x5D, 0xFF, 0x30, 0xB4, 0xEA, 0x21, 0x63, 0x6D, 0xA4}};
static const u8 aes_test_cbc_dec[3][16] = {{0xFA, 0xCA, 0x37, 0xE0, 0xB0, 0xC8, 0x53, 0x73, 0xDF, 0x70, 0x6E, 0x73, 0xF7, 0xC9, 0xAF, 0x86}, {0x5D, 0xF6, 0x78, 0xDD, 0x17, 0xBA, 0x4E, 0x75, 0xB6, 0x17, 0x68, 0xC6, 0xAD, 0xEF, 0x7C, 0x7B}, {0x48, 0x04, 0xE1, 0x81, 0x8F, 0xE6, 0x29, 0x75, 0x19, 0xA3, 0xE8, 0x8C, 0x57, 0x31, 0x04, 0x13}};
static const u8 aes_test_cbc_enc[3][16] = {{0x8A, 0x05, 0xFC, 0x5E, 0x09, 0x5A, 0xF4, 0x84, 0x8A, 0x08, 0xD3, 0x28, 0xD3, 0x68, 0x8E, 0x3D}, {0x7B, 0xD9, 0x66, 0xD5, 0x3A, 0xD8, 0xC1, 0xBB, 0x85, 0xD2, 0xAD, 0xFA, 0xE8, 0x7B, 0xB1, 0x04}, {0xFE, 0x3C, 0x53, 0x65, 0x3E, 0x2F, 0x45, 0xB5, 0x6F, 0xCD, 0x88, 0xB2, 0xCC, 0x89, 0x8F, 0xF0}};
static const u8 aes_test_cfb128_key[3][32] = {{0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C}, {0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B}, {0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4}};
static const u8 aes_test_cfb128_iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
static const u8 aes_test_cfb128_pt[64] = {0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A, 0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51, 0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF, 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10};
static const u8 aes_test_cfb128_ct[3][64] = {{0x3B, 0x3F, 0xD9, 0x2E, 0xB7, 0x2D, 0xAD, 0x20, 0x33, 0x34, 0x49, 0xF8, 0xE8, 0x3C, 0xFB, 0x4A, 0xC8, 0xA6, 0x45, 0x37, 0xA0, 0xB3, 0xA9, 0x3F, 0xCD, 0xE3, 0xCD, 0xAD, 0x9F, 0x1C, 0xE5, 0x8B, 0x26, 0x75, 0x1F, 0x67, 0xA3, 0xCB, 0xB1, 0x40, 0xB1, 0x80, 0x8C, 0xF1, 0x87, 0xA4, 0xF4, 0xDF, 0xC0, 0x4B, 0x05, 0x35, 0x7C, 0x5D, 0x1C, 0x0E, 0xEA, 0xC4, 0xC6, 0x6F, 0x9F, 0xF7, 0xF2, 0xE6}, {0xCD, 0xC8, 0x0D, 0x6F, 0xDD, 0xF1, 0x8C, 0xAB, 0x34, 0xC2, 0x59, 0x09, 0xC9, 0x9A, 0x41, 0x74, 0x67, 0xCE, 0x7F, 0x7F, 0x81, 0x17, 0x36, 0x21, 0x96, 0x1A, 0x2B, 0x70, 0x17, 0x1D, 0x3D, 0x7A, 0x2E, 0x1E, 0x8A, 0x1D, 0xD5, 0x9B, 0x88, 0xB1, 0xC8, 0xE6, 0x0F, 0xED, 0x1E, 0xFA, 0xC4, 0xC9, 0xC0, 0x5F, 0x9F, 0x9C, 0xA9, 0x83, 0x4F, 0xA0, 0x42, 0xAE, 0x8F, 0xBA, 0x58, 0x4B, 0x09, 0xFF}, {0xDC, 0x7E, 0x84, 0xBF, 0xDA, 0x79, 0x16, 0x4B, 0x7E, 0xCD, 0x84, 0x86, 0x98, 0x5D, 0x38, 0x60, 0x39, 0xFF, 0xED, 0x14, 0x3B, 0x28, 0xB1, 0xC8, 0x32, 0x11, 0x3C, 0x63, 0x31, 0xE5, 0x40, 0x7B, 0xDF, 0x10, 0x13, 0x24, 0x15, 0xE5, 0x4B, 0x92, 0xA1, 0x3E, 0xD0, 0xA8, 0x26, 0x7A, 0xE2, 0xF9, 0x75, 0xA3, 0x85, 0x74, 0x1A, 0xB9, 0xCE, 0xF8, 0x20, 0x31, 0x62, 0x3D, 0x55, 0xB1, 0xE4, 0x71}};
static const u8 aes_test_ctr_key[3][16] = {{0xAE, 0x68, 0x52, 0xF8, 0x12, 0x10, 0x67, 0xCC, 0x4B, 0xF7, 0xA5, 0x76, 0x55, 0x77, 0xF3, 0x9E}, {0x7E, 0x24, 0x06, 0x78, 0x17, 0xFA, 0xE0, 0xD7, 0x43, 0xD6, 0xCE, 0x1F, 0x32, 0x53, 0x91, 0x63}, {0x76, 0x91, 0xBE, 0x03, 0x5E, 0x50, 0x20, 0xA8, 0xAC, 0x6E, 0x61, 0x85, 0x29, 0xF9, 0xA0, 0xDC}};
static const u8 aes_test_ctr_nonce_counter[3][16] = {{0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, {0x00, 0x6C, 0xB6, 0xDB, 0xC0, 0x54, 0x3B, 0x59, 0xDA, 0x48, 0xD9, 0x0B, 0x00, 0x00, 0x00, 0x01}, {0x00, 0xE0, 0x01, 0x7B, 0x27, 0x77, 0x7F, 0x3F, 0x4A, 0x17, 0x86, 0xF0, 0x00, 0x00, 0x00, 0x01}};
static const u8 aes_test_ctr_pt[3][48] = {{0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67}, {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}, {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23}};
static const u8 aes_test_ctr_ct[3][48] = {{0xE4, 0x09, 0x5D, 0x4F, 0xB7, 0xA7, 0xB3, 0x79, 0x2D, 0x61, 0x75, 0xA3, 0x26, 0x13, 0x11, 0xB8}, {0x51, 0x04, 0xA1, 0x06, 0x16, 0x8A, 0x72, 0xD9, 0x79, 0x0D, 0x41, 0xEE, 0x8E, 0xDA, 0xD3, 0x88, 0xEB, 0x2E, 0x1E, 0xFC, 0x46, 0xDA, 0x57, 0xC8, 0xFC, 0xE6, 0x30, 0xDF, 0x91, 0x41, 0xBE, 0x28}, {0xC1, 0xCF, 0x48, 0xA8, 0x9F, 0x2F, 0xFD, 0xD9, 0xCF, 0x46, 0x52, 0xE9, 0xEF, 0xDB, 0x72, 0xD7, 0x45, 0x40, 0xA4, 0x2B, 0xDE, 0x6D, 0x78, 0x36, 0xD5, 0x9A, 0x5C, 0xEA, 0xAE, 0xF3, 0x10, 0x53, 0x25, 0xB2, 0x07, 0x2F}};
static const i32 aes_test_ctr_len[3] = {16, 32, 36};
pub fn mbedtls_aes_self_test(i32 verbose) -> i32
{
	i32 ret = 0, i, j, u, v;
	u8 key[32];
	u8 buf[64];
	u8 iv[16];
	u8 prv[16];
	usize offset;
	i32 len;
	u8 nonce_counter[16];
	u8 stream_block[16];
	mbedtls_aes_context ctx;
	memset(key, 0, 32);
	mbedtls_aes_init(&ctx);
	for (i = 0; i < 6; i++)
	{
		u = i >> 1;
		v = i & 1;
		if verbose != 0
		{
			printf("  AES-ECB-%3d (%s): ", 128 + u * 64, (v == 0) ? "dec" : "enc");
		}
		memset(buf, 0, 16);
		if v == 0
		{
			mbedtls_aes_setkey_dec(&ctx, key, 128 + u * 64);
			for (j = 0; j < 10000; j++)
			{
				mbedtls_aes_crypt_ecb(&ctx, v, buf, buf);
			}
			if memcmp(buf, aes_test_ecb_dec[u], 16) != 0
			{
				if verbose != 0
				{
					printf("failed\n");
				}
				ret = 1;
				goto exit;
			}
		}
		else
		{
			mbedtls_aes_setkey_enc(&ctx, key, 128 + u * 64);
			for (j = 0; j < 10000; j++)
			{
				mbedtls_aes_crypt_ecb(&ctx, v, buf, buf);
			}
			if memcmp(buf, aes_test_ecb_enc[u], 16) != 0
			{
				if verbose != 0
				{
					printf("failed\n");
				}
				ret = 1;
				goto exit;
			}
		}
		if verbose != 0
		{
			printf("passed\n");
		}
	}
	if verbose != 0
	{
		printf("\n");
	}
	for (i = 0; i < 6; i++)
	{
		u = i >> 1;
		v = i & 1;
		if verbose != 0
		{
			printf("  AES-CBC-%3d (%s): ", 128 + u * 64, (v == 0) ? "dec" : "enc");
		}
		memset(iv, 0, 16);
		memset(prv, 0, 16);
		memset(buf, 0, 16);
		if v == 0
		{
			mbedtls_aes_setkey_dec(&ctx, key, 128 + u * 64);
			for (j = 0; j < 10000; j++)
			{
				mbedtls_aes_crypt_cbc(&ctx, v, 16, iv, buf, buf);
			}
			if memcmp(buf, aes_test_cbc_dec[u], 16) != 0
			{
				if verbose != 0
				{
					printf("failed\n");
				}
				ret = 1;
				goto exit;
			}
		}
		else
		{
			mbedtls_aes_setkey_enc(&ctx, key, 128 + u * 64);
			for (j = 0; j < 10000; j++)
			{
				u8 tmp[16];
				mbedtls_aes_crypt_cbc(&ctx, v, 16, iv, buf, buf);
				memcpy(tmp, prv, 16);
				memcpy(prv, buf, 16);
				memcpy(buf, tmp, 16);
			}
			if memcmp(prv, aes_test_cbc_enc[u], 16) != 0
			{
				if verbose != 0
				{
					printf("failed\n");
				}
				ret = 1;
				goto exit;
			}
		}
		if verbose != 0
		{
			printf("passed\n");
		}
	}
	if verbose != 0
	{
		printf("\n");
	}
	for (i = 0; i < 6; i++)
	{
		u = i >> 1;
		v = i & 1;
		if verbose != 0
		{
			printf("  AES-CFB128-%3d (%s): ", 128 + u * 64, (v == 0) ? "dec" : "enc");
		}
		memcpy(iv, aes_test_cfb128_iv, 16);
		memcpy(key, aes_test_cfb128_key[u], 16 + u * 8);
		offset = 0;
		mbedtls_aes_setkey_enc(&ctx, key, 128 + u * 64);
		if v == 0
		{
			memcpy(buf, aes_test_cfb128_ct[u], 64);
			mbedtls_aes_crypt_cfb128(&ctx, v, 64, &offset, iv, buf, buf);
			if memcmp(buf, aes_test_cfb128_pt, 64) != 0
			{
				if verbose != 0
				{
					printf("failed\n");
				}
				ret = 1;
				goto exit;
			}
		}
		else
		{
			memcpy(buf, aes_test_cfb128_pt, 64);
			mbedtls_aes_crypt_cfb128(&ctx, v, 64, &offset, iv, buf, buf);
			if memcmp(buf, aes_test_cfb128_ct[u], 64) != 0
			{
				if verbose != 0
				{
					printf("failed\n");
				}
				ret = 1;
				goto exit;
			}
		}
		if verbose != 0
		{
			printf("passed\n");
		}
	}
	if verbose != 0
	{
		printf("\n");
	}
	for (i = 0; i < 6; i++)
	{
		u = i >> 1;
		v = i & 1;
		if verbose != 0
		{
			printf("  AES-CTR-128 (%s): ", (v == 0) ? "dec" : "enc");
		}
		memcpy(nonce_counter, aes_test_ctr_nonce_counter[u], 16);
		memcpy(key, aes_test_ctr_key[u], 16);
		offset = 0;
		mbedtls_aes_setkey_enc(&ctx, key, 128);
		if v == 0
		{
			len = aes_test_ctr_len[u];
			memcpy(buf, aes_test_ctr_ct[u], len);
			mbedtls_aes_crypt_ctr(&ctx, len, &offset, nonce_counter, stream_block, buf, buf);
			if memcmp(buf, aes_test_ctr_pt[u], len) != 0
			{
				if verbose != 0
				{
					printf("failed\n");
				}
				ret = 1;
				goto exit;
			}
		}
		else
		{
			len = aes_test_ctr_len[u];
			memcpy(buf, aes_test_ctr_pt[u], len);
			mbedtls_aes_crypt_ctr(&ctx, len, &offset, nonce_counter, stream_block, buf, buf);
			if memcmp(buf, aes_test_ctr_ct[u], len) != 0
			{
				if verbose != 0
				{
					printf("failed\n");
				}
				ret = 1;
				goto exit;
			}
		}
		if verbose != 0
		{
			printf("passed\n");
		}
	}
	if verbose != 0
	{
		printf("\n");
	}
	ret = 0;
exit:
	mbedtls_aes_free(&ctx);
	return ret;
}
*/
