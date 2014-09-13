/*
 * =BEGIN MIT LICENSE
 * 
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Andras Csizmadia
 * http://www.vpmedia.hu
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * 
 * =END MIT LICENSE
 *
 */

/**
 *  ClientLib
 *  clientlib.h
 *  Purpose: Client library header
 *
 *  @author Andras Csizmadia
 *  @version 1.0
 */
 
//----------------------------------
//  Include Once Start
//----------------------------------

#ifndef __CLIENTLIB_H
#define __CLIENTLIB_H

//----------------------------------
//  CPP Start
//----------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//----------------------------------
//  MHash Constants
//----------------------------------

#include "mutils/mglobal.h"

//----------------------------------
//  MCrypt Constants
//----------------------------------

/* Algorithms */
#define MCRYPT_BLOWFISH		"blowfish"
#define MCRYPT_DES 		"des"
#define MCRYPT_3DES 		"tripledes"
#define MCRYPT_3WAY 		"threeway"
#define MCRYPT_GOST 		"gost"
#define MCRYPT_SAFER_SK64 	"safer-sk64"
#define MCRYPT_SAFER_SK128 	"safer-sk128"
#define MCRYPT_CAST_128 	"cast-128"
#define MCRYPT_XTEA 		"xtea"
#define MCRYPT_RC2	 	"rc2"
#define MCRYPT_TWOFISH 		"twofish"
#define MCRYPT_CAST_256 	"cast-256"
#define MCRYPT_SAFERPLUS 	"saferplus"
#define MCRYPT_LOKI97 		"loki97"
#define MCRYPT_SERPENT 		"serpent"
#define MCRYPT_RIJNDAEL_128 	"rijndael-128"
#define MCRYPT_RIJNDAEL_192 	"rijndael-192"
#define MCRYPT_RIJNDAEL_256 	"rijndael-256"
#define MCRYPT_ENIGMA 		"enigma"
#define MCRYPT_ARCFOUR		"arcfour"
#define MCRYPT_WAKE		"wake"

	/* Modes */
#define MCRYPT_CBC		"cbc"
#define MCRYPT_ECB		"ecb"
#define MCRYPT_CFB		"cfb"
#define MCRYPT_OFB		"ofb"
#define MCRYPT_nOFB		"nofb"
#define MCRYPT_STREAM		"stream"

//----------------------------------
//  API
//----------------------------------

/**
 * Does the encryption
 *
 * @param algo
 * @param mode
 * @param buffer
 * @param buffer_len
 * @param IV
 * @param key
 * @param key_len
 *
 * @return int
 *
 */
int ext_encrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len);

/**
 * Does the decryption
 *
 * @param algo
 * @param mode
 * @param buffer
 * @param buffer_len
 * @param IV
 * @param key
 * @param key_len
 *
 * @return int
 */
int ext_decrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len);

/**
 * Hashes a string
 *
 * @param hashid
 * @param buffer
 * @param out
 * @param outsize
 *
 * @return int
 */
int ext_hash(int type, char* buffer, unsigned char** out, unsigned int* outsize);

//----------------------------------
//  CPP End
//----------------------------------

#ifdef __cplusplus
}
#endif

//----------------------------------
//  Include Once End
//----------------------------------

#endif/*__CLIENTLIB_H*/