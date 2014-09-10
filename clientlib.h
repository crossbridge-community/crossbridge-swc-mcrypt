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
//  Library Version
//----------------------------------

#define VERSION "1.0.0" 

//----------------------------------
//  Encryption Algorithms
//----------------------------------

#define ALGO_3WAY 1
#define ALGO_ARCFOUR 2
#define ALGO_BLOWFISH 3
#define ALGO_CAST128 4
#define ALGO_DES 5
#define ALGO_ENIGMA 6
#define ALGO_GOS 7
#define ALGO_LOKI97 8
#define ALGO_PANAMA 9
#define ALGO_RC2 10
#define ALGO_RIJNDAEL 11
#define ALGO_RIJNDAEL128 12
#define ALGO_RIJNDAEL192 13
#define ALGO_RIJNDAEL256 14
#define ALGO_SAFER 15
#define ALGO_SAFERPLUS 16
#define ALGO_SERPENT 17
#define ALGO_TRIPLEDES 18
#define ALGO_TWOFISH 19
#define ALGO_WAKE 20
#define ALGO_XTEA 21

//----------------------------------
//  Encryption Modes
//----------------------------------

#define MODE_CBC 1
#define MODE_CBS 2
#define MODE_CFB 3
#define MODE_CTR 4
#define MODE_ECB 5
#define MODE_NCFB 6
#define MODE_NOFB 7
#define MODE_OFB 8
#define MODE_STREAM 9 

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
int encrypt(int algo, int mode, void* buffer, int buffer_len, char* IV, char* key, int key_len);

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
int decrypt(int algo, int mode, void* buffer, int buffer_len, char* IV, char* key, int key_len);

/**
 * Runs a self test
 */
int selftest();

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