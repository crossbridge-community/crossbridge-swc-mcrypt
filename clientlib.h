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

#define ALGO_RIJNDAEL_128 "rijndael-128"

//----------------------------------
//  Encryption Modes
//----------------------------------

#define MODE_ECB "ecb"
#define MODE_CBC "cbc"
#define MODE_CFB "cfb"
#define MODE_OFB "ofb"
#define MODE_CTR "ctr"

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
int encrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len);

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
int decrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len);

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