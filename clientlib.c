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
 *  clientlib.c
 *  Purpose: MCrypt SWC Wrapper
 *
 *  @author Andras Csizmadia
 *  @version 1.0
 *  @see https://gist.github.com/bricef/2436364
 */

//----------------------------------
//  Imports
//----------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <mutils/mcrypt.h>
#include <mhash.h>
#include "clientlib.h"

//----------------------------------
//  Static
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
//  Helpers
//----------------------------------

/**
 * @private
 */
void display(char* ciphertext, int len){
    int i;
    for (i = 0; i < len; i++){
        printf("%d", ciphertext[i]);
    }
    printf("\n");
}

/**
 * @private
 */
void bin_to_hex(unsigned char *bin, unsigned int binsz, unsigned char **result)
{
  unsigned char          hex_str[]= "0123456789abcdef";
  unsigned int  i;

  *result = (unsigned char *)malloc(binsz * 2 + 1);
  (*result)[binsz * 2] = 0;

  if (!binsz)
    return;

  for (i = 0; i < binsz; i++)
    {
      (*result)[i * 2 + 0] = hex_str[bin[i] >> 4  ];
      (*result)[i * 2 + 1] = hex_str[bin[i] & 0x0F];
    }
}

//----------------------------------
//  API
//----------------------------------

// const unsigned char* buffer
// void* buffer

/**
 * @private
 */
int ext_encrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len){
    MCRYPT td = mcrypt_module_open(algo, NULL, mode, NULL);
    if( !td ){return 1;}
    int blocksize = mcrypt_enc_get_block_size(td);
    int keysize = mcrypt_enc_get_key_size(td);
    printf("keysize: %d\n", keysize);
    printf("key_len: %d\n", key_len);
    if( buffer_len % blocksize != 0 ){return 1;}
    //if( key_len % keysize != 0 ){return 3;}
    mcrypt_generic_init(td, key, key_len, IV);
    mcrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit (td);
    mcrypt_module_close(td);
    return 0;
}
 
/**
 * @private
 */
int ext_decrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len){
    MCRYPT td = mcrypt_module_open(algo, NULL, mode, NULL);
    if( !td ){return 1;}
    int blocksize = mcrypt_enc_get_block_size(td);
    int keysize = mcrypt_enc_get_key_size(td);
    printf("keysize: %d\n", keysize);
    printf("key_len: %d\n", key_len);
    if( buffer_len % blocksize != 0 ){return 1;}
    //if( key_len % keysize != 0 ){return 3;}
    mcrypt_generic_init(td, key, key_len, IV);
    mdecrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit (td);
    mcrypt_module_close(td);
    return 0;
}

/**
 * @see clientlib.h
 */
int ext_hash(int type, char* buffer, unsigned char** out, unsigned int* outsize){
    MHASH td;
    td = mhash_init((hashid)type);
    if (td == MHASH_FAILED) exit(1);

    int buffer_len = strlen(buffer);
    mhash(td, buffer, buffer_len);

    unsigned int block_size = mhash_get_block_size((hashid)type);
    unsigned char hash[block_size];
    mhash_deinit(td, hash);

    //printf("block_size: %d\n", block_size);
    //printf("hash: %s\n", hash);
    /*unsigned int i;
    for (i = 0; i < block_size; i++) {
        printf("%.2x", hash[i]);
    }
    printf("\n");*/

    unsigned char *result;
    bin_to_hex((unsigned char *)hash, block_size, &result);
    //printf("result : %s\n", result);
    //free(result);

    *out = result;
    *outsize = block_size * 2;

    return 0;
}

/**
 * @see clientlib.h 
 */
int ext_hmac(){ 
    return 0;
}

/**
 * @see clientlib.h 
 */
int ext_keygen(){ 
    return 0;
}
