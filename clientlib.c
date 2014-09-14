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
void bin_to_hex(unsigned char *bin, unsigned int binsz, unsigned char **result)
{
  unsigned char hex_str[]= "0123456789abcdef";
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
    if( buffer_len % blocksize != 0 ){return 1;}
    //if( keysize %  key_len != 0 ){return 1;}
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
    if( buffer_len % blocksize != 0 ){return 1;}
    //if( keysize % key_len != 0 ){return 1;}
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

    unsigned char *result;
    bin_to_hex((unsigned char *)hash, block_size, &result);

    *out = result;
    *outsize = block_size * 2;

    free(result);

    return 0;
}

/**
 * @see clientlib.h 
 */
int ext_hmac(int type, char* password, char* data, unsigned char** out, unsigned int* outsize){
    unsigned int passlen = strlen(password);
    unsigned int datalen = strlen(data);
    MHASH td = mhash_hmac_init((hashid)type, password, passlen, mhash_get_hash_pblock(MHASH_MD5));
    mhash(td, data, datalen);
    unsigned char *mac = mhash_hmac_end(td);
    unsigned char *tmp = mutils_asciify(mac, mhash_get_block_size(MHASH_MD5));
    unsigned int tmp_len = strlen(tmp);
    *out = tmp;
    *outsize = tmp_len;
    mutils_free(tmp);
    return 0;
}

/**
 * @see clientlib.h 
 */
int ext_keygen(int type, char* password, unsigned char** out, unsigned int* outsize){
    unsigned char *tmp;
    unsigned char *salt;
    unsigned int passlen;
    unsigned int keysize;
    unsigned int salt_size;
    KEYGEN data;
    unsigned char *key;

    passlen=strlen(password)+1;
    //printf("passlen : %d\n", passlen);

    if (mhash_get_keygen_max_key_size(KEYGEN_MCRYPT)==0) {
        keysize=100;
    } else {
        keysize = mhash_get_keygen_max_key_size(KEYGEN_MCRYPT);
    }

    if (mhash_get_keygen_salt_size(KEYGEN_MCRYPT)==0) {
        salt_size=10;
    } else {
        salt_size = mhash_get_keygen_salt_size(KEYGEN_MCRYPT);
    }

    salt = (unsigned char *) mutils_malloc(salt_size);
    key = (unsigned char *) mutils_malloc(keysize);

    if ((salt == NULL) || (key == NULL))
    {
        return 1;
    }

    data.hash_algorithm[0] = (hashid)type;
    data.count = 0;
    data.salt = salt;
    data.salt_size = salt_size;

    mhash_keygen_ext(KEYGEN_MCRYPT, data, key, keysize, password, passlen);

    tmp = mutils_asciify(key, keysize);

    if ((tmp == NULL))
    {
        return 1;
    }

    unsigned int tmp_len = strlen(tmp) + 1;

    *out = tmp;
    *outsize = tmp_len;

    mutils_free(password);
    mutils_free(key);
    mutils_free(tmp);

    return 0;
}
