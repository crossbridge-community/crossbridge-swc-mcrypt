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

//----------------------------------
//  API
//----------------------------------

/**
 * @private
 */
int ext_encrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len){
    MCRYPT td = mcrypt_module_open(algo, NULL, mode, NULL);
    int blocksize = mcrypt_enc_get_block_size(td);
    /* Because the plaintext could include null bytes*/
    if( buffer_len % blocksize != 0 ){return 1;}     
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
    int blocksize = mcrypt_enc_get_block_size(td);
    /* Because the plaintext could include null bytes*/
    if( buffer_len % blocksize != 0 ){return 1;}
    mcrypt_generic_init(td, key, key_len, IV);
    mdecrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit (td);
    mcrypt_module_close(td);
    return 0;
}

/**
 * @see clientlib.h 
 */
int ext_hash(hashid type, char* buffer){ 
    MHASH td;
    td = mhash_init(type);
    if (td == MHASH_FAILED) exit(1);

    int buffer_len = strlen(buffer);
    mhash(td, buffer, buffer_len);

    unsigned char hash[16]; 
    mhash_deinit(td, hash);

    unsigned int i;
    for (i = 0; i < mhash_get_block_size(type); i++) {
        printf("%.2x", hash[i]);
    }
    printf("\n");
 
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

/**
 * @see clientlib.h 
 */
int selftest(){ 
    char* algo = "rijndael-128";
    char* mode = "cbc";
    char* plaintext = "test text 123";
    char* IV = "AAAAAAAAAAAAAAAA";
    char* key = "0123456789abcdef";
    int keysize = 16; /* 128 bits */
    char* buffer;
    int buffer_len = 16;
     
    buffer = calloc(1, buffer_len);
    strncpy(buffer, plaintext, buffer_len);
     
    printf("plain: %s\n", plaintext);
    ext_encrypt(algo, mode, buffer, buffer_len, IV, key, keysize);
    printf("cipher: "); display(buffer, buffer_len);
    //printf("cipher: %s\n", buffer);
    ext_decrypt(algo, mode, buffer, buffer_len, IV, key, keysize);
    printf("decrypt: %s\n", buffer); 
    
    // MHASH
    
     // source data
    char* test_hash = "Hello World"; 
    
    // md5: b10a8db164e0754105b7a99be72e3fe5
    printf("Testing MHASH_MD5 ...\n");
    ext_hash(MHASH_MD5, test_hash);
    
    // sha1: 0a4d55a8d778e5022fab701977c5d840bbc486d0
    printf("Testing MHASH_SHA1 ...\n");
    ext_hash(MHASH_SHA1, test_hash);
       
    // sha256: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e
    printf("Testing MHASH_SHA256 ...\n");
    ext_hash(MHASH_SHA256, test_hash);
    
    // sha512: 2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b
    printf("Testing MHASH_SHA512 ...\n");
    ext_hash(MHASH_SHA512, test_hash);
    
    return 0;
}
