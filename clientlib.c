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

/**
 * @private
 */
int doEncrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len){
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
int doDecrypt(char* algo, char* mode, void* buffer, int buffer_len, char* IV, char* key, int key_len){
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

//----------------------------------
//  API
//----------------------------------

/**
 * @see clientlib.h 
 */
int encrypt(int algo, int mode, void* buffer, int buffer_len, char* IV, char* key, int key_len){
    // TODO: switch by algo and mode
    char* algo_name = "rijndael-128";
    char* mode_name = "cbc";
    int result = 1;
    result = doEncrypt(algo_name, mode_name, buffer, buffer_len, IV, key, key_len);
    return result;
}

/**
 * @see clientlib.h 
 */
int decrypt(int algo, int mode, void* buffer, int buffer_len, char* IV, char* key, int key_len){
    // TODO: switch by algo and mode
    char* algo_name = "rijndael-128";
    char* mode_name = "cbc";
    int result = 1;
    result = doDecrypt(algo_name, mode_name, buffer, buffer_len, IV, key, key_len);
    return result;
}

/**
 * @see clientlib.h 
 */
int selftest(){         
    char * plaintext = "test text 123";
    char* IV = "AAAAAAAAAAAAAAAA";
    char* key = "0123456789abcdef";
    int keysize = 16; /* 128 bits */
    char* buffer;
    int buffer_len = 16;
     
    buffer = calloc(1, buffer_len);
    strncpy(buffer, plaintext, buffer_len);
     
    printf("plain: %s\n", plaintext);
    encrypt(ALGO_RIJNDAEL128, MODE_CBC, buffer, buffer_len, IV, key, keysize);
    printf("cipher: "); display(buffer, buffer_len);
    //printf("cipher: %s\n", buffer);
    decrypt(ALGO_RIJNDAEL128, MODE_CBC, buffer, buffer_len, IV, key, keysize);
    printf("decrypt: %s\n", buffer); 
    return 0;
}
