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
 *  Purpose: Client library implementation
 *
 *  @author Andras Csizmadia
 *  @version 1.0
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
//  Constants
//----------------------------------

/**
 * @private
 */
#define PAYLOAD "HelloWorld";

//----------------------------------
//  API
//----------------------------------

/**
 * @see clientlib.h 
 */
void testMCrypt(){ 
    MCRYPT td; 
    int i;
    char *key; /* created using mcrypt_gen_key */
    char *block_buffer;
    char *IV;
    int blocksize;
    int keysize = 24; /* 192 bits == 24 bytes */


    key = calloc(1, keysize);
    strcpy(key, "A_large_and_random_key"); 

    td = mcrypt_module_open("saferplus", NULL, "cbc", NULL);

    blocksize = mcrypt_enc_get_block_size(td);
    block_buffer = malloc(blocksize);
    /* but unfortunately this does not fill all the key so the rest bytes are
    * padded with zeros. Try to use large keys or convert them with mcrypt_gen_key().
    */

    IV=malloc(mcrypt_enc_get_iv_size(td));

    /* Put random data in IV. Note these are not real random data, 
    * consider using /dev/random or /dev/urandom.
    */

    /* srand(time(0)); */
    for (i=0; i < mcrypt_enc_get_iv_size(td); i++) {
    IV[i]=rand();
    }

    mcrypt_generic_init(td, key, keysize, IV);

    /* Encryption in CBC is performed in blocks */
    while ( fread (block_buffer, 1, blocksize, stdin) == blocksize ) {
      mcrypt_generic (td, block_buffer, blocksize);
    /*      mdecrypt_generic (td, block_buffer, blocksize); */
      fwrite ( block_buffer, 1, blocksize, stdout);
    }
    mcrypt_generic_end (td);
}


/**
 * @see clientlib.h 
 */
void getPayload(char** out, int* outsize){
    char* version = PAYLOAD;
    *out = version;
    *outsize = strlen(version);
}