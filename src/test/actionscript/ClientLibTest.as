/*
 * =BEGIN MIT LICENSE
 * 
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 The CrossBridge Team
 * https://github.com/crossbridge-community
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
package {
import crossbridge.MCrypt.CModule;

import flash.display.Sprite;
import flash.utils.ByteArray;

import flexunit.framework.Assert;

public class ClientLibTest extends Sprite {
    
    [Before]
    public function setUp():void {
       if(!CModule.rootSprite) {
            CModule.throwWhenOutOfMemory = true;
            CModule.rootSprite = this;
            CModule.startAsync(this);
       }
        
    }

    [After]
    public function tearDown():void {
        //CModule.dispose();
    }
    
    [Test]
    public function test_md5():void {
        testAlgo(ClientLib.MHASH_MD5, "Hello World", "b10a8db164e0754105b7a99be72e3fe5");
    }

    [Test]
    public function test_sha1():void {
        testAlgo(ClientLib.MHASH_SHA1, "Hello World", "0a4d55a8d778e5022fab701977c5d840bbc486d0");
    }

    [Test]
    public function test_sha256():void {
        testAlgo(ClientLib.MHASH_SHA256, "Hello World", "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e");
    }

    [Test]
    public function test_sha384():void {
        testAlgo(ClientLib.MHASH_SHA384, "Hello World", "99514329186b2f6ae4a1329e7ee6c610a729636335174ac6b740f9028396fcc803d0e93863a7c3d90f86beee782f4f3f");
    }

    [Test]
    public function test_sha512():void {
        testAlgo(ClientLib.MHASH_SHA512, "Hello World", "2c74fd17edafd80e8447b0d46741ee243b7eb74dd2149a0ab1b9246fb30382f27e853d8585719e0e67cbda0daa8f51671064615d645ae27acb15bfb1447f459b");
    }

    [Test]
    public function test_keygen_md5():void {
        testKeygen(ClientLib.MHASH_MD5, "Hello there", "95686ac64b9d18e71e3f41445ef0e5cbec88445e83aa03a8255cb5aa234d6f8c7bd6bfc2f2eb6051c29658cfb77cd0fc1a8254612193e3ec64b38a77803eee54788421b72508372a1363e4761a83c5775bdd2edd8dc12ba4321a4a113a73902eac824ac9");
    }

    [Test]
    public function test_keygen_sha512():void {
        testKeygen(ClientLib.MHASH_SHA512, "Hello there", "2f918a43a5a2041913c668b7f969c4a3d18e0f065f755738ee547fd4e6e86a28580656ccefa75151dbc8fe01dddc73643c8deaabf2aff5e56308b18823a48bb607f657464b367bb74d0a7dcf8fdf2c7da2e592ae45f0e76c7a9b75f3c21ac78226ecdf56");
    }

    [Test]
    public function test_hmac_md5():void {
        testHMAC(ClientLib.MHASH_MD5, "Jefe", "what do ya want for nothing?", "750c783e6ab0b503eaa86e310a5db738");
    }

    [Test]
    public function test_hmac_sha512():void {
        testHMAC(ClientLib.MHASH_SHA512, "Jefe", "what do ya want for nothing?", "d2766eca33fe852bd629253fe01c6351");
    }

    [Test]
    public function test_rijndael_128_cbc():void {
        testEncDec(ClientLib.MCRYPT_RIJNDAEL_128, ClientLib.MCRYPT_CBC);
    }

    /*[Test]
    public function test_rijndael_192_cbc():void {
        testEncDec(ClientLib.MCRYPT_RIJNDAEL_192, ClientLib.MCRYPT_CBC);
    }*/

    [Test]
    public function test_rijndael_256_cbc():void {
        testEncDec(ClientLib.MCRYPT_RIJNDAEL_256, ClientLib.MCRYPT_CBC);
    }

    [Test]
    public function test_blowfish_cbc():void {
        testEncDec(ClientLib.MCRYPT_BLOWFISH, ClientLib.MCRYPT_CBC);
    }

    [Test]
    public function test_xtea_cbc():void {
        testEncDec(ClientLib.MCRYPT_XTEA, ClientLib.MCRYPT_CBC);
    }

    [Test]
    public function test_saferplus_cbc():void {
        testEncDec(ClientLib.MCRYPT_SAFERPLUS, ClientLib.MCRYPT_CBC);
    }

    /*[Test]
    public function test_arcfour_cbc():void {
        testEncDec(ClientLib.MCRYPT_ARCFOUR, ClientLib.MCRYPT_CBC);
    }*/

    /**
     * @private
     */
    private function testEncDec(type:String, mode:String):void {
        var bytes:ByteArray = new ByteArray();
        bytes.endian = "littleEndian";
        for (var i:int = 0; i < 16; i++) {
            bytes.writeInt(i);
        }
        bytes.position = 0;
        var bytesPtr:int = CModule.malloc(bytes.length);
        CModule.writeBytes(bytesPtr, bytes.length, bytes);
        var result:int;
        result = ClientLib.ext_encrypt(type, mode, bytesPtr, bytes.length, "AAAAAAAAAAAAAAAA", "0123456789abcdef", 16);
        Assert.assertEquals(result, 0);
        result = ClientLib.ext_decrypt(type, mode, bytesPtr, bytes.length, "AAAAAAAAAAAAAAAA", "0123456789abcdef", 16);
        Assert.assertEquals(result, 0);
        bytes.position = 0;
        for (var j:int = 0; j < 16; j++) {
            Assert.assertEquals(bytes.readInt(), j);
        }
    }

    /**
     * @private
     */
    private function testAlgo(type:int, source:String, expected:String):void {
        var outputPtr:int = CModule.malloc(4);
        var outputLengthPtr:int = CModule.malloc(4);

        ClientLib.ext_hash(type, source, outputPtr, outputLengthPtr);

        var outputLength:int = CModule.read32(outputLengthPtr);
        var outputString:String = CModule.readString(CModule.read32(outputPtr), outputLength);
        Assert.assertEquals(outputString, expected);

        CModule.free(outputPtr);
        CModule.free(outputLengthPtr);
    }

    /**
     * @private
     */
    private function testKeygen(type:int, source:String, expected:String):void {
        var outputPtr:int = CModule.malloc(4);
        var outputLengthPtr:int = CModule.malloc(4);

        ClientLib.ext_keygen(type, source, outputPtr, outputLengthPtr);

        var outputLength:int = CModule.read32(outputLengthPtr);
        var outputString:String = CModule.readString(CModule.read32(outputPtr), outputLength);

        Assert.assertEquals(outputString, expected);

        CModule.free(outputPtr);
        CModule.free(outputLengthPtr);
    }

    /**
     * @private
     */
    private function testHMAC(type:int, source:String, data:String, expected:String):void {
        var outputPtr:int = CModule.malloc(4);
        var outputLengthPtr:int = CModule.malloc(4);

        ClientLib.ext_hmac(type, source, data, outputPtr, outputLengthPtr);

        var outputLength:int = CModule.read32(outputLengthPtr);
        var outputString:String = CModule.readString(CModule.read32(outputPtr), outputLength);

        Assert.assertEquals(outputString, expected);

        CModule.free(outputPtr);
        CModule.free(outputLengthPtr);
    }
}
}
