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
import crossbridge.MCrypt.vfs.ISpecialFile;

import flash.display.Sprite;
import flash.display.StageScaleMode;
import flash.events.Event;
import flash.text.TextField;
import flash.utils.ByteArray;

/**
 * ClientLib Example
 */
[SWF(width="800", height="600", backgroundColor="#999999", frameRate="60")]
public class Main extends Sprite implements ISpecialFile {
    /**
     * @private
     */
    private var output:TextField;

    //----------------------------------
    //  Constructor
    //----------------------------------

    /**
     * Constructor
     */
    public function Main() {
        CModule.rootSprite = this;
        CModule.throwWhenOutOfMemory = true;
        CModule.vfs.console = this;
        addEventListener(Event.ADDED_TO_STAGE, onAdded);
    }

    /**
     * @private
     */
    private function onAdded(event:Event):void {
        removeEventListener(Event.ADDED_TO_STAGE, onAdded);

        // setup the output text area
        output = new TextField();
        output.multiline = true;
        output.wordWrap = true;
        output.width = stage.stageWidth;
        output.height = stage.stageHeight;
        addChild(output);

        stage.frameRate = 60;
        stage.scaleMode = StageScaleMode.NO_SCALE;

        CModule.startAsync(this);

        //addEventListener(Event.ENTER_FRAME, enterFrame);

        printLine("RIJNDAEL_128:");
        var bytes:ByteArray = new ByteArray();
        bytes.endian = "littleEndian";
        for (var i:int = 0; i < 16; i++) {
            bytes.writeInt(i);
        }
        bytes.position = 0;
        var bytesPtr:int = CModule.malloc(bytes.length);
        CModule.writeBytes(bytesPtr, bytes.length, bytes);
        printLine(ClientLib.ext_encrypt(ClientLib.MCRYPT_RIJNDAEL_128, ClientLib.MCRYPT_CBC, bytesPtr, bytes.length, "AAAAAAAAAAAAAAAA", "0123456789abcdef", 16).toString());
        printLine(ClientLib.ext_decrypt(ClientLib.MCRYPT_RIJNDAEL_128, ClientLib.MCRYPT_CBC, bytesPtr, bytes.length, "AAAAAAAAAAAAAAAA", "0123456789abcdef", 16).toString());
        /*bytes.position = 0;
        for (var j:int = 0; j < 16; j++) {
            trace(bytes.readInt());
        }*/
    }

    /**
     * @private
     */
    private function printLine(string:String):void {
        output.appendText(string + "\n");
        trace(string);
    }

    /**
     * The enterFrame callback will be run once every frame. UI thunk requests should be handled
     * here by calling CModule.serviceUIRequests() (see CModule ASdocs for more information on the UI thunking functionality).
     */
    private function enterFrame(e:Event):void {
        CModule.serviceUIRequests();
    }

    // ISpecialFile API implementation

    /**
     * The callback to call when FlasCC code calls the posix exit() function. Leave null to exit silently.
     * @private
     */
    public var exitHook:Function;

    /**
     * The PlayerKernel implementation will use this function to handle
     * C process exit requests
     */
    public function exit(code:int):Boolean {
        // default to unhandled
        return exitHook ? exitHook(code) : false;
    }

    /**
     * The PlayerKernel implementation will use this function to handle
     * C IO write requests to the file "/dev/tty" (e.g. output from
     * printf will pass through this function). See the ISpecialFile
     * documentation for more information about the arguments and return value.
     */
    public function write(fd:int, bufPtr:int, nbyte:int, errnoPtr:int):int {
        var str:String = CModule.readString(bufPtr, nbyte)
        printLine(str)
        return nbyte
    }

    /**
     * The PlayerKernel implementation will use this function to handle
     * C IO read requests to the file "/dev/tty" (e.g. reads from stdin
     * will expect this function to provide the data). See the ISpecialFile
     * documentation for more information about the arguments and return value.
     */
    public function read(fd:int, bufPtr:int, nbyte:int, errnoPtr:int):int {
        return 0
    }

    /**
     * The PlayerKernel implementation will use this function to handle
     * C fcntl requests to the file "/dev/tty"
     * See the ISpecialFile documentation for more information about the
     * arguments and return value.
     */
    public function fcntl(fd:int, com:int, data:int, errnoPtr:int):int {
        return 0
    }

    /**
     * The PlayerKernel implementation will use this function to handle
     * C ioctl requests to the file "/dev/tty"
     * See the ISpecialFile documentation for more information about the
     * arguments and return value.
     */
    public function ioctl(fd:int, com:int, data:int, errnoPtr:int):int {
        return 0
    }

    // HEX Helpers


    //----------------------------------
    //  Static methods
    //----------------------------------

    /**
     * Generates byte-array from given hexadecimal string
     *
     * Supports straight and colon-laced hex (that means 23:03:0e:f0, but *NOT* 23:3:e:f0)
     * The first nibble (hex digit) may be omitted.
     * Any whitespace characters are ignored.
     */
    public static function toArray(hex:String):ByteArray {
        hex = hex.replace(/^0x|\s|:/gm, '');
        var array:ByteArray = new ByteArray();
        if ((hex.length & 1) == 1)
            hex = "0" + hex;
        const n:uint = hex.length;
        for (var i:uint = 0; i < n; i += 2) {
            array[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return array;
    }

    /**
     * Generates lowercase hexadecimal string from given byte-array
     */
    public static function fromArray(array:ByteArray, colons:Boolean = false):String {
        var s:String = "";
        const n:uint = array.length;
        for (var i:uint = 0; i < n; i++) {
            s += ("0" + array[i].toString(16)).substr(-2, 2);
            if (colons && i < n - 1) {
                s += ":";
            }
        }
        return s;
    }

    /**
     * Generates string from given hexadecimal string
     */
    public static function toString(hex:String, charSet:String = 'utf-8'):String {
        var array:ByteArray = toArray(hex);
        return array.readMultiByte(array.length, charSet);
    }

    /**
     * Convenience method for generating string using iso-8859-1
     */
    public static function toRawString(hex:String):String {
        return toString(hex, 'iso-8859-1');
    }

    /**
     * Generates hexadecimal string from given string
     */
    public static function fromString(str:String, colons:Boolean = false, charSet:String = 'utf-8'):String {
        var array:ByteArray = new ByteArray;
        array.writeMultiByte(str, charSet);
        return fromArray(array, colons);
    }

    /**
     * Convenience method for generating hexadecimal string using iso-8859-1
     */
    public static function fromRawString(str:String, colons:Boolean = false):String {
        return fromString(str, colons, 'iso-8859-1');
    }

}
}
