<?php
/**
 * Utility library
 *
 * This class defines some static functions that are used through the project.
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
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
 * @package    BrowserID
 * @subpackage Utils
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Utility library
 *
 * @package     BrowserID
 * @subpackage  Utils
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class Utils {
    
    /**
     * Encodes data with MIME base64 and make it URL-safe
     * 
     * @param string    $data   The message to encode
     * @return string The encoded message
     */
    public static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decodes data made URL-safe and encoded with MIME base64
     * 
     * @param string    $data   The message to decode
     * @return string The decoded message
     */
    public static function base64url_decode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
    
    /**
     * Concat parts of a file path descriptor into a complete path
     * 
     * @return string
     */
    public static function path_concat()
    {
        return join(DIRECTORY_SEPARATOR, func_get_args());
    }
    
    /**
     * Checks if a given URL is valid
     * 
     * @param string $url URL to be verified
     * @return boolean true, if the URL is valid
     */
    public static function is_url_valid($url)
    {
        return preg_match('|^http(s)?://[a-z0-9-]+(.[a-z0-9-]+)*(:[0-9]+)?(/.*)?$|i', $url);
    }
    
    /**
     * Pads a hexadecimal string with 0s to the left
     * 
     * @param string $str Hexadecimal number to be padded
     * @param int $length The length of the final hexadecimal number
     * @return string 
     */
    public static function hex_lpad($str, $length) {
        while (strlen($str) < $length) {
            $str = "0" . $str;
        }
        return $str;
    }
}

?>