<?php
/**
 * Secret credentials
 *
 * Some helping function to access the credentials of the identity provider. 
 * These can be used to verify own signed assertions or to sign identity certificates 
 * for principals.
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
 * @subpackage Secrets
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include Utils
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/utils.php");


/**
 * Include Configuration
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/configuration.php");

/**
 * Secret credentials
 *
 * Some helping function to access the credentials of the identity provider. 
 * These can be used to verify own signed assertions or to sign identity certificates 
 * for principals.
 *
 * @package     BrowserID
 * @subpackage  Secrets
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class Secrets {
    
    /**
     * Get the base name of the certificate to use if given or use the default 
     * name 'root'
     * 
     * @param optional string $name Name to use or null
     * @return string Name to use
     */
    static function checkName($name = null) {
        return $name ? $name : 'root';
    }

    /**
     * Get the directory where the certificates are stored or use the default 
     * path defined in the configuration as 'var_path'
     * 
     * @param optional string $dir Directory to use or null
     * @return string Directory to use
     */
    static function checkDir($dir = null) {
        $inst = Configuration::getInstance();
        return $dir ? $dir : Utils::path_concat($inst->get("base_path"), $inst->get("var_path"));
    }
    
    /**
     * Get the complete path to the secret key of the identity provider
     * 
     * @param optional string $name The basename of the certificate or null for default
     * @param optional string $dir The directory to the certificate or null for default
     * @return string The path to the secret key
     */
    static function getPathSecretKey($name = null, $dir = null) {
        $name = Secrets::checkName($name);
        $dir = Secrets::checkDir($dir);
        return Utils::path_concat($dir, $name . ".secretkey");
    }
    
    /**
     * Gets an instance of the secret key of the identity provider
     * 
     * @param optional string $name The basename of the certificate or null for default
     * @param optional string $dir The directory to the certificate or null for default
     * @return AbstractSecretKey The secret key
     */
    static function loadSecretKey($name = null, $dir = null) {
        $p = Secrets::getPathSecretKey($name, $dir);
        $secret = null;
        // may throw
        $secret = @file_get_contents($p);

        if (!$secret) {
            return null;
        }

        // parse it
        return AbstractSecretKey::deserialize($secret);
    }
    
    /**
     * Get the complete path to the public key of the identity provider
     * 
     * @param optional string $name The basename of the certificate or null for default
     * @param optional string $dir The directory to the certificate or null for default
     * @return string The path to the public key
     */
    static function getPathPublicKey($name = null, $dir = null) {
        $name = Secrets::checkName($name);
        $dir = Secrets::checkDir($dir);
        return Utils::path_concat($dir, $name . ".cert");
    }

    /**
     * Get the public key of the basic support document of the identity provider
     * 
     * @param optional string $name The basename of the certificate or null for default
     * @param optional string $dir The directory to the certificate or null for default
     * @return object An instance of the basic support document containing the public key or null
     */
    static function readAndParseCert($name = null, $dir = null) {
        $p = Secrets::getPathPublicKey($name, $dir);
        $cert = null;

        // may throw
        $cert = @file_get_contents($p);

        if (!$cert) {
            return null;
        }

        try {
            // parse it
            // it should be a JSON structure with alg and serialized key
            // {alg: <ALG>, value: <SERIALIZED_KEY>}
            $payloadSegment = WebToken::parse($cert)->getPayloadSegment();
            return json_decode(Utils::base64url_decode($payloadSegment), true);
        } catch (Exception $e) {
            return null;
        }
    }

    /**
     * Gets an instance of the public key of the identity provider
     * 
     * @param optional string $name The basename of the certificate or null for default
     * @param optional string $dir The directory to the certificate or null for default
     * @return AbstractPublicKey The public key
     */
    static function loadPublicKey($name = null, $dir = null) {
        $parsedCert = Secrets::readAndParseCert($name, $dir);
        if (!$parsedCert) return null;
        
        $pkString = $parsedCert["public-key"] ? $parsedCert["public-key"] : $parsedCert["publicKey"];
        return AbstractPublicKey::deserialize(json_encode($pkString));
    }
}
?>