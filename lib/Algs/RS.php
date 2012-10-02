<?php
/**
 * RSA-SHA Hashing Interface
 * 
 * Offers methods for signing and verifiying data using RSA-SHA
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
 * @package    Algs
 * @subpackage RS
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include Crypt_RSA
 */
require_once(BROWSERID_BASE_PATH."lib/Crypt/RSA.php");

/**
 * Include BigInteger
 */
require_once(BROWSERID_BASE_PATH."lib/Math/BigInteger.php");

/**
 * RSA key pair
 * 
 * A pair of RSA keys.
 *
 * @package     Algs
 * @subpackage  RS
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class RSAKeyPair extends AbstractKeyPair {
    
    /**
     * Allowed keysizes
     * 
     * @access public
     * @static
     * @var array
     */
    public static $KEYSIZES = array(
        64 => array(
            "rsaKeySize" => 512,
            "hashAlg" => "sha1" // sha256 is not working, encoding error
        ),
        128 => array(
            "rsaKeySize" => 1024,
            "hashAlg" => "sha256"
        ),
        256 => array(
            "rsaKeySize" => 2048,
            "hashAlg" => "sha256"
        )
    );

    /**
     * RSA instance
     * 
     * @access private
     * @var Crypt_RSA
     */
    private $rsa;
    
    /**
     * Get keysize
     * 
     * Gets the keysize depending on the bit count of the rsa key.
     * 
     * @access public
     * @statis
     * @param int $bits Amount of bits
     * @return int Keysize
     */
    public static function _getKeySizeFromRSAKeySize($bits) {
        foreach(RSAKeyPair::$KEYSIZES as $keysize => $entry) {
            // we tolerate one bit off from the keysize
            if (abs($entry["rsaKeySize"]-$bits) <= 1)
                return $keysize;
        }

        throw new Exception("bad key");
    }
    
    /**
     * @see AbstractKeyPair::createPublicKey();
     */
    public function createPublicKey()
    {
        return new RSAPublicKey();
    }
    
    /**
     * @see AbstractKeyPair::createSecretKey();
     */
    public function createSecretKey()
    {
        return new RSASecretKey();
    }

    /**
     * @see AbstractKeyPair::generate($keysize);
     */
    public static function generate($keysize) {
        if (!isset(self::$KEYSIZES[$keysize]))
            throw new NoSuchAlgorithmException("keysize not supported");
        
        $instance = new RSAKeyPair();
        $instance->rsa = new Crypt_RSA();
        $instance->rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
        $instance->rsa->setHash(self::$KEYSIZES[$keysize]["hashAlg"]);
        $keys = $instance->rsa->createKey(self::$KEYSIZES[$keysize]["rsaKeySize"]);
        $instance->keysize = $keysize;
        
        $instance->publicKey = new RSAPublicKey($keys["publickey"], $keysize);
        $instance->secretKey = new RSASecretKey($keys["privatekey"], $keysize);
        
        $instance->algorithm = $instance->publicKey->algorithm = $instance->secretKey->algorithm = "RS";
        return $instance;
    }
}

/**
 * RSA public key
 * 
 * A public key using the RSA algorithm.
 *
 * @package     Algs
 * @subpackage  RS
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class RSAPublicKey extends AbstractPublicKey {
    
    /**
     * RSA instance
     * 
     * @access private
     * @var Crypt_RSA
     */
    private $rsa;
    
    /**
     * Constructor
     * 
     * @access public
     * @param string $key Public key in PKCS#1 or raw format
     * @param type $keysize 
     */
    public function __construct($key = null, $keysize = null)
    {
        $this->rsa = new Crypt_RSA();
        $this->rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
        if ($key != null)
        {
            $this->rsa->loadKey($key);
            $this->rsa->setPublicKey($key);
            if ($keysize != null)
            {
                $this->rsa->setHash(RSAKeyPair::$KEYSIZES[$keysize]["hashAlg"]);
                $this->keysize = $keysize;
            }
        }
    }

    /**
     * @see AbstractKeyInstance::deserializeFromObject($obj)
     */
    protected function deserializeFromObject($obj)
    {
        $n = new Math_BigInteger($obj["n"]);
        $e = new Math_BigInteger($obj["e"]);
        $array = array(
            "n" => $n,
            "e" => $e
        );
        $this->rsa->loadKey($array, CRYPT_RSA_PUBLIC_FORMAT_RAW);
        $this->rsa->setPublicKey($array, CRYPT_RSA_PUBLIC_FORMAT_RAW);
        $this->keysize = RSAKeyPair::_getKeySizeFromRSAKeySize(strlen($n->toBits()));
        $this->rsa->setHash(RSAKeyPair::$KEYSIZES[$this->keysize]["hashAlg"]);
        return $this;
    }
    
    /**
     * @see AbstractKeyInstance::serializeToObject($obj)
     */
    protected function serializeToObject(&$obj){
        $key = $this->rsa->getPublicKey(CRYPT_RSA_PUBLIC_FORMAT_RAW);
        $obj["n"] = $key["n"]->toString();
        $obj["e"] = $key["e"]->toString();
    }
    
    /**
     * @see AbstractPublicKey::verify($message, $signature)
     */
    public function verify($message, $signature)
    {
        return $this->rsa->verify($message, $signature);
    }
}

/**
 * RSA secret key
 * 
 * A secret key using the RSA algorithm.
 *
 * @package     Algs
 * @subpackage  RS
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class RSASecretKey extends AbstractSecretKey {
    
    /**
     * RSA instance
     * 
     * @access private
     * @var Crypt_RSA
     */
    private $rsa;
    
    /**
     * Constructor
     * 
     * @access public
     * @param string $key Secret key in PKCS#1 or raw format
     * @param type $keysize 
     */
    public function __construct($key = null, $keysize = null)
    {
        $this->rsa = new Crypt_RSA();
        $this->rsa->setSignatureMode(CRYPT_RSA_SIGNATURE_PKCS1);
        if ($key != null)
        {
            $this->rsa->loadKey($key);
            $this->rsa->setPrivateKey($key);
            if ($keysize != null)
            {
                $this->rsa->setHash(RSAKeyPair::$KEYSIZES[$keysize]["hashAlg"]);
                $this->keysize = $keysize;
            }
        }
    }

    /**
     * @see AbstractKeyInstance::deserializeFromObject($obj)
     */
    protected function deserializeFromObject($obj)
    {
        $n = new Math_BigInteger($obj["n"]);
        $e = new Math_BigInteger($obj["e"]);
        $d = new Math_BigInteger($obj["d"]);
        $array = array(
            "n" => $n,
            "e" => $e,
            "d" => $d
        );
        $this->rsa->loadKey($array, CRYPT_RSA_PUBLIC_FORMAT_RAW);
        $this->rsa->setPrivateKey($array, CRYPT_RSA_PUBLIC_FORMAT_RAW);
        $this->keysize = RSAKeyPair::_getKeySizeFromRSAKeySize(strlen($n->toBits()));
        $this->rsa->setHash(RSAKeyPair::$KEYSIZES[$this->keysize]["hashAlg"]);
        return $this;
    }
    
    /**
     * @see AbstractKeyInstance::serializeToObject($obj)
     */
    protected function serializeToObject(&$obj){
        $key = $this->rsa->getPrivateKey();
        $obj["n"] = $key["n"]->toString();
        $obj["e"] = $key["e"]->toString();
        $obj["d"] = $key["d"]->toString();
    }
    
    /**
     * @see AbstractSecretKey::sign($message)
     */
    public function sign($message)
    {
        return $this->rsa->sign($message);
    }
}
?>