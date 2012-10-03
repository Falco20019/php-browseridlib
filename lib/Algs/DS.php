<?php
/**
 * DSA-SHA Hashing Interface
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
 * @subpackage DS
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include Utils
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/utils.php");

/**
 * Include Crypt_DSA
 */
require_once(BROWSERID_BASE_PATH."lib/Crypt/DSA.php");

/**
 * Include BigInteger
 */
require_once(BROWSERID_BASE_PATH."lib/Math/BigInteger.php");

/**
 * DSA key pair
 * 
 * A pair of DSA keys.
 *
 * @package     Algs
 * @subpackage  DS
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class DSAKeyPair extends AbstractKeyPair {
    /**
     * Is initialized
     * 
     * @access private
     * @static
     * @var type 
     */
    private static $isInitialized = false;
    
    /**
     * Big Integer zero
     * 
     * @access public
     * @static
     * @var type 
     */
    public static $zero;
    
    /**
     * Allowed keysizes
     * 
     * @access public
     * @static
     * @var array
     */
    public static $KEYSIZES = array(
        // 160 is the keysize for standard DSA
        // the following are based on the first FIPS186-3 test vectors for 1024/160 SHA-256
        // under the category A.2.3 Verifiable Canonical Generation of the Generator g
        // HOWEVER***** for backwards compatibility we are labeling this 128 for now
        // XXXX this should be changed to 160
        128 => array(
            "p" => "ff600483db6abfc5b45eab78594b3533d550d9f1bf2a992a7a8daa6dc34f8045ad4e6e0c429d334eeeaaefd7e23d4810be00e4cc1492cba325ba81ff2d5a5b305a8d17eb3bf4a06a349d392e00d329744a5179380344e82a18c47933438f891e22aeef812d69c8f75e326cb70ea000c3f776dfdbd604638c2ef717fc26d02e17",
            "q" => "e21e04f911d1ed7991008ecaab3bf775984309c3",
            "g" => "c52a4a0ff3b7e61fdf1867ce84138369a6154f4afa92966e3c827e25cfa6cf508b90e5de419e1337e07a2e9e2a3cd5dea704d175f8ebf6af397d69e110b96afb17c7a03259329e4829b0d03bbc7896b15b4ade53e130858cc34d96269aa89041f409136c7242a38895c9d5bccad4f389af1d7a4bd1398bd072dffa896233397a",
            "hashAlg" => "sha1"
        ),
        // the following are based on the first FIPS186-3 test vectors for 2048/256 SHA-256
        // under the category A.2.3 Verifiable Canonical Generation of the Generator g
        256 => array(
            "p" => "d6c4e5045697756c7a312d02c2289c25d40f9954261f7b5876214b6df109c738b76226b199bb7e33f8fc7ac1dcc316e1e7c78973951bfc6ff2e00cc987cd76fcfb0b8c0096b0b460fffac960ca4136c28f4bfb580de47cf7e7934c3985e3b3d943b77f06ef2af3ac3494fc3c6fc49810a63853862a02bb1c824a01b7fc688e4028527a58ad58c9d512922660db5d505bc263af293bc93bcd6d885a157579d7f52952236dd9d06a4fc3bc2247d21f1a70f5848eb0176513537c983f5a36737f01f82b44546e8e7f0fabc457e3de1d9c5dba96965b10a2a0580b0ad0f88179e10066107fb74314a07e6745863bc797b7002ebec0b000a98eb697414709ac17b401",
            "q" => "b1e370f6472c8754ccd75e99666ec8ef1fd748b748bbbc08503d82ce8055ab3b",
            "g" => "9a8269ab2e3b733a5242179d8f8ddb17ff93297d9eab00376db211a22b19c854dfa80166df2132cbc51fb224b0904abb22da2c7b7850f782124cb575b116f41ea7c4fc75b1d77525204cd7c23a15999004c23cdeb72359ee74e886a1dde7855ae05fe847447d0a68059002c3819a75dc7dcbb30e39efac36e07e2c404b7ca98b263b25fa314ba93c0625718bd489cea6d04ba4b0b7f156eeb4c56c44b50e4fb5bce9d7ae0d55b379225feb0214a04bed72f33e0664d290e7c840df3e2abb5e48189fa4e90646f1867db289c6560476799f7be8420a6dc01d078de437f280fff2d7ddf1248d56e1a54b933a41629d6c252983c58795105802d30d7bcd819cf6ef",
            "hashAlg" => "sha256"
        )
    );
    
    /**
     * Initialization routine
     * 
     * @access public
     * @static
     */
    public static function initialize()
    {
        if (self::$isInitialized)
            return;
        
        $zero = new Math_BigInteger();
        
        // turn the keysize params to bigints
        foreach(DSAKeyPair::$KEYSIZES as $keysize => $entry) {
            $params = &DSAKeyPair::$KEYSIZES[$keysize];
            $params["p"] = new Math_BigInteger($params["p"], 16);
            $params["q"] = new Math_BigInteger($params["q"], 16);
            $params["g"] = new Math_BigInteger($params["g"], 16);
            
            // sizes
            $params["q_bitlength"] = strlen($params["q"]->toBits());
        }
        
        self::$isInitialized = true;
    }
    
    /**
     * Get keysize
     * 
     * Gets the keysize depending on the bit count of the rsa key.
     * 
     * @access public
     * @statis
     * @param int $size Amount of bits
     * @return int Keysize
     */
    public static function _getKeySizeFromRSAKeySize($size) {
        foreach(DSAKeyPair::$KEYSIZES as $keysize => $entry) {
            $keysize_nbits = strlen($entry["p"]->toBits());
            $diff = $keysize_nbits - $size;

            // extremely unlikely to be more than 30 bits smaller than p
            // 2^-30. FIXME: should we be more tolerant here.
            if ($diff >= 0 && $diff < 30) {
                return $keysize;
            }
        }

        return null;
    }
    
    /**
     * @see AbstractKeyPair::createPublicKey();
     */
    public function createPublicKey()
    {
        return new DSAPublicKey();
    }
    
    /**
     * @see AbstractKeyPair::createSecretKey();
     */
    public function createSecretKey()
    {
        return new DSASecretKey();
    }

    /**
     * @see AbstractKeyPair::generate($keysize);
     */
    public static function generate($keysize) {
        if (!isset(self::$KEYSIZES[$keysize]))
            throw new NoSuchAlgorithmException("keysize not supported");
        
        $static_keys = self::$KEYSIZES[$keysize];
        $instance = new DSAKeyPair();
        $keys = Crypt_DSA::generate($static_keys["p"], $static_keys["q"], $static_keys["g"]);
        $instance->keysize = $keysize;
        
        $instance->secretKey = new DSASecretKey($keys["x"], $keysize);
        $instance->publicKey = new DSAPublicKey($keys["y"], $keysize);
        
        $instance->algorithm = $instance->publicKey->algorithm = $instance->secretKey->algorithm = "DS";
        return $instance;
    }
}

/**
 * DSA public key
 * 
 * A public key using the DSA algorithm.
 *
 * @package     Algs
 * @subpackage  DS
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class DSAPublicKey extends AbstractPublicKey {
    
    /**
     * Public key
     * 
     * @access private
     * @var Math_BigInteger
     */
    private $key_y;
    
    /**
     * Prime p
     * 
     * @access private
     * @var Math_BigInteger
     */
    private $key_p;
    
    /**
     * Prime q
     * 
     * @access private
     * @var Math_BigInteger
     */
    private $key_q;
    
    /**
     * Group g
     * 
     * @access private
     * @var Math_BigInteger
     */
    private $key_g;
    
    /**
     * Constructor
     * 
     * @access public
     * @param Math_BigInteger $key Public key as number
     * @param type $keysize 
     */
    public function __construct($key = null, $keysize = null)
    {
        $this->key_y = $key;
        if ($keysize != null)
        {
            $key_values = DSAKeyPair::$KEYSIZES[$keysize];
            $this->key_p = $key_values["p"];
            $this->key_q = $key_values["q"];
            $this->key_g = $key_values["g"];
            $this->keysize = $keysize;
        }
    }

    /**
     * @see AbstractKeyInstance::deserializeFromObject($obj)
     */
    protected function deserializeFromObject($obj)
    {
        $this->key_p = new Math_BigInteger($obj["p"], 16);
        $this->key_q = new Math_BigInteger($obj["q"], 16);
        $this->key_g = new Math_BigInteger($obj["g"], 16);
        $this->key_y = new Math_BigInteger($obj["y"], 16);
        $this->keysize = DSAKeyPair::_getKeySizeFromRSAKeySize(strlen($this->key_y->toBits()));
        $this->key_values = DSAKeyPair::$KEYSIZES[$this->keysize];
        return $this;
    }
    
    /**
     * @see AbstractKeyInstance::serializeToObject($obj)
     */
    protected function serializeToObject(&$obj){
        $obj["p"] = $this->key_p->toHex();
        $obj["q"] = $this->key_q->toHex();
        $obj["g"] = $this->key_g->toHex();
        $obj["y"] = $this->key_y->toHex();
    }
    
    /**
     * @see AbstractPublicKey::verify($message, $signature)
     */
    public function verify($message, $signature)
    {
        $params = DSAKeyPair::$KEYSIZES[$this->keysize];
        $hash_alg = $params["hashAlg"];
        $hexlength = $params["q_bitlength"] / 4;
        
        // we pre-pad with 0s because encoding may have gotten rid of some
        $signature = Utils::hex_lpad(bin2hex($signature), $hexlength * 2);
        
        // now this should only happen if the signature was longer
        if (strlen($signature) != ($hexlength * 2)) {
            throw new AlgorithmException("problem with r/s combo: " . sizeof($signature) . "/" . $hexlength . " - " . $signature);
        }
        
        $r = new Math_BigInteger(substr($signature, 0, $hexlength), 16);
        $s = new Math_BigInteger(substr($signature, $hexlength, $hexlength), 16);

        // check rangeconstraints
        if (($r->compare(DSAKeyPair::$zero) < 0) || ($r->compare($this->key_q) > 0)) {
            throw new AlgorithmException("problem with r: " . $r->toString());
        }
        
        if (($s->compare(DSAKeyPair::$zero) < 0) || ($s->compare($this->key_q) > 0)) {
            throw new AlgorithmException("problem with s: " . $r->toString());
        }
        
        return Crypt_DSA::verify($message, $hash_alg, $r, $s, $this->key_p, $this->key_q, $this->key_g, $this->key_y);
    }
}

/**
 * DSA secret key
 * 
 * A secret key using the DSA algorithm.
 *
 * @package     Algs
 * @subpackage  DS
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class DSASecretKey extends AbstractSecretKey {
    
    /**
     * Secret key
     * 
     * @access private
     * @var Math_BigInteger
     */
    private $key_x;
    
    /**
     * Prime p
     * 
     * @access private
     * @var Math_BigInteger
     */
    private $key_p;
    
    /**
     * Prime q
     * 
     * @access private
     * @var Math_BigInteger
     */
    private $key_q;
    
    /**
     * Group g
     * 
     * @access private
     * @var Math_BigInteger
     */
    private $key_g;
    
    /**
     * Constructor
     * 
     * @access public
     * @param Math_BigInteger $key Secret key as number
     * @param type $keysize 
     */
    public function __construct($key = null, $keysize = null)
    {
        $this->key_x = $key;
        if ($keysize != null)
        {
            $key_values = DSAKeyPair::$KEYSIZES[$keysize];
            $this->key_p = $key_values["p"];
            $this->key_q = $key_values["q"];
            $this->key_g = $key_values["g"];
            $this->keysize = $keysize;
        }
    }

    /**
     * @see AbstractKeyInstance::deserializeFromObject($obj)
     */
    protected function deserializeFromObject($obj)
    {
        $this->key_p = new Math_BigInteger($obj["p"], 16);
        $this->key_q = new Math_BigInteger($obj["q"], 16);
        $this->key_g = new Math_BigInteger($obj["g"], 16);
        $this->key_x = new Math_BigInteger($obj["x"], 16);
        $this->keysize = DSAKeyPair::_getKeySizeFromRSAKeySize(strlen($this->key_p->toBits()));
        return $this;
    }
    
    /**
     * @see AbstractKeyInstance::serializeToObject($obj)
     */
    protected function serializeToObject(&$obj){
        $obj["p"] = $this->key_p->toHex();
        $obj["q"] = $this->key_q->toHex();
        $obj["g"] = $this->key_g->toHex();
        $obj["x"] = $this->key_x->toHex();
    }
    
    /**
     * @see AbstractSecretKey::sign($message)
     */
    public function sign($message)
    {
        $params = DSAKeyPair::$KEYSIZES[$this->keysize];
        $hash_alg = $params["hashAlg"];
        $hexlength = $params["q_bitlength"] / 4;
        
        $keys = Crypt_DSA::sign($message, $hash_alg, $this->key_p, $this->key_q, $this->key_g, $this->key_x);
        $signature = Utils::hex_lpad($keys["r"]->toHex(), $hexlength) . Utils::hex_lpad($keys["s"]->toHex(), $hexlength);
        return pack("H*" , $signature);
    }
}

DSAKeyPair::initialize();
?>