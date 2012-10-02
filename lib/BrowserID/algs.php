<?php
/**
 * Algorithms
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
 * @subpackage Algs
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include RSA Algorithm
 */
require_once(BROWSERID_BASE_PATH."lib/Algs/RS.php");

/**
 * Include DSA Algorithm
 */
require_once(BROWSERID_BASE_PATH."lib/Algs/DS.php");

/**
 * Implemented Algorithms
 */
$GLOBALS["ALGS"] = array(
    "RS" => new RSAKeyPair(),
    "DS" => new DSAKeyPair()
);

/**
 * Abstract key
 * 
 * A base class for all keys.
 *
 * @abstract
 * @package     BrowserID
 * @subpackage  Algs
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
abstract class AbstractKey {
    
    /**
     * Algorithm
     * 
     * @access protected
     * @var string
     */
    protected $algorithm;
    
    /**
     * Keysize
     * 
     * @access protected
     * @var int
     */
    protected $keysize;

    /**
     * Algorithm
     * 
     * Gets the algorithm identifier as used in the web tokens header.
     * 
     * @access public
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->algorithm . $this->keysize;
    }
}

/**
 * Abstract key pair
 * 
 * A base class for all key pairs.
 *
 * @abstract
 * @package     BrowserID
 * @subpackage  Algs
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
abstract class AbstractKeyPair extends AbstractKey {
    
    /**
     * Public key
     * 
     * @access protected
     * @var AbstractPublicKey
     */
    protected $publicKey;
    
    /**
     * Secret key
     * 
     * @access protected
     * @var AbstractSecretKey
     */
    protected $secretKey;
    
    /**
     * Generate keypair
     * 
     * Generates a keypair for a given keysize in bits
     * 
     * @abstract
     * @access public
     * @static
     * @param int $keysize Keysize in bits
     * @return AbstractKeyPair Returning an instance of the key pair
     */
    abstract public static function generate($keysize);
    
    /**
     * Creates public key
     * 
     * Creates a public key using the algorithm of the extended class.
     * 
     * @abstract
     * @access public
     * @return AbstractPublicKey
     */
    abstract public function createPublicKey();
    
    /**
     * Creates secret key
     * 
     * Creates a secret key using the algorithm of the extended class.
     * 
     * @abstract
     * @access public
     * @return AbstractSecretKey
     */
    abstract public function createSecretKey();
    
    /**
     * Get public key
     * 
     * Gets the public key of this key pair.
     * 
     * @access public
     * @return AbstractPublicKey
     */
    public function getPublicKey()
    {
        return $this->publicKey;
    }
    
    /**
     * Get secret key
     * 
     * Gets the secret key of this key pair.
     * 
     * @access public
     * @return AbstractSecretKey
     */
    public function getSecretKey()
    {
        return $this->secretKey;
    }
}

/**
 * Abstract key instance
 * 
 * A base class for all instanciated keys.
 *
 * @abstract
 * @package     BrowserID
 * @subpackage  Algs
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
abstract class AbstractKeyInstance extends AbstractKey {
    
    /**
     * Deserialize from object
     * 
     * Deserialize parameters from the parameter object depending on the algorithmic specific implementation.
     * 
     * @abstract
     * @access protected
     * @params array $obj Array of algorithmic specific parameters
     * @return AbstractKeyInstance 
     */
    abstract protected function deserializeFromObject($obj);
    
    /**
     * Serialize to object
     * 
     * Serializes parameters of the instance depending on the algorithmic specific 
     * implementation into the parameter object.
     * 
     * @abstract
     * @access protected
     * @params array $obj Array of algorithmic specific parameters
     */
    abstract protected function serializeToObject(&$obj);
    
    /**
     * Unflatten key
     * 
     * Creates an key instance from the parameters.
     * 
     * @abstract
     * @access public
     * @static
     * @param array $obj Parameters of the key
     * @return AbstractKeyInstance
     */
    abstract public static function fromSimpleObject($obj);
    
    /**
     * Deserialize key
     * 
     * Deserializes the key.
     * 
     * @abstract
     * @access public
     * @static
     * @param string $str Serialized parmeters of the key
     * @return AbstractKeyInstance
     */
    abstract public static function deserialize($str);
    
    /**
     * Flatten key
     * 
     * Extracts the parameters of the key.
     * 
     * @access public
     * @return array 
     */
    public function toSimpleObject()
    {
        $obj = array("algorithm" => $this->algorithm);
        $this->serializeToObject($obj);
        return $obj;
    }
    
    /**
     * Serialize key
     * 
     * Serializes the key.
     * 
     * @access public
     * @return string
     */
    public function serialize()
    {
        return json_encode($this->toSimpleObject());
    }
}

/**
 * Abstract public key
 * 
 * A base class for all public keys.
 *
 * @abstract
 * @package     BrowserID
 * @subpackage  Algs
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
abstract class AbstractPublicKey extends AbstractKeyInstance {
    /**
     * Verify message
     * 
     * Verifies a message using a signature.
     * 
     * @abstract
     * @access public
     * @param string $message The message to be verified
     * @param string $signature The signature to be validated
     * @return boolean
     */
    abstract public function verify($message, $signature);
    
    /**
     * @see AbstractKeyInstance::fromSimpleObject($obj)
     */
    public static function fromSimpleObject($obj) {
        if (!isset($GLOBALS["ALGS"][$obj["algorithm"]]))
          throw new NotImplementedException("no such algorithm: " . $obj["algorithm"]);

        $publicKey = $GLOBALS["ALGS"][$obj["algorithm"]]->createPublicKey();
        $publicKey->algorithm = $obj["algorithm"];
        $publicKey->deserializeFromObject($obj);
        return $publicKey;
    }
    
    /**
     * @see AbstractKeyInstance::deserialize($str)
     */
    public static function deserialize($str) {
        return AbstractPublicKey::fromSimpleObject(json_decode($str, true));
    }
}

/**
 * Abstract secret key
 * 
 * A base class for all secret keys.
 *
 * @abstract
 * @package     BrowserID
 * @subpackage  Algs
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
abstract class AbstractSecretKey extends AbstractKeyInstance {
    /**
     * Sign message
     * 
     * Generate a signature for the message.
     * 
     * @abstract
     * @access public
     * @param string $message The message
     * @return string The signature
     */
    abstract public function sign($message);
    
    /**
     * @see AbstractKeyInstance::fromSimpleObject($obj)
     */
    public static function fromSimpleObject($obj) {
        if (!isset($GLOBALS["ALGS"][$obj["algorithm"]]))
          throw new NotImplementedException("no such algorithm: " . $obj["algorithm"]);

        $secretKey = $GLOBALS["ALGS"][$obj["algorithm"]]->createSecretKey();
        $secretKey->algorithm = $obj["algorithm"];
        $secretKey->deserializeFromObject($obj);
        return $secretKey;
    }
    
    /**
     * @see AbstractKeyInstance::deserialize($str)
     */
    public static function deserialize($str) {
        return AbstractSecretKey::fromSimpleObject(json_decode($str, true));
    }
}

/**
 * Algorithmic exception
 * 
 * The algorithm was not executable
 *
 * @abstract
 * @package     BrowserID
 * @subpackage  Algs
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class AlgorithmException extends Exception { }
?>