<?php
/**
 * JSON Web Token implementation
 *
 * Implementation of the JWT protocol based on:
 * http://self-issued.info/docs/draft-jones-json-web-token-01.html
 * 
 * This code is also based on the scripts found at jwcryptos's github repository:
 * https://github.com/mozilla/jwcrypto/blob/master/lib/jwcrypto.js
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
 * @subpackage WebToken
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include Utils
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/utils.php");

/**
 * JSON Web Token implementation
 *
 * Implementation of the JWT protocol based on:
 * http://self-issued.info/docs/draft-jones-json-web-token-01.html
 *
 * @package     BrowserID
 * @subpackage  WebToken
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class WebToken {
    
    /**
     * The header segment of the web token on parsing
     * 
     * @access private
     * @var array A list of header entries (like the algorithm)
     */
    private $headerSegment;
    
    /**
     * The payload that was signed
     * 
     * @access private
     * @var string The data
     */
    private $payloadSegment;
    
    /**
     * The signature generated from the payload using the algorithm
     * given in the header
     * 
     * @access private
     * @var string The signature
     */
    private $cryptoSegment;

    /**
     * Constructor
     * 
     * @access public
     * @param string $object The data to be signed
     */
    public function __construct($object="") {
        $this->payloadSegment = Utils::base64url_encode(json_encode($object));
    }

    /**
     * Parse serialized JWT data
     * 
     * Generate a Webtoken object for parsing JWT data.
     * 
     * @access public
     * @static
     * @param string $input The JSON Web Token
     * @return WebToken A Webtoken instance for verification
     */
    public static function parse($input) {
        $parts = explode(".", $input);
        if (sizeof($parts) != 3)
            throw new MalformedWebTokenException("signed object must have three parts, this one has " . sizeof($parts));

        $token = new WebToken();
        $token->headerSegment = $parts[0];
        $token->payloadSegment = $parts[1];
        $token->cryptoSegment = $parts[2];
        return $token;
    }

    /**
     * Serialize web token
     * 
     * Serializes data as JWT using the defined algorithm and data and signed
     * with the key.
     * 
     * @access public
     * @param string $key The key used for hashing
     * @return string Serialized web token
     */
    public function serialize($key) {
        $header = array("alg" => $key->getAlgorithm());
        $this->headerSegment = Utils::base64url_encode(json_encode($header));
        
        $stringToSign = $this->headerSegment . "." . $this->payloadSegment;
        $signatureValue = Utils::base64url_encode($key->sign($stringToSign));
        $this->cryptoSegment = $signatureValue;
        
        return $stringToSign . "." . $signatureValue;
    }

    /**
     * Verify web token
     * 
     * Verifies a Webtoken against an public key.
     * 
     * @param AbstractPublicKey $key The key used to verify the webtoken
     * @return bool true, if the webtoken is valid
     */
    public function verify($key) {
        return $key->verify($this->headerSegment . "." . $this->payloadSegment, $this->getSignature());
    }
    
    /**
     * Header data
     * 
     * Returns the data of the token header, normally containing the algorithm used.
     * 
     * @access public
     * @return object An object of header data
     */
    public function getHeader()
    {
        if ($this->headerSegment == null)
            return null;
        
        return json_decode(Utils::base64url_decode($this->headerSegment), true);
    }
    
    /**
     * Header segment
     * 
     * Returns the serialized header segment of the token.
     * 
     * @access public
     * @return string
     */
    public function getHeaderSegment()
    {
        return $this->headerSegment;
    }
    
    /**
     * Payload data
     * 
     * Returns the payload of the token that was to be serialized and signed.
     * 
     * @return object An object of payload data
     */
    public function getPayload()
    {
        if ($this->payloadSegment == null)
            return null;
        
        return json_decode(Utils::base64url_decode($this->payloadSegment), true);
    }
    
    /**
     * Payload segment
     * 
     * Returns the serialized payload segment of the token.
     * 
     * @access public
     * @return string
     */
    public function getPayloadSegment()
    {
        return $this->payloadSegment;
    }
    
    /**
     * Signature
     * 
     * Returns the signature of the token as binary data.
     * 
     * @return string The signature as binary data
     */
    public function getSignature()
    {
        if ($this->cryptoSegment == null)
            return null;
        
        return Utils::base64url_decode($this->cryptoSegment);
    }
    
    /**
     * Crypto segment
     * 
     * Returns the serialized crypto segment of the token.
     * 
     * @access public
     * @return string
     */
    public function getCryptoSegment()
    {
        return $this->cryptoSegment;
    }
}

/**
 * Malformed webtoken
 * 
 * The webtoken is not well-formed
 * 
 * @package     BrowserID
 * @subpackage  WebToken
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class MalformedWebTokenException extends Exception {

    /**
     * @access public
     * @param string    $message    The error message
     * @param int       $code       An error code
     */
    public function __construct($message, $code = 0) {
        parent::__construct("Malformed JSON web token: " . $message, $code);
    }

}
?>