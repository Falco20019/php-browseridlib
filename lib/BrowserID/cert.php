<?php
/**
 * Certificate
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
 * @subpackage Cert
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include WebToken
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/web_token.php");

/**
 * Include Assertion
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/assertion.php");

/**
 * Include CertParams
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/cert_params.php");

/**
 * Certificate
 * 
 * Represents an identity certificate.
 *
 * @package     BrowserID
 * @subpackage  Cert
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class Cert {
    
    /**
     * Additional payload
     * 
     * @access private
     * @var array
     */
    private $payload;
    
    /**
     * Assertion parameters
     * 
     * @access private
     * @var Assertion
     */
    private $assertion;
    
    /**
     * Certificate parameters
     * 
     * @access private
     * @var CertParams
     */
    private $certParams;
    
    /**
     * Constructor
     * 
     * @access public
     * @param Assertion $assertion The assertion parameters
     * @param CertParams $certParams The certificate parameters
     * @param type $payload 
     */
    public function __construct($assertion, $certParams, $payload)
    {
        $this->assertion = $assertion;
        $this->certParams = $certParams;
        $this->payload = $payload;
    }
    
    /**
     * Serialize parameters
     * 
     * Serializes the objects parameters into an array.
     * 
     * @param array $params An array of parameters, existing ones will be overwritten
     * @return array The combined params array
     */
    public function serialize($params = null) {
        if ($params == null)
            $params = array();
        
        $this->payload = $params;
        $this->assertion->serialize(&$params);
        $this->certParams->serialize(&$params);
        
        return $params;
    }
    
    /**
     * Deserialize parameters
     * 
     * Creates an instance based on the parameter object. The used parameters will be removed from params.
     * 
     * @param array $params An array of parameters, used ones will be removed
     * @return Cert An instance of a certificate
     */
    public static function deserialize($params) {
        $assertion = Assertion::deserialize($params);
        $certParams = CertParams::deserialize($params);
        return new Cert($assertion, $certParams, $params);
    }
    
    /**
     * Additional payload
     * 
     * Gets the additional payload.
     * 
     * @access public
     * @return array 
     */
    public function getPayload(){
        return $this->payload;
    }
    
    /**
     * Assertion parameters
     * 
     * Gets the assertion parameters.
     * 
     * @access public
     * @return Assertion
     */
    public function getAssertion() {
        return $this->assertion;
    }
    
    /**
     * Certificate parameters
     * 
     * Gets the certificate parameters.
     * 
     * @access public
     * @return CertParams
     */
    public function getCertParams() {
        return $this->certParams;
    }
    
    /**
     * Parse serialized identity certificate
     * 
     * Parses a serialized, signed identity certificate and check if it's valid by 
     * checking the signature against the public key of the issuer.
     * 
     * @access public
     * @static
     * @param string $signedObject Signed identity certificate
     * @param AbstractPublicKey $publicKey Public key of the issuer
     * @return Cert Instance of the identity certificate
     */
    public static function parse($signedObject, $publicKey)
    {
        $token = WebToken::parse($signedObject);
        if (!$token->verify($publicKey))
            throw new Exception("cert was not valid signed");

        $params = $token->getPayload();
        return Cert::deserialize($params);
    }
    
    /**
     * Sign identity certificate
     * 
     * Sign and serialize this instance using the secret key of the issuer.
     * 
     * @access public
     * @param AbstractSecretKey $secretKey Secret key of the issuer
     * @param array $additionalPayload Additional payload or null if none to add
     * @return string Serialized identity certificate
     */
    public function sign($secretKey, $additionalPayload = null) {
        $payload = array();
        if ($additionalPayload !== null)
            $payload = array_merge($additionalPayload, $payload);
        $this->serialize(&$payload);
        
        return $this->assertion->sign($secretKey, $payload);
    }
    
    /**
     * Verify
     * 
     * Checks if the parameters are valid.
     * 
     * @access public
     * @param int $now Unix timestamp in milliseconds
     * @return boolean true, if the instance is valid
     */
    public function verify($now) {
        if (!$this->assertion->verify($now))
            throw new Exception("cert assertion is not valid");
        
        if (!$this->certParams->verify($now))
            throw new Exception("cert params are not valid");

        return true;
    }
}
?>
