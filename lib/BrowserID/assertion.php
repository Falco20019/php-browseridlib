<?php
/**
 * BrowserID assertion implementation
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
 * @subpackage Assertion
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include WebToken
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/web_token.php");

/**
 * Assertion
 *
 * @package     BrowserID
 * @subpackage  Assertion
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class Assertion {
    
    /**
     * Issued at
     * 
     * @access private
     * @var int Unix timestamp in milliseconds
     */
    private $issuedAt;
    
    /**
     * Expires at
     * 
     * @access private
     * @var int Unix timestamp in milliseconds
     */
    private $expiresAt;
    
    /**
     * Issuer
     * 
     * The domain of the issuing identity provider
     * 
     * @access private
     * @var string
     */
    private $issuer;
    
    /**
     * Audience
     * 
     * The audience this assertion is valid for
     * 
     * @access private
     * @var string
     */
    private $audience;
    
    /**
     * Constructor
     * 
     * @access public
     * @param int $iat Issued at
     * @param int $exp Expires at
     * @param string $iss Issuer
     * @param string $aud Audience
     */
    public function __construct($iat, $exp, $iss, $aud) {
        $this->issuedAt = $iat;
        $this->expiresAt = $exp;
        $this->issuer = $iss;
        $this->audience = $aud;
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
        
        if ($this->issuedAt != null) $params["iat"] = $this->issuedAt;
        if ($this->expiresAt != null) $params["exp"] = $this->expiresAt;
        if ($this->issuer != null) $params["iss"] = $this->issuer;
        if ($this->audience != null) $params["aud"] = $this->audience;
        return $params;
    }
    
    /**
     * Deserialize parameters
     * 
     * Creates an instance based on the parameter object. The used parameters will be removed from params.
     * 
     * @access public
     * @static
     * @param array $params An array of parameters, used ones will be removed
     * @return Assertion An instance of an assertion
     */
    public static function deserialize(&$params) {
        $assertion = new Assertion($params["iat"], $params["exp"], $params["iss"], $params["aud"]);
        unset($params["iat"], $params["exp"], $params["iss"], $params["aud"]);
        return $assertion;
    }
    
    /**
     * Issued at
     * 
     * Gets the timestamp when this assertion was issued.
     * 
     * @access public
     * @return int
     */
    public function getIssuedAt(){
        return $this->issuedAt;
    }
    
    /**
     * Expires at
     * 
     * Gets the timestamp when this assertion will expire.
     * 
     * @access public
     * @return int
     */
    public function getExpiresAt() {
        return $this->expiresAt;
    }
    
    /**
     * Issuer
     * 
     * Gets the domain of the issuing identity provider.
     * 
     * @access public
     * @return string
     */
    public function getIssuer() {
        return $this->issuer;
    }
    
    /**
     * Audience
     * 
     * Gets the audience this assertion is valid for.
     * 
     * @access public
     * @return string
     */
    public function getAudience(){
        return $this->audience;
    }
    
    /**
     * Sign assertion
     * 
     * Sign and serialize the assertion using the users secret key belonging to his
     * identity certificate.
     * 
     * @access public
     * @param type $secretKey Secret key of the identity certificate
     * @param array $additionalPayload Additional payload
     * @return string Signed assertion
     */
    public function sign($secretKey, $additionalPayload=null) {
        $allParams = array();
        if ($additionalPayload != null)
            $allParams = array_merge($allParams, $additionalPayload);
        $this->serialize(&$allParams);
        
        $token = new WebToken($allParams);
        return $token->serialize($secretKey);
    }
    
    /**
     * Verify
     * 
     * Checks if the parameters are valid.
     * 
     * @param int $now Unix timestamp in milliseconds
     * @return boolean true, if the instance is valid
     */
    public function verify($now) {
        // check iat
        if ($this->issuedAt != null) {
            if ($this->issuedAt > $now)
                throw new Exception("assertion issued later than verification date");
        }

        // check exp expiration
        if ($this->expiresAt != null) {
            if ($this->expiresAt < $now)
                throw new Exception("assertion has expired");
        }
        
        return true;
    }
}
?>