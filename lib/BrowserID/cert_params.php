<?php
/**
 * Certification parameters
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
 * @subpackage CertParams
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include Algorithms
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/algs.php");

/**
 * Certificate parameters
 * 
 * A container for certificate specific parameters like the principal or the public key.
 *
 * @package     BrowserID
 * @subpackage  CertParams
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class CertParams {
    
    /**
     * Public key
     * 
     * @access private
     * @var AbstractPublicKey The public key of the certificate
     */
    private $publicKey;
    
    /**
     * Principal
     * 
     * @access private
     * @var array the principal, mostly the email address
     */
    private $principal;
    
    /**
     * Constructor
     * 
     * @access public
     * @param AbstractPublicKey $pubKey Public key of the certificate
     * @param array $principal The principal the certificate belongs to
     */
    public function __construct($pubKey, $principal)
    {
        $this->publicKey = $pubKey;
        $this->principal = $principal;
    }
    
    /**
     * Serialize parameters
     * 
     * Serializes the objects parameters into an array.
     * 
     * @access public
     * @param array $params An array of parameters, existing ones will be overwritten
     * @return array The combined params array
     */
    public function serialize($params = null) {
        if ($params == null)
            $params = array();
        
        if ($this->publicKey != null) $params["public-key"] = $this->publicKey->toSimpleObject();
        if ($this->principal != null) $params["principal"] = $this->principal;
        
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
     * @return CertParams An instance of certificate parameters
     */
    public static function deserialize(&$params) {
        $pubKey = AbstractPublicKey::deserialize(json_encode($params["public-key"]));
        $cert_params = new CertParams($pubKey, $params["principal"]);
        unset($params["public-key"], $params["principal"]);
        return $cert_params;
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
        return true;
    }
    
    /**
     * Public Key
     * 
     * Gets the public key.
     * 
     * @access public
     * @return AbstractPublicKey 
     */
    public function getPublicKey() {
        return $this->publicKey;
    }
    
    /**
     * Principal
     * 
     * Gets the principal.
     * 
     * @return array
     */
    public function getPrincipal() {
        return $this->principal;
    }
}
?>