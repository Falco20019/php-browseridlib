<?php
/**
 * Certificate bundle
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
 * @subpackage CertBundle
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include Cert
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/cert.php");

/**
 * Include Secrets
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/secrets.php");

/**
 * Include Configuration
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/configuration.php");

/**
 * Certificate bundle
 * 
 * A bundle consisting of an signed assertion and a list of identity certificates.
 *
 * @package     BrowserID
 * @subpackage  CertBundle
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class CertBundle {
    
    /**
     * Identity certificates
     * 
     * A list of signed identity certificates
     * 
     * @access private
     * @var array
     */
    private $certs;
    
    /**
     * Signed assertion
     * 
     * @access private
     * @var string
     */
    private $signedAssertion;
    
    /**
     * Constructor
     * 
     * @access public
     * @param string $assertion Signed assertion
     * @param array $certificates List of signed identity certificates
     */
    public function __construct($assertion, $certificates)
    {
        if ($certificates == null || !is_array($certificates))
                throw new Exception("certificates must be a non-empty array");
        
        $this->signedAssertion = $assertion;
        $this->certs = $certificates;
    }
    
    /**
     * Identity certificates
     * 
     * Gets the list of identity certificates.
     * 
     * @access public
     * @return array
     */
    public function getCerts() {
        return $this->certs;
    }
    
    /**
     * Signed assertion
     * 
     * Gets the signed assertion.
     * 
     * @access public
     * @return string
     */
    public function getSignedAssertion() {
        return $this->signedAssertion;
    }
    
    /**
     * Unbundle assertion
     * 
     * Creates an instance by parsing a bundled assertion.
     * 
     * @access public
     * @static
     * @param string $bundle Bundled assertion
     * @return CertBundle 
     */
    public static function unbundle($bundle)
    {
        if (!is_string($bundle))
            throw new Exception("malformed backed assertion");

        $certificates = explode('~', $bundle);
        $assertion = array_pop($certificates);
        
        return new CertBundle($assertion, $certificates);
    }
    
    /**
     * Bundle assertion
     * 
     * Bundle the signed assertion and the list of identity certificates into an bundled assertion.
     * 
     * @access public
     * @return string Bundled assertion
     */
    public function bundle() {
        if ($this->certs == null || !is_array($this->certs))
                throw new Exception("certificates must be a non-empty array");
        
        $certificates = $this->certs;
        $certificates[] = $this->signedAssertion;
        return join('~', $certificates);
    }
    
    /**
     * Verify certificate chain
     * 
     * Verifies the chain of certificates based on the first one as root certificate.
     * 
     * @access private
     * @param int $now Unix timestamp in milliseconds
     * @return array An array of Cert-objects based on the identity certificates
     */
    private function verifyChain($now) {
        if (!is_array($this->certs))
            throw new Exception("certs must be an array of at least one cert");

        $rootIssuer;
        try {
            // the root
            $token = WebToken::parse($this->certs[0]);
            $rootIssuer = $token->getPayload();
            $rootIssuer = $rootIssuer["iss"];
        } catch (Exception $x) {
            // can't extract components
            throw new Exception("malformed signature");
        }
		
		// TODO: Check if PrimaryCache entry exists, try verifyChainAgainstKey with cached entry.
		// If it fails, remove the cache entry and retry verifyChainAgainstKey with newly fetched key.
        
		// TODO: Extract this into verifyChainAgainstKey
        $rootPK = CertBundle::getPublicKey($rootIssuer);
          
        $certResult = array();
        for($i = 0; $i < sizeof($this->certs); $i++)
        {
            $cert = Cert::parse($this->certs[$i], $rootPK);
            if (!$cert->verify($now))
                throw new Exception("certificate " . $i . " is not valid");
            
            $certResult[] = $cert;
        }
		// TODO: Extract this into verifyChainAgainstKey
        
        return $certResult;
    }
    
    /**
     * Get public key
     * 
     * Gets the public key for the issuer. If our own identity provider is the issuer, we 
     * can load our own public key avoiding network traffic.
     * 
     * @access public
     * @static
     * @param string $issuer The issuers domain
     * @return AbstractPublicKey
     */
    public static function getPublicKey($issuer) {
        // allow other retrievers for testing
        if ($issuer === Configuration::getInstance()->get("hostname")) return Secrets::loadPublicKey();
        /*else if (config.get('disable_primary_support')) {
            throw new Exception("this verifier doesn't respect certs issued from domains other than: " . Configuration::getInstance()->get("hostname"));
        }*/
        
        // let's go fetch the public key for this host
        return Primary::getPublicKey($issuer);
    }
    
    /**
     * Verify the bundled assertion
     * 
     * Verifies if the bundled assertion is valid.
     * 
     * @access public
     * @param int $now Unix timestamp in milliseconds
     * @return array Containing the array of certificates as 'certChain', the additional assertion payload as 'payload' and an assertion object as 'assertion'
     */
    public function verify($now) {
        // no certs? not okay
        if (sizeof($this->certs) == 0)
            throw new Exception ("no certificates provided");

        // simplify error message
        try {
            // verify the chain
            $certChain = $this->verifyChain($now);
        } catch (Exception $e){
            $err = $e->getMessage();
            // allow through the malformed signature
            if ($err == 'malformed signature' ||
                  $err == "assertion issued later than verification date" ||
                  $err == "assertion has expired")
                throw $e;
            else
                throw new Exception("bad signature in chain");
        }
        
        // what was the last PK in the successful chain?
        $lastPK = $certChain[sizeof($certChain) - 1]->getCertParams()->getPublicKey();
        
        $token = WebToken::parse($this->signedAssertion);
        if (!$token->verify($lastPK))
            throw new Exception("signed assertion was not valid signed");

        // now verify the assertion
        $payload = $token->getPayload();
        $assertion = Assertion::deserialize($payload);
        if (!$assertion->verify($now))
            throw new Exception ("assertion is not valid");
        
        return array("certChain" => $certChain,
            "payload" => $payload,
            "assertion" => $assertion);
    }
}
?>