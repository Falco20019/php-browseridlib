<?php
/**
 * BrowserID certificate assertion implementation
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
 * @subpackage CertAssertion
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include CertBundle
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/cert_bundle.php");

/**
 * Include Primary
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/primary.php");

/**
 * Include Configuration
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/configuration.php");

/**
 * Certificate assertion
 * 
 * This class offers functions to create certified assertions, certificate identities 
 * or to check if a signed assertion is valid.
 *
 * @package     BrowserID
 * @subpackage  CertAssertion
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class CertAssertion {
    
    /**
     * Certified assertion
     * 
     * @access private
     * @var string
     */
    private $assertion;
    
    /**
     * Audience
     * 
     * The audience this assertion was signed for.
     * 
     * @access private
     * @var string
     */
    private $audience;
    
    /**
     * Constructor
     * 
     * @access public
     * @param string $assertion A certified assertion
     * @param string $audience The audience the assertion was signed for
     */
    public function __construct($assertion, $audience)
    {
        $this->assertion = $assertion;
        $this->audience = $audience;
    }
    
    /**
     * Normalize parsed URL
     * 
     * Normalizes a parsed URL, so that it contains the port part.
     * 
     * @access private
     * @static
     * @param array $parts The parts of the parsed domain
     * @return array The parts, but with filled port field
     */
    private static function normalizeParsedURL($parts) {
        if (!$parts['port']) $parts['port'] = $parts['scheme'] === 'https:' ? 443 : 80;
        return $parts;
    }
    
    /**
     * Compare audiences
     * 
     * Checks if the given assertion is valid for the audience.
     * 
     * @access private
     * @param string $want The expected audience
     * @return string The error message if it fails or null on success
     */
    private function compareAudiences($want) {
        try {
            // We allow the RP to provide audience in multiple forms (see issue #82).
            // The RP SHOULD provide full origin, but we allow these alternate forms for
            // some dude named Postel doesn't go postal.
            // 1. full origin 'http://rp.tld'
            // 1a. full origin with port 'http://rp.tld:8080'
            // 2. domain and port 'rp.tld:8080'
            // 3. domain only 'rp.tld'

            // case 1 & 1a
            if (preg_match("/^https?:\/\//", $this->audience)) {
                $gu = CertAssertion::normalizeParsedURL(parse_url($this->audience));
                $this->audience_scheme = $gu['scheme'];
                $this->audience_domain = $gu['host'];
                $this->audience_port = $gu['port'];
            }
            // case 2
            else if (strpos($this->audience, ':') !== false) {
                $p = explode(':', $this->audience);
                if (count($p) !== 2)
                    throw new Exception("malformed domain");
                $this->audience_domain = $p[0];
                $this->audience_port = $p[1];
            }
            // case 3
            else {
                $this->audience_domain = $this->audience;
            }

            // now parse "want" url
            $want = CertAssertion::normalizeParsedURL(parse_url($want));

            // compare the parts explicitly provided by the client
            if (isset($this->audience_scheme) && $this->audience_scheme != $want['scheme']) throw new Exception("scheme mismatch");
            if (isset($this->audience_port) && $this->audience_port != $want['port']) throw new Exception("port mismatch");
            if (isset($this->audience_domain) && $this->audience_domain != $want['host']) throw new Exception("domain mismatch");

            return null;
        } catch(Exception $e) {
            return $e->getMessage();
        }
    }
    
    /**
     * Check validity
     * 
     * Checks if the assertion is valid for the given audience
     * 
     * @access public
     * @return boolean
     */
    public function isValid()
    {
        try {
            $this->verify();
            return true;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Create identity certificate
     * 
     * Create an identity certificate that is signed by this identity providers key
     * 
     * @access public
     * @static
     * @param string $principal The mail address of the person to identify
     * @param AbstractPublicKey $publicKeyIdentity The public key of the person
     * @param int $now Unix Timestamp in milliseconds or null for now
     * @param string $issuer Issuer domain of the identity provider or null for the configured hostname
     * @return string The serialized signed identity certificate
     */
    public static function createIdentityCert($principal, $publicKeyIdentity, $now=null, $issuer=null) {
        if ($now == null)
            $now = time()*1000;
        if ($issuer == null)
            $issuer = Configuration::getInstance()->get('hostname');
        
        $expires = $now + Configuration::getInstance()->get('identity_validity')*1000;
        $certAssertion = new Assertion($now, $expires, $issuer, null);
        $certParams = new CertParams($publicKeyIdentity, array("email" => $principal));
        $cert = new Cert($certAssertion, $certParams, null);
        return $cert->sign(Secrets::loadSecretKey());
    }
    
    /**
     * Create signed assertion
     * 
     * Create a signed assertion using the users secret key.
     * 
     * @access public
     * @static
     * @param string $audience The audience this assertion is signed for
     * @param AbstractSecretkey $secretKeyIdentity An instance of the secret key matching the users certificate identity
     * @param array $additionalPayload Additional fields to assert
     * @param int $now Unix timestamp in milliseconds or null for now
     * @return string The serialized signed assertion
     */
    public static function createAssertion($audience, $secretKeyIdentity, $additionalPayload = null, $now = null) {
        if ($now == null)
            $now = time()*1000;
        
        $expires = $now + Configuration::getInstance()->get('assertion_validity')*1000;
        $assertion = new Assertion(null, $expires, null, $audience);
        return $assertion->sign($secretKeyIdentity, $additionalPayload);
    }
    
    /**
     * Verificate validity
     * 
     * Verify if the signed assertion is valid.
     * 
     * @access public
     * @return array Containing the used certificate chain as 'certChain', additional payload given in the assertion as 'payload' and the assertion object as 'assertion'
     * @throws Exception Throws an exception if the verification fails
     */
    public function verify() {
        // assertion is bundle
        $bundle = CertBundle::unbundle($this->assertion);
        $result = $bundle->verify(time() * 1000);
        $certChain = &$result["certChain"];
        $payload = &$result["payload"];
        $assertion = &$result["assertion"];
        
        // for now, to be extra safe, we don't allow cert chains
        if (sizeof($certChain) > 1)
            throw new Exception("certificate chaining is not yet allowed");

        // audience must match!
        $err = $this->compareAudiences($assertion->getAudience());
        if ($err) {
            //logger.debug("verification failure, audience mismatch: '"
            //             + assertionParams.audience + "' != '" + audience + "': " + err);
            throw new Exception("audience mismatch: " . $err);
        }

        // principal and issuer are in the last cert
        $lastCert = &$certChain[sizeof($certChain) - 1];
        $principal = $lastCert->getCertParams()->getPrincipal();
        $issuer = $lastCert->getAssertion()->getIssuer();

        // verify that the issuer is the same as the email domain or
        // that the email's domain delegated authority to the issuer
        $domainFromEmail = preg_replace("/^.*@/", "", $principal["email"]);

        if ($issuer != Configuration::getInstance()->get("master_idp") && // TODO: This is only valid for mozillas main idp
            $issuer != Configuration::getInstance()->get("hostname") &&
            $issuer !== $domainFromEmail)
        {
            $delegated = Primary::delegatesAuthority($domainFromEmail, $issuer);
            if (!$delegated) {
                throw new Exception("issuer '" . $issuer . "' may not speak for emails from '" . $domainFromEmail . "'");
            }
        }
        return $result;
    }
}
?>