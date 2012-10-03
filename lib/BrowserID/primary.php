<?php
/**
 * Identity provider
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
 * @subpackage Primary
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include Utils
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/utils.php");

/**
 * Include Secrets
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/secrets.php");

/**
 * Include Algorithms
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/algs.php");

/**
 * Include Configuration
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/configuration.php");

/**
 * Identity Provider (Primary)
 * 
 * To verify the validity of certificates, the public keys of the identity providers 
 * have to be well-known. Therefore every identity provider has offer an /.well-known/browserid 
 * under his domain.
 * 
 * This class can check a identity provider using the 'Basic Support Document', offering his 
 * public key, an authentication- and an provisioning-url for his own signed identity 
 * certificates or the 'Delegated Support Document' stating the authority which takes care 
 * of the signing and key holding.
 *
 * @package     BrowserID
 * @subpackage  Primary
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class Primary {
    
    /**
     * The path to the well-known document
     */
    const WELL_KNOWN_URL = "/.well-known/browserid";
    
    /**
     * The maximum number of hops supported for cert chains
     */
    const MAX_AUTHORITY_DELEGATIONS = 6;
    
    /**
     * Initialization status
     * 
     * This shows if the class and static variables are already initialized.
     * 
     * @access private 
     * @static 
     * @var boolean
     */
    private static $initialized = false;
    
    /**
     * Shimmed primaries
     * 
     * A list of shimmed primaries. Used for local developement or standard 
     * certificates to boost up key retrieval.
     * 
     * Every entry of the array contains the 'origin' where the traffic should be 
     * directed to and a 'body' where the public key is stored.
     * 
     * @access private 
     * @static 
     * @var array Indixed by the domain name
     */
    private static $g_shim_cache = array();
    
    /**
     * Public key of the Identity Provider
     * 
     * If this server is used as identity provider, this localy public key is used 
     * for verification instead of using the well-known protocol.
     * 
     * @access private
     * @static
     * @var AbstractPublicKey Public key of this identity provider
     */
    private static $public_key = null;
    
    /**
     * Initialization routine
     * 
     * @access public
     * @static
     */
    public static function initialize()
    {
        if (Primary::$initialized)
            return;
        
        // Support "shimmed primaries" for local development. That is an environment variable that is any number of
        // CSV values of the form:
        // <domain>|<origin>|<path to .well-known/browserid>,
        // where 'domain' is the domain that we would like to shim. 'origin' is the origin to which traffic should
        // be directed, and 'path to .well-known/browserid' is a path to the browserid file for the domain
        foreach(Configuration::getInstance()->get("shimmed_primaries") as $primary)
        {
            list($domain, $origin, $path) = explode("|", $primary);
            Primary::$g_shim_cache[$domain] = array(
                "origin" => $origin,
                "body" => @file_get_contents(Utils::path_concat(Configuration::getInstance()->get("shimmed_path"), $path))
            );
            //logger.info("inserted primary info for '" + domain + "' into cache, TODO point at '" + origin + "'");
        }
        Primary::$public_key = Secrets::loadPublicKey();
        
        Primary::$initialized = true;
    }
    
    /**
     * Well-Known document parsing
     * 
     * Parses the reply of the well-known document, verifying that all needed 
     * parts are contained. 'Basic Support Documents' have to implement the keys 
     * 'public-key', 'authentication' and 'provisioning'. 'Delegated Support Documents' 
     * only need an 'authority' entry.
     * 
     * This is called recursive for delegated identity providers.
     * 
     * @access public
     * @static
     * @param string $body The body of the well-known document
     * @param string $domain The domain the body belongs to
     * @param array $delegates A list of already seen domains while delegating
     * @return array Containing the string 'publicKey' (the domains public key) and the array 'urls' (with the URL of the authentification document as 'auth' and the URL of the provisioning document as 'prov')
     */
    public static function parseWellKnownBody($body, $domain, $delegates) {
        try {
            $v = json_decode($body, true);
        } catch(Exception $e) {
            throw new Exception("malformed declaration of support for '" . $domain . "': " . $e->getMessage());
        }

        $want = array( 'public-key', 'authentication', 'provisioning' );
        $got = array();
        if (is_array($v)) {
            $got = array_keys(get_object_vars($v));
        }
        
        foreach ($got as $k) {
            $dels = array_keys($delegates);
            if ('authority' === $k) {
                // Recursion
                if (isset($delegates[$domain])) {
                    // return to break out of function, but callbacks are actual program flow
                    throw new Exception("Circular reference in delegating authority " . json_encode($delegates));
                }
                
                if (sizeof($dels) > Primary::MAX_AUTHORITY_DELEGATIONS) {
                    throw new Exception("Too many hops while delegating authority " . json_encode($dels));
                }
                //logger.debug(domain + ' is delegating to ' + v[k]);

                // recurse into low level get /.well-known/browserid and parse again?
                // If everything goes well, finally call our original callback
                $delegates[$domain] = sizeof($dels);
                $r = Primary::getWellKnown($v[$k], $delegates);
                return Primary::parseWellKnownBody($r["body"], $r["domain"], $r["delegates"]);
            }
        }
        
        $missing_keys = array();
        if ($domain != Configuration::getInstance()->get("master_idp")) { // TODO: This is only valid for mozillas main idp)
            foreach ($want as $k) {
                if (array_search($k, $got) === false) {
                    array_push($missing_keys, $k);
                }
            }
        }
        
        if (sizeof($missing_keys) > 0) {
            throw new Exception("missing required key: " . join(', ', $missing_keys));
        };

        // Allow SHIMMED_PRIMARIES to change example.com into 127.0.0.1:10005
        $url_prefix = 'https://' . $domain;
        if (isset(Primary::$g_shim_cache[$domain])) {
            $url_prefix = Primary::$g_shim_cache[$domain]["origin"];
        }

        $urls = array(
            "auth" => $url_prefix . $v["authentication"],
            "prov" => $url_prefix . $v["provisioning"],
        );

        // validate the urls
        if (!Utils::is_url_valid($urls["auth"])) throw new Exception("authentication url isn't valid");
        if (!Utils::is_url_valid($urls["prov"])) throw new Exception("provisioning url isn't valid");

        // parse the public key
        return array(
            "publicKey" => AbstractPublicKey::fromSimpleObject($v['public-key']),
            "urls" => $urls
        );
    }

    /**
     * Well-Known document retrieval
     * 
     * Get the body of the well-known document of a domain.
     * 
     * @access public
     * @static
     * @param string $domain The domain for which the well-known document should be retrieved
     * @param array $delegates A list of already seen domains while delegating
     * @return array Containing the content of the document as 'body', 'domain' and the already seen deletages as 'delegates'
     */
    public static function getWellKnown($domain, $delegates) {
        if (Primary::$g_shim_cache[$domain]) {
            return array(
                "body" => Primary::$g_shim_cache[$domain]["body"],
                "domain" => $domain,
                "delegates" => $delegates
            );
        }

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, "https://" . $domain . Primary::WELL_KNOWN_URL);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if (substr(PHP_OS, 0, 3) == 'WIN') {
            if (!isset($cabundle)) {
                $inst = Configuration::getInstance();
                $cabundle = Utils::path_concat($inst->get('base_path'), $inst->get('var_path'), 'cabundle.crt');
            }
            curl_setopt($ch, CURLOPT_CAINFO, $cabundle);
        }
        $buffer = curl_exec($ch);
        curl_close($ch);

        if ($buffer === false) {
            //logger.debug(domain + ' is not a browserid primary: ' + e.toString());
            throw new Exception($domain . ' is not a browserid primary.');
        }

        return array(
            "body" => $buffer,
            "domain" => $domain,
            "delegates" => $delegates);
    }

    /**
     * Check domain support
     * 
     * Checks if the given domain supports BrowserID/Persona and offers a support document.
     * 
     * @access public
     * @static
     * @param string $domain The name of the domain
     * @param array $delegates A list of already seen domains while delegating
     * @return array @see Primary::getWellKnown() or null if not supported
     */
    public static function checkSupport($domain, $delegates = null) {
        // Delegates will be populatd via recursion to detect cycles
        if (!is_array($delegates)) {
            $delegates = array();
        }

        /*if (config.get('disable_primary_support')) {
        return process.nextTick(function() { cb(null, false); });
        }*/

        if (!is_string($domain) || strlen($domain) == 0) {
            throw new Exception("invalid domain");
        }

        $result = Primary::getWellKnown($domain, $delegates);

        if (!$result["body"]) {
            return null;
        }

        try {
            return Primary::parseWellKnownBody($result["body"], $result["domain"], $result["delegates"]);
        } catch(Exception $e) {
            throw new Exception($domain . ' is a broken browserid primary, malformed dec of support: ' . $e->getMessage());
        }
    }

    /**
     * Retrieve public key for domain
     * 
     * Gets the public key for a domain that acts as Persona Identity Provider
     * @access public
     * @static
     * @param string $domain The domain
     * @return AbstractPublicKey Instance of the public key
     */
    public static function getPublicKey($domain) {
        $result = Primary::checkSupport($domain);

        if ($result["publicKey"] === null) {
            throw new Exception("can't get public key for " . $domain);
        }

        return $result["publicKey"];
    }

    // Does emailDomain actual delegate to the issuingDomain?
    /**
     * Check for authority delegation
     * 
     * Checking if the issuing domain is allowed to issue identity certificates for 
     * this email  domain. This should only be the case if the issuing domain is 
     * Mozilla's server or if the email domain is delegating to the issuing domain.
     * 
     * @param string $emailDomain The domain of the mail, the expected issuer
     * @param string $issuingDomain The domain that issued the assertion
     * @return type 
     */
    static function delegatesAuthority($emailDomain, $issuingDomain) {
        /* // TODO: Maybe later
        if (config.has('proxy_idps')) {
        var proxyIDPs = config.get('proxy_idps');
        if (proxyIDPs.hasOwnProperty(emailDomain))
        if (g_shim_cache.hasOwnProperty(proxyIDPs[emailDomain])) {
        var url = g_shim_cache[proxyIDPs[emailDomain]].origin + "/";
        if (url.indexOf('://' + issuingDomain + ':') !== -1)
        return cb(true);
        }
        }*/

        $result = Primary::checkSupport($emailDomain);
        $urls = &$result["urls"];

        // Check http or https://{issuingDomain}/some/sign_in_path
        if (!$err && $urls && $urls["auth"] && 
            strpos($urls["auth"], '://' . issuingDomain . '/') !== false)
        {
            return true;
        }
        return false;
    }
}

// Call initialization routine
Primary::initialize();
?>