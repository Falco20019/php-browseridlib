<?php
/**
 * BrowserID assertion implementation
 *
 * Implementation of the VerifiedEmailProtocol based on:
 * https://wiki.mozilla.org/Labs/Identity/VerifiedEmailProtocol
 * 
 * This code is also based on the scripts found at browserid's github repository:
 * https://github.com/mozilla/browserid/tree/dev/verifier/lib
 *
 * @author Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @package php-browseridlib
 */
require_once("jwt.php");
require_once("configuration.php");

/**
 * Webfinger implementation
 * 
 * An implementation of the webfinger protocol for looking up user data 
 * assuming that site-level metadata is retrieved through HTTPS using the 
 * .well-known/host-meta mechanism described in IETF RFC 5785 and 
 * draft-hammer-hostmeta
 * 
 * http://tools.ietf.org/html/rfc5785
 * http://tools.ietf.org/html/draft-hammer-hostmeta-13
 * @package php-browseridlib
 */
class Webfinger {

    /**
     * A cache for host-meta templates
     * @var array   The array contains templates for the domains
     */
    private static $hostMetaCache = array();
    
    /**
     * A constant defining that no host-meta data was found for a domain
     */
    const NO_HOST_META = "NO";

    /**
     * Extract the LRDD template from the host-meta data
     * @param string    $docBytes   A xml-string containing the host-meta
     * @param string    $domain     The name of the domain the host-meta belongs to
     * @return string The URL of the LRDD template or null if not found in the host-meta
     */
    private static function extractLRDDTemplateFromHostMeta($docBytes, $domain) {
        $parser = @simplexml_load_string($docBytes);
        if ($parser === false)
            throw new Exception("The lrdd template was not parsable as XML");

        $namespaces = $parser->getNameSpaces(true);
        $namespaceHm = $parser->children(isset($namespaces['hm']) ? $namespaces['hm'] : '');

        $host = $namespaceHm->Host;
        if (!$host) {
            throw new Exception("Unable to find a Host element in the host-meta file for " . $domain);
        }

        if ($parser->Link->count() > 0) {
            foreach ($parser->Link as $link) {
                $rel = $link->attributes()->rel;
                if ($rel) {
                    if (strtolower($rel) == "lrdd") {
                        return $link->attributes()->template;
                        break;
                    }
                }
            }
        }
        return null;
    }

    /**
     * Gets the /.well-known/host-meta template for the domain and caches
     * the result for the upcoming assertions
     * @param string    $domain     The domain of the issuer
     * @param callback  $continueFn A function to be called on success
     * @param callback  $errorFn    A function to be called on error
     */
    private static function retrieveTemplateForDomain($domain, $continueFn, $errorFn) {
        if (isset(self::$hostMetaCache[$domain])) {
            if (self::$hostMetaCache[$domain] == NO_HOST_META) {
                //console.log("HostMeta cache hit (negative) for " . $domain);
                $errorFn("NoHostMeta");
            } else {
                //console.log("HostMeta cache hit (positive) for " . $domain);
                $continueFn(self::$hostMetaCache[$domain]);
            }
        } else {
            try {
                //console.log("Requesting host-meta for " + options.host + ":" + options.port + " (" + domain + ")");
                $domainParts = parse_url($domain);
                $domainPort = isset($domainParts['port']) ? $domainParts['port'] : 80;
                $schemeByPort = $domainPort == 443 ? "https" : "http";
                $scheme = $domainParts['scheme'] ? $domainParts['scheme'] : $schemeByPort;
                $hostmetaURL = $scheme . "://" . $domainParts['host'] . ($domainPort != 80 ? ':' . $domainPort : '') . "/.well-known/host-meta";
                $buffer = @file_get_contents($hostmetaURL);
                if ($buffer === FALSE) {
                    $last_error = error_get_last();
                    self::$hostMetaCache[$domain] = NO_HOST_META;
                    throw new Exception($last_error['message']);
                }

                $template = self::extractLRDDTemplateFromHostMeta($buffer, $domain);
                self::$hostMetaCache[$domain] = $template;
                $continueFn($template);
            } catch (Exception $e) {
                $errorFn($e);
            }
        }
    }

    /**
     * Retrieves the list of public keys for all devices of a user by the issuer
     * @param string    $addr               The e-mail address of the user
     * @param string    $issuer             The issuer
     * @param callback  $successCallback    A function called on success
     * @param callback  $errorCallback      A function called on error
     */
    public static function resolvePublicKeysForAddress($addr, $issuer=NULL, $successCallback, $errorCallback) {
        $domain = null;
        if (is_string($issuer)) {
            $domain = $issuer;
        } else {
            $split = explode("@", $addr);
            if (count($split) != 2) {
                //console.log("Cannot parse " . $addr . " as an email address");
                $errorCallback("Cannot parse input as an email address");
                return;
            }
            $domain = $split[1];
        }

        //console.log("Verifier: resolving public key for address " . $addr . "; issuer " . $issuer);

        self::retrieveTemplateForDomain(
                $domain, function($template) use ($addr, $domain, $successCallback, $errorCallback) {
                    $userXRDURL = NULL;
                    if ($template)
                        $userXRDURL = str_replace("{uri}", urlencode($addr), $template);
                    if ($userXRDURL == NULL) {
                        $errorCallback($domain . " does not support webfinger (no Link with an lrdd rel and template attribute)");
                        return;
                    }

                    try {
                        $buffer = @file_get_contents($userXRDURL);
                        if ($buffer === FALSE) {
                            $last_error = error_get_last();
                            throw new Exception($last_error['message']);
                        }

                        $parser = simplexml_load_string($buffer);
                        $publicKeys = array();

                        if ($parser->Link->count() > 0) {
                            foreach ($parser->Link as $link) {
                                $rel = $link->attributes()->rel;
                                if ($rel) {
                                    $val = $link->attributes()->value;
                                    $id = $link->attributes()->id;
                                    if (strtolower($rel) == "public-key") {
                                        $keyObj = array("key" => $val);
                                        if ($id)
                                            $keyObj['keyid'] = $id;
                                        $publicKeys[] = $keyObj;
                                    }
                                }
                            }
                        }
                        $successCallback($publicKeys);
                    } catch (Exception $e) {
                        //console.log("Unable to retrieve template for domain " . $domain);
                        $errorCallback("Unable to retrieve the template for the given domain.");
                    }
                }, function($e) use ($domain, $errorCallback) {
                    //console.log("Unable to retrieve template for domain " + domain);
                    $errorCallback("Unable to retrieve the template for the given domain.");
                }
        );
    }

}

/**
 * BrowserID assertion
 * 
 * A class for creating assertions and verifying them.
 * @package php-browseridlib
 */
class IDAssertion {

    /**
     * A serialized JSON Web Token
     * @var string  The webtoken
     */
    private $assertion;

    /**
     * Creates an instance to verify this assertion
     * @param string    $assertion  The assertion to be verified
     */
    public function __construct($assertion) {
        $this->assertion = $assertion;
    }
    
    /**
     * Creates an assertion for the user that can be validated by the
     * relaying party
     * @param string    $email          The email to be used for authentication
     * @param int       $validUntil     A Unix timestamp with microseconds defining the lifetime of the assertion
     * @param string    $audience       The domain of the relaying party
     * @param string    $privateKeyData The private key used for signing in PEM format
     * @return type 
     */
    public static function create($email, $validUntil, $audience, $privateKeyData) {
        $config = Configuration::getInstance();
        
        $payload = array();
        $payload["email"] = $email;
        $payload["valid-until"] = $validUntil;
        $payload["audience"] = $audience;
        $payload["issuer"] = $config->get('hostname') . ':' . $config->get('port');

        $token = new WebToken(json_encode($payload), json_encode(array("alg"=>"RS256")));
        $signed = $token->serialize($privateKeyData);
        return $signed;
    }

    /**
     * Verifies the assigned assertion and calls a callback on success or error
     * @param string    $forAudience    The domain of the relaying party
     * @param callback  $onSuccess      A function to be called on success
     * @param callback  $onError        A function to be called on error
     */
    public function verify($forAudience, $onSuccess, $onError) {
        // Assertion should be a JWT.
        $token = WebToken::parse($this->assertion);

        // JWT will look like:
        // <algorithm-b64>.<payload-b64>.<signature-b64>
        //
		// payload will look like
        // {audience: <>, valid-until:<>, email: <>}
        $decoded = JWTInternals::base64url_decode($token->payloadSegment);
        $payload = json_decode($decoded);

        if (!$payload->email) {
            $onError("Payload is missing required email.");
            return;
        }
        if (!$payload->audience) {
            $onError("Payload is missing required audience.");
            return;
        }
        if ($payload->audience !== $forAudience) {
            $onError("Payload audience does not match provided audience.");
            return;
        }
        if (!$payload->{"valid-until"}) {
            $onError("Payload is missing required valid-until.");
            return;
        }
        $validUntil = $payload->{"valid-until"} / 1000;
        if ($validUntil < time()) {
            $onError("Payload has expired.");
            return;
        }
        
        // check that the issuer is just US for now, no other issuer
        // FIXME: this will need to change for certs
        $config = Configuration::getInstance();
        $expected_issuer = $config->get('hostname') . ':' . $config->get('port');
        if ($payload->issuer != $expected_issuer) {
            $onError("Issuer can only be ourselves for now, it should be: " . $expected_issuer);
            return;
        }

        // (if there was a certificate, we could verify it here)
        // but for now we will assume email-based lookup
        Webfinger::resolvePublicKeysForAddress(
                $payload->email, $payload->issuer, function($publicKeys) use ($token, $payload, $onSuccess, $onError) {
                    if (count($publicKeys) == 0) {
                        $onError("Email address had no public keys");
                        return;
                    }

                    // In the absence of a key identifier, we need to check them all.
                    foreach ($publicKeys as $key) {
                        try {
                            if ($token->verify((string) $key['key'])) {
                                // success!
                                //console.log("Token for " . $payload->email . " verified successfully.");
                                // send back all the verified data
                                $onSuccess($payload);
                                return;
                            }
                        } catch (Exception $e) {
                            //console.log("failed to parse public key: " . $e);
                        }
                    }
                    $onError("None of the user's public keys verified the signature");
                }, function($error) use ($onError) {
                    $onError($error);
                }
        );
    }

}

?>