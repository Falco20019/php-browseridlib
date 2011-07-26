<?php
/**
 * JSON Web Token implementation
 *
 * Implementation of the JWT protocol based on:
 * http://self-issued.info/docs/draft-jones-json-web-token-01.html
 * 
 * This code is also based on the scripts found at browserid's github repository:
 * https://github.com/mozilla/browserid/tree/dev/verifier/lib
 *
 * @author Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @package BrowserIDLib
 */
/**
 * Base64 URL encoding/decoding
 * 
 * Static functions for encoding and decoding strings using Base64 and
 * encode/decode it for usage in URLs
 * @package BrowserIDLib
 */
class JWTInternals {

    /**
     * Encodes data with MIME base64 and make it URL-safe
     * 
     * @param string    $data   The message to encode
     * @return string The encoded message
     */
    public static function base64url_encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * Decodes data made URL-safe and encoded with MIME base64
     * 
     * @param string    $data   The message to decode
     * @return string The decoded message
     */
    public static function base64url_decode($data) {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }

}

/**
 * HMAC Hashing Interface
 * 
 * Offers methods for signing and verifiying data using HMAC
 * @package BrowserIDLib
 */
class HMACAlgorithm {

    /**
     * The hashing algorithm used to sign or verify data. Has to be supported
     * by the PHP Version and is checked against the list of available 
     * hashing algorithms in hash_algos()
     * 
     * @var string  The hashing algorithm
     */
    private $hash;
    
    /**
     * Shared secret key used for generating the HMAC variant of the
     * message digest. 
     * 
     * @var string  The shared secret key
     */
    private $key;
    
    /**
     * The message to be hashed.
     * 
     * @var string The message
     */
    private $data;

    /**
     * @param string    $hash   The hashing algorithm
     * @param string    $key    The shared secret key
     * @throws NoSuchAlgorithmException The algorithm is not supported
     */
    public function __construct($hash, $key) {
        if (!in_array($hash, hash_algos())) {
            throw new NoSuchAlgorithmException("HMAC does not support hash " . $hash);
        }
        $this->hash = $hash;
        $this->key = $key;
    }

    /**
     * Not needed for HMAC
     */
    public function finalize() {
        
    }

    /**
     * Set the message to be hashed
     * @param string    $data   The message
     */
    public function update($data) {
        $this->data = $data;
    }

    /**
     * Generates the signature using the specified algorithm
     * @return string   The hashed message
     */
    public function sign() {
        return JWTInternals::base64url_encode(hash_hmac($this->hash, $this->data, $this->key));
    }

    /**
     * Verifies the signature
     * @param string    $sig    The signature given
     * @return bool Returns true if the signature was valid
     */
    public function verify($sig) {
        return $this->sign() == $sig;
    }

}

/**
 * RSA-SHA Hashing Interface
 * 
 * Offers methods for signing and verifiying data using RSA-SHA
 * @package BrowserIDLib
 */
class RSASHAAlgorithm {

    /**
     * The hashing algorithm used to sign or verify data. Has to be supported
     * by the PHP Version and is checked against the list of available 
     * hashing algorithms in openssl_get_md_methods()
     * 
     * @var string  The hashing algorithm
     */
    private $hash;
    
    /**
     * A PEM formatted private/public key used for signing or validating
     * 
     * @var string  The key
     */
    private $keyPEM;
    
    /**
     * The message to be hashed.
     * 
     * @var string The message
     */
    private $data;

    /**
     * @param string    $hash   The hashing algorithm
     * @param string    $keyPEM The pem key
     */
    public function __construct($hash, $keyPEM) {
        if (!in_array($hash, openssl_get_md_methods())) {
            throw new NoSuchAlgorithmException("JWT algorithm: " . $hash);
        }

        $this->hash = $hash;
        $this->keyPEM = $keyPEM;
    }

    /**
     * Not needed for RSA-SHA
     */
    public function finalize() {
        
    }

    /**
     * Set the message to be signed/verified
     * @param string    $data   The message
     */
    public function update($data) {
        $this->data = $data;
    }

    /**
     * Generates the signature using the specified algorithm
     * @return string   The hashed message
     */
    public function sign() {
        // Ensure it's in pem format openssl_pkey_get_* understands, therefore 
        // all line breaks have to exist and the key has to be chunked
        $this->keyPEM = str_replace(array(
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----END RSA PRIVATE KEY-----",
            " ",
            "\r\n"), "", $this->keyPEM);
        $this->keyPEM = "-----BEGIN RSA PRIVATE KEY-----\r\n" . chunk_split($this->keyPEM, 64, "\r\n") . "-----END RSA PRIVATE KEY-----";

        $pkeyid = @openssl_pkey_get_private($this->keyPEM);
        if ($pkeyid === false)
            throw new MalformedSignatureException($this->keyPEM);

        $signature = NULL;
        @openssl_sign($this->data, $signature, $pkeyid, $this->hash);
        openssl_free_key($pkeyid);
        return JWTInternals::base64url_encode($signature);
    }

    /**
     * Verifies the signature
     * @param string    $sig    The signature given
     * @return bool Returns true if the signature was valid
     */
    public function verify($sig) {
        // Ensure it's in pem format openssl_pkey_get_* understands, therefore 
        // all line breaks have to exist and the key has to be chunked
        $this->keyPEM = str_replace(array(
            "-----BEGIN PUBLIC KEY-----",
            "-----END PUBLIC KEY-----",
            " ",
            "\r\n"), "", $this->keyPEM);
        $this->keyPEM = "-----BEGIN PUBLIC KEY-----\r\n" . chunk_split($this->keyPEM, 64, "\r\n") . "-----END PUBLIC KEY-----";

        $pkeyid = @openssl_pkey_get_public($this->keyPEM);
        if ($pkeyid === false)
            throw new MalformedSignatureException($this->keyPEM);

        $result = @openssl_verify($this->data, JWTInternals::base64url_decode($sig), $pkeyid, $this->hash);
        openssl_free_key($pkeyid);
        return $result == 1;
    }

}

/**
 * JSON Web Token implementation
 *
 * Implementation of the JWT protocol based on:
 * http://self-issued.info/docs/draft-jones-json-web-token-01.html
 * @package BrowserIDLib
 */
class WebToken {

    /**
     * The data to be signed
     * @var string  The data
     */
    private $objectStr;
    
    /**
     * The algorithm used for hashing. Supported are:
     * ES256, ES384, ES512, HS256, HS384, HS512, RS256, RS384, RS512
     * 
     * @var string  A supported algorithm
     */
    private $pkAlgorithm;
    
    /**
     * The header segment of the web token on parsing
     * @var array A list of header entries (like the algorithm)
     */
    private $headerSegment;
    
    /**
     * The payload that was signed
     * @var string  The data
     */
    private $payloadSegment;
    
    /**
     * The signature generated from the payload using the algorithm
     * given in the header
     * @var string  The signature
     */
    private $cryptoSegment;

    /**
     * @param string    $objectStr  The data to be signed
     * @param string    $algorithm  The algorithm used for signing (ES256, ES384, ES512, HS256, HS384, HS512, RS256, RS384, RS512)
     */
    public function __construct($objectStr="", $algorithm="") {
        $this->objectStr = $objectStr;
        $this->pkAlgorithm = $algorithm;
    }

    /**
     * A getter-function for the class variables
     * @param string    $name   The name of the class variable
     * @return mixed The value of the variable corresponding
     */
    public function __get($name) {
        return $this->$name;
    }

    /**
     * Generate a Webtoken object for parsing JWT data
     * @param string    $input  The JSON Web Token
     * @return WebToken A Webtoken instance for verification
     */
    public static function parse($input) {
        $parts = explode(".", $input);
        if (sizeof($parts) != 3)
            throw new MalformedWebTokenException("Must have three parts");

        $token = new WebToken();
        $token->headerSegment = $parts[0];
        $token->payloadSegment = $parts[1];
        $token->cryptoSegment = $parts[2];
        $token->pkAlgorithm = JWTInternals::base64url_decode($parts[0]);
        return $token;
    }

    /**
     * Create a instance of an hashing algorithm interface depending on the
     * chosen algorithm
     * @param string    $jwtAlgStr  The algorithm used to sign/verify (ES256, ES384, ES512, HS256, HS384, HS512, RS256, RS384, RS512)
     * @param string    $key        The key used for signing/verification
     * @return HMACAlgorithm|RSASHAAlgorithm 
     */
    private function constructAlgorithm($jwtAlgStr, $key) {
        if ("ES256" === $jwtAlgStr) {
            throw new NotImplementedException("ECDSA-SHA256 not yet implemented");
        } else if ("ES384" === $jwtAlgStr) {
            throw new NotImplementedException("ECDSA-SHA384 not yet implemented");
        } else if ("ES512" === $jwtAlgStr) {
            throw new NotImplementedException("ECDSA-SHA512 not yet implemented");
        } else if ("HS256" === $jwtAlgStr) {
            return new HMACAlgorithm("sha256", $key);
        } else if ("HS384" === $jwtAlgStr) {
            return new HMACAlgorithm("sha384", $key);
        } else if ("HS512" === $jwtAlgStr) {
            return new HMACAlgorithm("sha512", $key);
        } else if ("RS256" === $jwtAlgStr) {
            return new RSASHAAlgorithm("sha256", $key);
        } else if ("RS384" === $jwtAlgStr) {
            return new RSASHAAlgorithm("sha384", $key);
        } else if ("RS512" === $jwtAlgStr) {
            return new RSASHAAlgorithm("sha512", $key);
        } else {
            throw new NoSuchAlgorithmException("Unknown algorithm: " . $jwtAlgStr);
        }
    }

    /**
     * Serializes data as JWT using the defined algorithm and data and signed
     * with the key
     * @param string    $key    The key used for hashing
     * @return string A JWT-serialized message
     */
    public function serialize($key) {
        $header = json_decode($this->pkAlgorithm);
        $jwtAlgStr = $header->alg;
        $algorithm = $this->constructAlgorithm($jwtAlgStr, $key);
        $algBytes = JWTInternals::base64url_encode($this->pkAlgorithm);
        $jsonBytes = JWTInternals::base64url_encode($this->objectStr);

        $stringToSign = $algBytes . "." . $jsonBytes;
        $algorithm->update($stringToSign);
        $digestValue = $algorithm->finalize();

        $signatureValue = $algorithm->sign();
        return $stringToSign . "." . $signatureValue;
    }

    /**
     * Verifies a Webtoken generated with the parse method
     * @param string    $key    The key used to verify the webtoken
     * @return bool Returns true if the webtoken is valid
     */
    public function verify($key) {
        $header = json_decode($this->pkAlgorithm);
        $jwtAlgStr = $header->alg;
        $algorithm = $this->constructAlgorithm($jwtAlgStr, $key);
        $algorithm->update($this->headerSegment . "." . $this->payloadSegment);
        $algorithm->finalize();
        return $algorithm->verify($this->cryptoSegment);
    }

}

/**
 * Unsupported algorithm
 * 
 * The algorithm used is not supported by your PHP installation
 * @package BrowserIDLib
 */
class NoSuchAlgorithmException extends Exception {

    /**
     * @param string    $message    The error message
     * @param int       $code       An error code
     */
    public function __construct($message, $code = 0) {
        parent::__construct("No such algorithm: " . $message, $code);
    }

}

/**
 * Unimplemented algorithm
 * 
 * The algorithm used is not implemented yet
 * @package BrowserIDLib
 */
class NotImplementedException extends Exception {

    /**
     * @param string    $message    The error message
     * @param int       $code       An error code
     */
    public function __construct($message, $code = 0) {
        parent::__construct("Not implemented: " . $message, $code);
    }

}

/**
 * Malformed webtoken
 * 
 * The webtoken is not well-formed
 * @package BrowserIDLib
 */
class MalformedWebTokenException extends Exception {

    /**
     * @param string    $message    The error message
     * @param int       $code       An error code
     */
    public function __construct($message, $code = 0) {
        parent::__construct("Malformed JSON web token: " . $message, $code);
    }

}

/**
 * Malformed signature
 * 
 * The signature supplied is not in the PEM format
 * @package BrowserIDLib
 */
class MalformedSignatureException extends Exception {

    /**
     * @param string    $message    The error message
     * @param int       $code       An error code
     */
    public function __construct($message, $code = 0) {
        parent::__construct("Malformed Signature: " . $message, $code);
    }

}

?>