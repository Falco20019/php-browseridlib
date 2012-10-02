<?php
/**
 * Crypt_DSA
 * 
 * Crypt_DSA - DSA signature verification and signing library
 *
 * LICENSE:
 *
 * Copyright (c) 2004-2006, TSURUOKA Naoya
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer. 
 *   - Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials provided
 *     with the distribution. 
 *   - Neither the name of the author nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission. 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @package     Crypt
 * @subpackage  Crypt_DSA
 * @author      TSURUOKA Naoya <tsuruoka@labs.cybozu.co.jp>
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright   2006 TSURUOKA Naoya
 * @license     http://www.opensource.org/licenses/bsd-license.php The BSD License
 * @see         http://search.cpan.org/dist/Crypt-DSA/lib/Crypt/DSA.pm
 * @version     0.0.4
 */

/**
 * uses PEAR_Exception
 */
require_once 'PEAR/Exception.php';

/**
 * Include Math_BigInteger
 */
require_once(BROWSERID_BASE_PATH.'lib/Math/BigInteger.php');

/**
 * Include Crypt_Random
 */
require_once(BROWSERID_BASE_PATH.'lib/Crypt/Random.php');

/**
 * Include Crypt_Hash
 */
require_once(BROWSERID_BASE_PATH.'lib/Crypt/Hash.php');

/**
 * Crypt_DSA_Exception
 *
 * This class is used in all place in the package where Exceptions
 * are raised.
 *
 * @package     Crypt
 * @subpackage  Crypt_DSA
 * @author      Shin OHNO <ganchiku@gmail.com>
 * @author      TSURUOKA Naoya <tsuruoka@labs.cybozu.co.jp>
 */
class Crypt_DSA_Exception extends PEAR_Exception
{
    /**
     * errorHandlerCallback
     *
     * @param int $code
     * @param string $string
     * @param string $file
     * @param int $line
     * @param array $context
     * @static
     * @access public
     * throw Crypt_DSA_Exception
     */
    public static function errorHandlerCallback($code, $string, $file, $line, $context)
    {
        $e = new self($string, $code);
        $e->line = $line;
        $e->file = $file;
        throw $e;
    }
}

/**
 * Crypt_DSA
 *
 * @package     Crypt
 * @subpackage  Crypt_DSA
 * @author      TSURUOKA Naoya <tsuruoka@labs.cybozu.co.jp>
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     0.0.4
 */
class Crypt_DSA
{
    /**
     * Version of this package
     */
    const VERSION = '0.0.4';

    /**
     * Generates a random string x bytes long
     *
     * @access private
     * @static
     * @param Integer $bytes
     * @param optional Integer $nonzero
     * @return String
     */
    static private function _random($bytes, $nonzero = false)
    {
        $temp = '';
        if ($nonzero) {
            for ($i = 0; $i < $bytes; $i++) {
                $temp.= chr(crypt_random(1, 255));
            }
        } else {
            $ints = ($bytes + 1) >> 2;
            for ($i = 0; $i < $ints; $i++) {
                $temp.= pack('N', crypt_random());
            }
            $temp = substr($temp, 0, $bytes);
        }
        return $temp;
    }

    /**
     * Octet-String-to-Integer primitive
     *
     * See {@link http://tools.ietf.org/html/rfc3447#section-4.2 RFC3447#section-4.2}.
     *
     * @access private
     * @static
     * @param String $x
     * @return Math_BigInteger
     */
    private static function _os2ip($x)
    {
        return new Math_BigInteger($x, 256);
    }
    
    /**
     * Generate modulated number
     * 
     * Generates a number that lies between 0 and q-1
     * 
     * @access public
     * @static
     * @staticvar Math_BigInteger $one Constant one
     * @param Math_BigInteger $q Modulation
     * @return Math_BigInteger Generated number
     */
    public static function randomNumberMod($q) {
        // do a few more bits than q so we can wrap around with not too much bias
        // wow, turns out this was actually not far off from FIPS186-3, who knew?
        // FIPS186-3 says to generate 64 more bits than needed into "c", then to do:
        // result = (c mod (q-1)) + 1
        static $one;
        if (!isset($one))
            $one = new Math_BigInteger(1);
        
        $c = self::_os2ip(self::_random(strlen($q->toBytes()) + 8));
        $result_base = $c->divide($q->subtract($one));
        return $result_base[1]->add($one);
    }

    /**
     * DSA keypair creation
     * 
     * @param Math_BigInteger $p p
     * @param Math_BigInteger $q q
     * @param Math_BigInteger $g g
     * @return array x = private key, y = public key
     * @throws Crypt_DSA_Exception
     */
    static public function generate($p, $q, $g)
    {
        $hash = new Crypt_Hash($hash_alg);
        
        $x = self::randomNumberMod($q);
        $y = $g->modPow($x, $p);
        
        return array(
            "x" => $x,
            "y" => $y
        );
    }

    /**
     * DSA sign
     * 
     * @param string $message message
     * @param string $hash_alg hash algorithm
     * @param Math_BigInteger $p p
     * @param Math_BigInteger $q q
     * @param Math_BigInteger $g g
     * @param Math_BigInteger $x private key
     * @return array r,s key
     * @throws Crypt_DSA_Exception
     */
    static public function sign($message, $hash_alg, $p, $q, $g, $x)
    {
        $hash = new Crypt_Hash($hash_alg);
        
        static $zero;
        if (!isset($zero))
            $zero = new Math_BigInteger();
        
        while (true)
        {
            $k = self::randomNumberMod($q);
            $r_base = $g->modPow($k, $p)->divide($q);
            $r = $r_base[1];
            
            if ($r->compare($zero) == 0)
            {
                //console.log("oops r is zero");
                continue;
            }

            // the hash
            $bigint_hash = new Math_BigInteger($hash->hash($message), 256);

            // compute H(m) + (x*r)
            $x_mul_r_base = $x->multiply($r)->divide($q);
            $x_mul_r = $x_mul_r_base[1];
            $message_dep_base = $bigint_hash->add($x_mul_r)->divide($q);
            $message_dep = $message_dep_base[1];

            // compute s
            $k_modInv = $k->modInverse($q);
            $k_modInv_mul = $k_modInv->multiply($message_dep);
            $s_base = $k_modInv_mul->divide($q);
            $s = $s_base[1];
            
            if ($s->compare($zero) == 0)
            {
                //console.log("oops s is zero");
                continue;
            }
            // r and s are non-zero, we can continue
            break;
        }
        
        // format the signature, it's r and s
        return array(
            "r" => $r,
            "s" => $s
        );
    }

    /**
     * DSA verify
     * 
     * @param string $message message
     * @param string $hash_alg hash algorithm
     * @param Math_BigInteger $r r
     * @param Math_BigInteger $s s
     * @param Math_BigInteger $p p
     * @param Math_BigInteger $q q
     * @param Math_BigInteger $g g
     * @param Math_BigInteger $y public key
     * @return bool
     * @throws Crypt_DSA_Exception
     */
    static public function verify($message, $hash_alg, $r, $s, $p, $q, $g, $y)
    {
        $hash = new Crypt_Hash($hash_alg);
        $hash_m = new Math_BigInteger($hash->hash($message), 256);
        
        $w      = $s->modInverse($q);

        $hash_m_mul = $hash_m->multiply($w);
        $u1_base    = $hash_m_mul->divide($q);
        $u1         = $u1_base[1];

        $r_mul  = $r->multiply($w);
        $u2_base = $r_mul->divide($q);
        $u2      = $u2_base[1];

        $g_pow              = $g->modPow($u1, $p);
        $y_pow              = $y->modPow($u2, $p);
        $g_pow_mul          = $g_pow->multiply($y_pow);
        $g_pow_mul_mod_base = $g_pow_mul->divide($p);
        $g_pow_mul_mod      = $g_pow_mul_mod_base[1];

        $v_base = $g_pow_mul_mod->divide($q);
        $v      = $v_base[1];

        return ($v->compare($r) == 0);
    }
}
?>
