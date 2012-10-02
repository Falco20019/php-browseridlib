<?php
/**
 * Verifier
 *
 * Verifies an assertion received via HTTP POST and returns a JSON object.
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
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Include Configuration
 */
require_once("BrowserID/configuration.php");

/**
 * Define BrowserID library base path
 */
define("BROWSERID_BASE_PATH", Configuration::getInstance()->get("base_path"));

/**
 * Include Verifier
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/verifier.php");

/**
 * Include CertAssertion
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/cert_assertion.php");

/**
 * Include Utils
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/utils.php");

/**
 * Include BrowserID library
 */
require_once(BROWSERID_BASE_PATH."lib/BrowserID/secrets.php");
?>
