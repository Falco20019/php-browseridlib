<?php
/**
 * Configuration
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
 * @subpackage Configuration
 * @author     Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @copyright  Alien-Scripts.de Benjamin Krämer
 * @license    http://www.opensource.org/licenses/mit-license.html  MIT License
 */

/**
 * Configuration
 *
 * An abstraction which contains various pre-set deployment
 * environments and adjusts runtime configuration appropriate for
 * the current environmnet (specified via Configuration::getInstance()->setEnvironment(...))
 * 
 * The class can only be used through the singleton Configuration::getInstance()
 * 
 * @package     BrowserID
 * @subpackage  Configuration
 * @author      Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @version     1.0.0
 */
class Configuration {
    
    /**
     * The various deployment configurations
     * 
     * @access private
     * @var array   The array contains configurations for the environments
     */
    private $g_configs = array();
    
    /**
     * The environment that defines what configuration to use
     * 
     * @access private
     * @var string  The selected environment
     */
    private $environment = 'production';
    
    /**
     * The configuration selected through the environment
     * 
     * @access private
     * @var array   The current configuration
     */
    private $g_config = NULL;
    
    /**
     * Singleton
     * 
     * @access private
     * @static
     * @var Configuration The only instance of this class
     */
    private static $instance = NULL;

    
    /**
     * Disallow construction
     * 
     * @access private
     */
    private function __construct() {}
    
    /**
     * Disallow cloning
     * 
     * @access private
     */
    private function __clone() {}
    
    /**
     * Initialize the singleton instance
     * 
     * @access private
     */
    private function __initInstance() {
        // production is the configuration that runs on the
        // public service (browserid.org)
        $this->g_configs['production'] = array(
            'hostname' => 'localhost',
            'port' => '443',
            'scheme' => 'https',
            'master_idp' => 'login.persona.org',
            'remote_verifier_url' => 'https://verifier.login.persona.org/verify',
            'use_remote_verifier' => true,
            'assertion_validity' => 300,
            'identity_validity' => 86400,
            'base_path' => 'C:/xampp/htdocs/browserid_sample/browseridlib/',
            'var_path' => 'var',
            'shimmed_path' => 'shimmed_primaries',
            'shimmed_primaries' => array()
        );
        
        // development the only difference from production is that the local 
        // verifier is used 
        $this->g_configs['developement'] = $this->g_configs['production'];
        $this->g_configs['developement']['use_remote_verifier'] = false;
        $this->g_configs['developement']['shimmed_primaries'] = array(
                'login.persona.org|https://login.persona.org|persona.org'
            );
        
        $this->setEnvironment($this->environment);
    }
    
    /**
     * Extract port from URL
     * 
     * Return the port extension if the port is not the standard for the scheme
     * 
     * @access private
     * @return string Port extension for URL
     */
    private function getPortForURL() {
        if ($this->g_config['scheme'] === 'https' && $this->g_config['port'] === '443') return '';
        if ($this->g_config['scheme'] === 'http' && $this->g_config['port'] === '80') return '';
        return ':' . $g_config['port'];
    }

    /**
     * Get singleton
     * 
     * Returns an instance of the configuration singleton
     * 
     * @access public
     * @static
     * @return Configuration The singleton
     */
    public static function getInstance() {
        if (self::$instance === NULL) {
            self::$instance = new self;
            self::$instance->__initInstance();
        }
        return self::$instance;
    }
    
    /**
     * Getter
     * 
     * Fetch a configuration parameter for the current environment
     * 
     * @access public
     * @param string    $val    The configuration param to retrieve
     * @return string The value corresponding to $val
     */
    public function get($val) {
        if ($val == 'env') return $this->environment;
        return $this->g_config[$val];
    }
    
    /**
     * Select environment
     * 
     * Select a new environment to use in the instance
     * 
     * @access public
     * @param string    $env    The environment to select (production, developement)
     */
    public function setEnvironment($env) {
        if (!isset($this->g_configs[$env]))
            throw new Exception("unknown environment: " . $env);
        
        $environment = $env;
        $this->g_config = $this->g_configs[$env];
        $this->g_config['URL'] = $this->g_config['scheme'] . '://' . $this->g_config['hostname'] . $this->getPortForURL();
    }
}
?>
