<?php
/**
 * Configuration
 *
 * @author Benjamin Krämer <benjamin.kraemer@alien-scripts.de>
 * @package php-browseridlib
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
 * @package php-browseridlib
 */
class Configuration {
    
    /**
     * The various deployment configurations
     * @var array   The array contains configurations for the environments
     */
    private $g_configs = array();
    
    /**
     * The environment that defines what configuration to use
     * @var string  The selected environment
     */
    private $environment = 'production';
    
    /**
     * The configuration selected through the environment
     * @var array   The current configuration
     */
    private $g_config = NULL;
    
    /**
     * Singleton
     * @var Configuration The only instance of this class
     */
    private static $instance = NULL;

    
    /**
     * Disallow construction
     */
    private function __construct() {}
    
    /**
     * Disallow cloning
     */
    private function __clone() {}
    
    /**
     * Initialize the singleton instance
     */
    private function __initInstance() {
        // production is the configuration that runs on the
        // public service (browserid.org)
        $this->g_configs['production'] = array(
            'hostname' => 'browserid.org',
            'port' => '443',
            'scheme' => 'https'
        );
        
        // beta (diresworb.org) the only difference from production
        // is the hostname
        $this->g_configs['beta'] = $this->g_configs['production'];
        $this->g_configs['beta']['hostname'] = 'diresworb.org';
        
        // development (dev.diresworb.org) the only difference from production
        // is, again, the hostname
        $this->g_configs['developement'] = $this->g_configs['production'];
        $this->g_configs['developement']['hostname'] = 'dev.diresworb.org';
        
        $this->setEnvironment($this->environment);
    }
    
    /**
     * Return the port extension if the port is not the standard for the scheme
     * @return string Portextension for URL
     */
    private function getPortForURL() {
        if ($this->g_config['scheme'] === 'https' && $this->g_config['port'] === '443') return '';
        if ($this->g_config['scheme'] === 'http' && $this->g_config['port'] === '80') return '';
        return ':' . $g_config['port'];
    }

    /**
     * Returns an instance of the configuration singleton
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
     * Fetch a configuration parameter for the current environment
     * @param string    $val    The configuration param to retrieve
     * @return string The value corresponding to $val
     */
    public function get($val) {
        if ($val == 'env') return $this->environment;
        return $this->g_config[$val];
    }
    
    /**
     * Select a new environment
     * @param string    $env    The environment to select (production, beta, developement)
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
