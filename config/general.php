<?php
/**
 * Config class.
 * 
 * Use the singleton design pattern to address configuration.
 * 
 * @author Dario Ghilardi
 */
class Config {
    
    private static $instance;
    
    // RIPS version to be displayed	
    public $version = '0.36';
    
    // Maximum of parameter traces per PVF find
    public $maxtrace = 30;
    
    // Warn user if amount of files to scan is higher than this value
    public $warnfiles = 40;
    
    // Default directory shown
    public $basedir = '';
    
    // PHP documentation path
    public $doku = 'http://php.net/';
    
    // Available code stylesheets
    public $stylesheets = array('phps', 'code-dark', 'twilight', 'espresso', 
                                'sunburst', 'barf', 'notepad++', 'ayti1', 
                                'ayti2'
                                );
    
    // Deafult code stylesheet
    public $default_stylesheet = 'twilight';

    // Filetypes to scan
    public $filetypes = array('.php', '.inc', '.phps', '.php4', '.php5', 
                              '.phtml', '.tpl', '.cgi', '.module'
                             ); 
    
    /**
     * Constructor
     */
    private function __construct() {
        ini_set('short_open_tag', 1);
        ini_set('auto_detect_line_endings', 1);
        set_time_limit(300);
        error_reporting(E_ALL);
    }
    
    /**
     * Get the defined instance.
     * 
     * @return object
     */
    public static function getInstance() 
    {
        if (!isset(self::$instance)) {
            $c = __CLASS__;
            self::$instance = new $c;
        }

        return self::$instance;
    }
}
