<?php
/**
 * Description of HttpParameterPollution
 *
 * @author ingo
 */

namespace Vulture\MainBundle\SecurityLibs;

class HttpParameterPollution {
    
    private static $instance;
    
    public $input = array(
        '$_GET',
		'$_POST',
		'$_COOKIE',
		'$_REQUEST',
		'$_FILES',
		'$_SERVER',
		'$_ENV',
		'$HTTP_GET_VARS',
		'$HTTP_POST_VARS',
		'$HTTP_COOKIE_VARS',  
		'$HTTP_REQUEST_VARS', 
		'$HTTP_POST_FILES',
		'$HTTP_SERVER_VARS',
		'$HTTP_ENV_VARS',
		'$HTTP_RAW_POST_DATA',
		'$argc',
        '$argv'
    );
    
    public $sinks = array (
        'echo',
		'print',
		'printf',
		'vprintf',
    );
    
    public $securing = array(
        'htmlentities',
		'htmlspecialchars'
    );
    
    public $ignore_tokens = array (
		
        // anything below ASCII 32 except \t (0x09), \n (0x0a) and \r (0x0d)
        T_BAD_CHARACTER,
        T_CONSTANT_ENCAPSED_STRING,
        // PHPDoc style comments
		T_DOC_COMMENT,
        
        // comments // or #, and /* */
		T_COMMENT,
        
        // comments /* and */
		/*T_ML_COMMENT,*/
        
        // text outside PHP
		T_INLINE_HTML,
        
        // \t \r \n
		T_WHITESPACE,
        
        // <?php, <? or <% and related closing tags
		T_OPEN_TAG,
		T_CLOSE_TAG,
    );
    
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
    
    /**
     * Called before the code is checked to remove unuseful token for 
     * HPP type of scan.
     */
    public static function additionalCleaning() {
        
    }
}

?>
