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
		T_BAD_CHARACTER,
		T_DOC_COMMENT,
		T_COMMENT,
		//T_ML_COMMENT,
		T_INLINE_HTML,
		T_WHITESPACE,
		T_OPEN_TAG
		//T_CLOSE_TAG
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
}

?>
