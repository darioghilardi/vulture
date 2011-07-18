<?php

/**
 * Tokens: A class that manages the source code converted to tokens.
 *
 * @author Dario Ghilardi
 */

namespace Vulture\MainBundle\Entity;

use Vulture\MainBundle\SecurityLibs\HttpParameterPollution;

class Tokens {
    
    public $filename;    
    public $source = array();
    public $lines_pointer;
    public $tokens = array();
    public $conf;
    
    /**
     * Contructor
     */
    public function __construct($file) {
        $this->filename = $file;
    }
    
    /**
     * Build the full tokens representation of the code.
     *
     * @param type $source
     */
    public function build() {
        $this->conf = HttpParameterPollution::getInstance();
        
        $this->source = file_get_contents($this->filename);
        
        $this->tokens = token_get_all($this->source);
        
        $this->pt();
        
        $this->clean();
        
        $this->pt();
        
        $this->pat();
               
    }
    
    /**
     * Delete all tokens to ignore while scanning
     * 
     * Into the tokens array it's unuseful to keep the html code, the array needs to be light.
     *
     * Every token is an array following the convention:
     * [0] => Token numeric index
     * [1] => String content
     * [2] => Line number
     */
	public function clean()
	{	
        
        for ($i = 0; $i < count($this->tokens); $i++) {
            if( is_array($this->tokens[$i]) ) {
                
                // Remove not needed tokens reived from the configuration class
                if ( in_array($this->tokens[$i][0], $this->conf->ignore_tokens) ) {
                    array_splice($this->tokens, $i, 1);
                }
                
                $this->conf->additionalCleaning();
            } else {
                
                
            }
        }
        
        
        /*for($i=0, $c=count($this->tokens); $i<$c; $i++)
		{
			if( is_array($this->tokens[$i]) ) 
			{
				if( in_array($this->tokens[$i][0], $T_IGNORE) )
					unset($this->tokens[$i]);
				else if( $this->tokens[$i][0] === T_CLOSE_TAG )
					$this->tokens[$i] = ';';	
				else if( $this->tokens[$i][0] === T_CONSTANT_ENCAPSED_STRING )
					$this->tokens[$i][1] = str_replace('"', "'", $this->tokens[$i][1]);
			}
			// ternary operator gives headaches, only partly supported
			else if($this->tokens[$i] === '?')
			{
				$d=1;
				// find last token before '?'
				while( !isset($this->tokens[$i-$d]) )
				{
					if($d>10)break;
					$d++;
				}
				// if condition in paranthesis ( )
				if($this->tokens[$i-$d] === ')')
				{
					$d=1;
					while( isset($this->tokens[$i-$d]) && $this->tokens[$i-$d] !== '(' )
					{
						// delete condition, because vars should not be traced
						unset($this->tokens[$i-$d]);
						if($d>20)break;
						$d++;
					}
				}
			}
		}
		
		// return tokens with rearranged key index
		$this->tokens = array_values($this->tokens);*/
    }
    
    /**
     * Print tokens into a readable format.
     */
    public function pt() {
        $res = array();
        while(list($key, $val) = each($this->tokens)) {
            if(is_array($val)) {
                $val2 = $val[1] . ' - ' . token_name($val[0]) . ' : ' .  $val[2];
                $res[$key] = $val2;
            } else {
                $res[$key] = $val;
            }
        }
        echo '<pre>'.print_r($res,1).'</pre>';
    }
    
    /**
     * Print all available tokens and their correspondence.
     */
    public function pat() {
        for($i=258; $i < 376; $i++){
            $res[$i] = token_name($i);
        }
        echo "<style>#tokenCodes td{ white-space:pre; }</style>\n";
        echo "<div id='tokenCodes'><table><tr>\n";
        asort($res);
        echo "<td style='padding-right:1em;'>"; print_r($res); echo "</td>\n";
        ksort($res);
        echo "<td  style='border-left:1px solid black; padding-left:1em;'>"; print_r($res); echo "</td>\n";
        echo "<tr></table></div>\n";
    }
}