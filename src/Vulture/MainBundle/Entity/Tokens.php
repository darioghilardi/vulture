<?php

/**
 * Tokens: A class that manages the source code converted to tokens.
 *
 * @author Dario Ghilardi
 */

namespace Vulture\MainBundle\Entity;

use Vulture\MainBundle\SecurityLibs\HttpParameterPollution;

class Tokens {
    
    public $code = array();
    public $tokens = array();
    
    /**
     * Build the full tokens representation of the code.
     *
     * @param type $source
     */
    public function build() {                
        $conf = HttpParameterPollution::getInstance();
        $this->tokens = token_get_all($code);
    }
    
    
    private function readfile() {
        
        // Next work here, reading the file.
        
        $this->lines_stack[] = file($this->file_name);
    
        // Pointer to current lines set
        $this->lines_pointer =& end($this->lines_stack);
    
        // Return code and tokens array
        $this->code = implode('',$this->lines_pointer);
        $tokens = new token($this->code);    
        $tokens->prepare_tokens($this->T_IGNORE);
        $tokens->fix_tokens();
        $this->tokens = $tokens->tokens;
    }
    
    /**
     * Delete all tokens to ignore while scanning, mostly whitespaces	
     */
	/*function clean()
	{	
		
        $conf = Config::getInstance();
        
        
        // delete whitespaces and other unimportant tokens
        for($i=0, $c=count($this->tokens); $i<$c; $i++)
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
		$this->tokens = array_values($this->tokens);
    */
}