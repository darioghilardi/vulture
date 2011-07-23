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
    public $source;
    public $tokens;
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
        
        // For the strange token_get_all behaviour that leave empty array 
        // elements i need to use array_values to reorder indexes
        $this->tokens = array_values($this->tokens);
                
        // Get the initial number of tokens
        $ntokens = count($this->tokens);
        for ($i = 0; $i < $ntokens; $i++) {
            
            // Clean tokens
            $this->clean($i);
            
            // Reconstruct arrays into one single token
            $this->manageArrays($i);
        }
        
        // Rearrange the array as some indexes have been removed
        $this->tokens = array_values($this->tokens);
        
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
	public function clean($i)
	{       
        if( is_array($this->tokens[$i]) ) {
                
            // Remove not needed token types received from the configuration class
            if ( in_array($this->tokens[$i][0], $this->conf->ignore_tokens) ) {
                unset($this->tokens[$i]);
            }
                
            // Launch additional cleaning from the securitylibs classes
            $this->conf->additionalCleaning();
                
        } else {        
                
        }      
    }
    
    /**
     * Manage PHP arrays. 
     * 
     * As default they're arrays are separated into different tokens, because of the brackets. 
     * This method assemble them into one single token with a new array at the index 3,
     * removing brackets:
     * [0] => Token numeric index
     * [1] => String content
     * [2] => Line number 
     * [3] => array(
     *   [1] => Token numeric index (ex. T_CONSTANT_ENCAPSED_STRING)
     *   [2] => String content (ex. index)
     *   [3] => Line number (ex. 1)
     */
    public function manageArrays($i) {
        
        // if i find a variable and the next token is an open bracket start the reconstruction
        if ( 
            (isset($this->tokens[$i][0])) &&
            ($this->tokens[$i][0] == T_VARIABLE) &&
            ($this->tokens[$i+1] == '[')
           ) {            
            $variableIndex = $i;
            $counter = $variableIndex++;
            
            // while the current token is not the last token that compose the array
            while ( ($this->tokens[$counter] != ']') || ($this->tokens[$counter+1] == '[') ) {
                print_r($this->tokens[$variableIndex]);
                die;
                // if the token is an index of the array
                /*if ( ($this->tokens[$counter][0] == T_CONSTANT_ENCAPSED_STRING) ||  
                     ($this->tokens[$counter][0] == T_VARIABLE) ) {
                    
                    // save it into the third element of the array
                    print $this->tokens[$variableIndex];
                    $this->tokens[$variableIndex][] = $this->tokens[$counter];
                    
                    // unset the token as I moved it
                    unset($this->tokens[$counter]);
                }*/
            }
        }
    }
    
    /**
     * Print tokens into a readable format.
     */
    public function pt() {
        foreach ($this->tokens as $key => $val) {
            if(is_array($val)) {
                $string = htmlentities($val[1]) ." - (". $val[0] .") ". token_name($val[0]) ." : $val[2]";
                $string = str_replace("\n", "", $string);
                $string = str_replace("\r", "", $string);
                $res[$key] = $string;
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