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
                
        // Loop through the tokens array
        $ntokens = count($this->tokens);
        for ($i = 0; $i < $ntokens; $i++) {
            
            // Clean tokens
            $this->clean($i);
            
            // Reconstruct arrays into one single token
            $this->manageArrays($i);
        }
        
        $this->removeMarkedTokens();
        
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
     * [3] => Multidimensional array indexes, not involved into this function
     * [4] => Token marked for removal
     */
	public function clean($i)
	{       
        if( is_array($this->tokens[$i]) ) {
                
            // Mark for removal not needed token types received from the configuration class
            if ( in_array($this->tokens[$i][0], $this->conf->ignore_tokens) ) {
                $this->tokens[$i][4] = true;
            }
                
            // Launch additional cleaning from the securitylibs classes
            $this->conf->additionalCleaning();           
                
        } else {        
                
        }      
    }
    
    /**
     * Manage PHP arrays. 
     * 
     * As default arrays are separated into different tokens, because of the brackets. 
     * This method assemble them into one single token with a new array at the index 3,
     * removing brackets:
     * [0] => Token numeric index
     * [1] => String content
     * [2] => Line number 
     * [3] => array(
     *   [1] => Token numeric index (ex. T_CONSTANT_ENCAPSED_STRING)
     *   [2] => String content (ex. index)
     *   [3] => Line number (ex. 1)
     * [4] => Token marked for removal
     */
    public function manageArrays($i) {
        
        // if i find a variable and the next token is an open bracket start the reconstruction
        if ( 
            (isset($this->tokens[$i][0])) &&
            ($this->tokens[$i][0] == T_VARIABLE) &&
            ($this->tokens[$i+1] == '[')
           ) {            
            $arrayIndex = $i;
            $counter = $arrayIndex + 1;
            
            // while the current token is not the last token that compose the array
            while ( ($this->tokens[$counter] != ']') || ($this->tokens[$counter+1] == '[') ) {
                // if the token is an index of the array
                if ( ($this->tokens[$counter][0] == T_CONSTANT_ENCAPSED_STRING) ||  
                     ($this->tokens[$counter][0] == T_VARIABLE) ) {
                    
                    // save it into the third element of the array
                    $this->tokens[$arrayIndex][3][] = $this->tokens[$counter];
                    
                    echo "<pre>".print_r($this->tokens,1)."</pre>";
                    $this->pt();
                    
                    // mark for removal the tokens with array indexes as I moved 
                    // them into the third element of the array
                    $this->tokens[$counter][4] = true;
                }
                $counter++;
            }
        }
    }
    
    /**
     * Remove the tokens marked for removal.
     * 
     * As the clean and the manageArrays functions deletes and move tokens into 
     * the multidimensional tokens array, it's obvoius that tokens will lose 
     * their index into the array. Calling unset and array_values to fix
     * indexes often is very inefficient. Instead, the previous functions marks
     * some tokens to be deleted, and removeMarkedTokens execute the delete on
     * a single loop.
     */    
    public function removeMarkedTokens() {
        
        // Loop through elements to remove tokens marked for removal
        for ($i = 0; $i < count($this->tokens); $i++) {
            if (isset($this->tokens[$i][4]) && ($this->tokens[$i][4])) {
                unset($this->tokens[$i]);
            }
        }
        
        // Rearrange the array as some indexes have been removed
        $this->tokens = array_values($this->tokens);
    }
    
    /**
     * Print tokens into a readable format.
     * 
     * Fix this function to print the multidimensional arrays.
     * 
     */
    public function pt() {
        foreach ($this->tokens as $key => $val) {
            if(is_array($val)) {
                $string = htmlentities($val[1]) ." - (". $val[0] .") ". token_name($val[0]) ." : $val[2]";
                $string = str_replace("\n", "", $string);
                $string = str_replace("\r", "", $string);
                $res[$key] = $string;
                if (isset($val[3]) && is_array($val[3])) {
                    // Here the fix.
                }
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