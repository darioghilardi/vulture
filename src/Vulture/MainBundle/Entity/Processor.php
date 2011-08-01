<?php

/**
 * Processor is the class that manages the whole process of finding 
 * vulnerabilities.
 *
 * @author Dario Ghilardi
 */

namespace Vulture\MainBundle\Entity;

use Vulture\MainBundle\SecurityLibs\HttpParameterPollution;

class Processor {
    
    public $source;
    public $tokens;
    public $conf;
    public $pvf = array();

    public function __construct($source, $tokens) {
        $this->conf = HttpParameterPollution::getInstance();
        $this->source = $source;
        $this->tokens = $tokens;
    }
    
    /**
     * Launch the processing.
     * 
     * The process will scan from the last token to the first, saving just the
     * variables that are printed.
     * 
     */
    public function launch() {
        
        $lastElement = count($this->tokens) - 1;
        
        for ($i = $lastElement; $i >= 0; $i--) {
            
            // Detect variables
            $this->printDetect($i);
        }
    }
    
    /**
     * Detect print statement and save the correspondent variable.
     */
    public function printDetect($i) {
        
        // If a print or echo statements are found
        if ( ($this->tokens[$i][0] == T_ECHO) || ($this->tokens[$i][0] == T_PRINT) ) {
            
            // Start a loop from the element following the print/echo to find 
            // printed variables
            $k = $i + 1;
            
            while ($this->tokens[$k][1] != ';') {
                
                // If the current token is a variable
                if ($this->tokens[$k][0] == T_VARIABLE) {
                    
                    // Save the printed element into the pvf array
                    $this->pvf[] = $this->tokens[$k];
                }
                
                // Move index to the next element
                $k++;
            }
        }
    }
    
    /**
     * Check if a variable has been sanitized. If so, the variable will be removed
     * from the pvf array.
     */
    public function checkSanitization($i) {
        $functions  = $this->conf->securing;
        
        if (in_array($this->tokens[$i][1], $functions)) {
            
            // The configuration class provides me a way to at what place there's the token
        }
    }
    
    /**
     * Check if a variable content is re-assigned.
     * This is useful to understand because sanitization could be compromised.
     */
    public function checkReassignment($i) {
        /*$functions  = $this->conf->securing;
        
        if (in_array($this->tokens[$i][1], $functions)) {
            
        }*/
    }
    
    /**
     * Print tokens into a readable format. Useful to show the tokens but it's
     * important to know that indexes are reformatted during the printing process.
     * 
     * The method print the tokens into a readable format.
     * A foreach needs to be added to print multidimensional arrays on index [3].
     */
    public function ptReadable() {
        // Initialize the output array
        $output = array();
        
        foreach ($this->pvf as $index => $token) {        
                
            // if the token is a multidimensional array take care
            $text = (isset($token[3])) ? $token[1].$token[3] : $token[1];

            // Remove whitespaces
            $text = str_replace("\n", "", $text);
            $text = str_replace("\n", "", $text);

            $output[$index]['value'] = token_name($token[0]);
            $output[$index]['text'] = htmlentities($text);
            $output[$index]['line'] = $token[2];
            
        }
        return $output;
    }
}

?>
