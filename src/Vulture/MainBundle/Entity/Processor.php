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
        
        for ($i = count($this->tokens) -1 ; $i > 0; $i--) {
            
            // Detect variables
            $this->printDetect($i);
        }
        
        print_r($this->pvf);
    }
    
    /**
     * Detect print statement and save the correspondent variable.
     */
    public function printDetect($i) {
        
        // If a print or echo statements are found
        if ( ($this->tokens[$i][0] == T_ECHO) || ($this->tokens[$i][0] == T_PRINT) ) {
            
            echo "cioap";
            
            // Start a loop from this element to find what has been printed until ;
            $k = $i;
            /*while ($this->tokens[$k][1] == ';') {
                
                // Save the printed elements into the pvf array
                $this->pvf[] = $this->tokens[$k];
                
                // Move index to the next element
                $k++;
            }*/
        }
    }
}

?>
