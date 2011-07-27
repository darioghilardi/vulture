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
    public $variables = array();

    public function __construct($source, $tokens) {
        $this->conf = HttpParameterPollution::getInstance();
        $this->source = $source;
        $this->tokens = $tokens;
    }
    
    /**
     * Launch the processing.
     */
    public function launch() {
        
        for ($i = 0; $i < count($this->tokens); $i++) {
            // Detect variables
            $this->varDetect($i);
        }
        
        print_r($this->variables);
    }
    
    /**
     * Detect variables and put them into the variables array
     */
    public function varDetect($i) {
        if ( ($this->tokens[$i][0] == T_VARIABLE) && (!in_array($this->tokens[$i][1], $this->variables))) {
            $this->variables[] = $this->tokens[$i][1];
        }
    }
}

?>
