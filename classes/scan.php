<?php

class scan {
  
  public $var_declares_global = array();	
  public $var_declares_local = array();
  public $put_in_global_scope = array();
  public $globals_from_function = array();
  public $dependencies = array();
  public $exit_functions = array();
  public $vuln_classes = array();
  public $class_vars = array();
  public $braces_open = 0;
  public $brace_save_func = -1;
  public $brace_save_class = -1;
  public $ignore_requirement = false;
  public $in_function = false;
  public $ignore_securing_function = false;
  public $in_class = false;
  public $comment = '';
  public $inc_file = '';
  public $inc_file_stack = array();
  public $inc_map = array();
  
  /* Manage the input file */
  public $file_name;
  public $lines_stack = array();
  public $lines_pointer = array();
  public $code;
    
  /**
   * Contructor
   */
  public function __construct($file_name, $scan_functions, $T_FUNCTIONS, $T_ASSIGNMENT, $T_IGNORE, $T_INCLUDES, $T_XSS, $T_IGNORE_STRUCTURE, $F_INTEREST) {
    $this->file_name = $file_name;
  }
  
  /**
   * prepare_code: read the input file and return the token object
   */
  function prepare_code() {
    $this->lines_stack[] = file($this->file_name);
    // Pointer to current lines set
    $this->lines_pointer =& end($this->lines_stack);
    
    // Return code and tokens array
    $this->code = implode('',$this->lines_pointer);
    $tokens = new token($this->code);    
    $tokens->prepare_tokens($T_IGNORE);
    $tokens->fix_tokens();
    return $tokens->tokens;
  }
}
