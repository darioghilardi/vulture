<?php

class scan {
  
  /* Tokens */
  public $tokens = array();
  
  /* Manage the input file */
  public $file_name;
  public $lines_stack = array();
  public $lines_pointer = array();
  public $code;
  
  /* Manage functions to scan */
  public $scan_functions;
  public $T_FUNCTIONS;
  public $T_ASSIGNMENT;
  public $T_IGNORE;
  public $T_INCLUDES;
  public $T_XSS;
  public $T_IGNORE_STRUCTURE;
  public $F_INTEREST;
  
  /* Manage the scanning process */
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
  
  /**
   * Contructor
   */
  public function __construct($file_name, $scan_functions, $T_FUNCTIONS, $T_ASSIGNMENT, $T_IGNORE, $T_INCLUDES, $T_XSS, $T_IGNORE_STRUCTURE, $F_INTEREST) {
    $this->file_name = $file_name;
    $this->scan_functions = $scan_functions;
    $this->T_FUNCTIONS = $T_FUNCTIONS;
    $this->T_ASSIGNMENT = $T_ASSIGNMENT;
    $this->T_IGNORE = $T_IGNORE;
    $this->T_INCLUDES = $T_INCLUDES;
    $this->T_IGNORE_STRUCTURE = $T_IGNORE_STRUCTURE;
    $this->T_XSS = $T_XSS;
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
    $tokens->prepare_tokens($this->T_IGNORE);
    $tokens->fix_tokens();
    $this->tokens = $tokens->tokens;
  }
  
  /**
   * scan_file: Scan a file.
   */
  function scan_file()
	{
		// scan all tokens of file
		for($i=0,$tokencount=count($this->tokens); $i<$tokencount;  $i++)
		{	
			$token = $this->tokens[$i];
				
			if( is_array($token) )
			{
				$token_name = $token[0];
				$token_value = $token[1];
				$line_nr = $token[2];
				
				# debug
				#echo "file:".$this->file_name.",line:".$line_nr.",token:".token_name($token_name).",";
				#echo "value:".htmlentities($token_value).",";
				#echo "in_function:".$this->in_function.",in_class:".$this->in_class."<br>";
        
        // Check for xss vulnerabilities
        $this->xss_check($i, $token_name, $token_value, $line_nr);
        
        // Switch lines pointer back to original code if included tokens end
        $this->switch_lines_pointer($i, $token_name, $token_value, $line_nr);
        
        // Build list of all variable declarations
				$this->build_variable_declaration_list($i, $token_name, $token_value, $line_nr);
				
        // Add user input variables to global finding list
				$this->add_user_input_vars($i, $token_name, $token_value, $line_nr);
			
        // Dynamic function call $bla()
				$this->dynamic_function_call($i, $token_name, $token_value, $line_nr);
			
        //Add globaled variables (global $a, $b, $c;) to var list	
				$this->add_global_vars($i, $token_name, $token_value, $line_nr);
				
        // Define("FOO", $_GET['asd']);
				$this->define_vars($i, $token_name, $token_value, $line_nr);
				
        // Compact $array = compact("event", "city");
        $this->compact_array($i, $token_name, $token_value, $line_nr);
				
        // Manage preg_match($regex, $source, $matches)	
        $this->preg_match_helper($i, $token_name, $token_value, $line_nr);
				
        // Manage list($drink, $color, $power) = $info;
				$this->list_helper($i, $token_name, $token_value, $line_nr);
			
        // Add interesting function calls to info gathering	
        $this->add_interesting_function_calls($i, $token_name, $token_value, $line_nr);
				
        // Check if token is a function call and a function to scan
				$this->check_if_function_call($i, $token_name, $token_value, $line_nr);
								
        // Check if token is a function declaration
				$this->token_is_function_declaration($i, $token_name, $token_value, $line_nr);
				
        // Check if token is a class declaration
        $this->token_is_class_declaration($i, $token_name, $token_value, $line_nr);
				
        // Build list of vars that are associated with a class: $var = new Classname()
				if( $token_name === T_NEW && $tokens[$i-2][0] === T_VARIABLE )
				{
					$this->class_vars[ $tokens[$i-2][1] ] = $tokens[$i+1][1];
				}
				
        // Watch function and constructor calls
				$this->watch_function_constructor($i, $token_name, $token_value, $line_nr);
				
			
        // Ignore requirements: do, while, for, foreach	
				if( in_array($token_name, $this->T_IGNORE_STRUCTURE) ) 
				{
					$this->ignore_requirement = true; 
				}
				
        // Watch returns before vuln function gets called
        $this->watch_returns_before_vuln_calls($i, $token_name, $token_value, $line_nr);				
				
        // Check if token is function call that affects variable scope (global)
				$this->check_for_function_calls($i, $token_name, $token_value, $line_nr);
				
        // Include tokens from included files
				$this->include_tokens_from_included_files($i, $token_name, $token_value, $line_nr);
				
			// keep track of { program blocks }
			} else {
				
        // Get current dependencies in program flow
        $this->get_dependencies($i, $token_name, $token_value, $line_nr);
        
				// Before block ending "}" there must be a ";" or another "}". otherwise curly syntax
				$this->block_ending_evaluation($i, $token_name, $token_value, $line_nr);
			}
			
			// token scanned. next.
		}	
		// all tokens scanned.
		
		return $inc_map;
	}
  
  /**
   * xss_check: Check for xss vulnerabilities
   */
  function xss_check($i, $token_name, $token_value, $line_nr) {
    if( in_array($token_name, $this->T_XSS) 
    && ($_POST['vector'] == 'client' || $_POST['vector'] == 'all') && $GLOBALS['verbosity'] != 5)
    {				
      if($token_name === T_OPEN_TAG_WITH_ECHO)
        $token_value = 'echo';

      // build new find					 
      $new_find = new VulnTreeNode();
      $new_find->name = $token_value;
      $new_find->title = 'Cross-Site Scripting';
      $new_find->lines[] = $line_nr;

      // if in included code, set file name
      if(!empty($this->inc_file))
        $new_find->filename = dirname($this->file_name) . '/' . $this->inc_file;

      // add dependencies
      foreach($this->dependencies as $deplinenr=>$dependency)
      {
        $new_find->dependencies[$deplinenr] = $dependency;
      }

      $c = 1;
      $has_vuln_parameters = false;
      $parameter_has_userinput = false;
      $secured_by_start = false;
      $tainted_vars = array();
      $var_count = 0;

      $GLOBALS['securedbyfunc'] = array();

      while( $this->tokens[$i + $c] !== ';' )
      {
        $this_one_is_secure = false;
        if( $tokens[$i + $c][0] === T_VARIABLE 
        || ($tokens[$i + $c][0] === T_STRING && $tokens[$i + $c+1] !== '(') )
        {
          $var_count++;

          if( (is_array($tokens[$i + $c -2]) 
          && (in_array($tokens[$i + $c -2][1], $GLOBALS['F_SECURING_STRING']) 
          || in_array($tokens[$i + $c -2][1], $GLOBALS['F_SECURING_XSS'])))
          || in_array($tokens[$i + $c -1][0], $GLOBALS['T_CASTS']) )
          {
            $secured_by_start = true;
            $this_one_is_secure = true;
          }
          $has_vuln_parameters = true;

          $trace_par_var = $tokens[$i + $c][1];

          // $var['keyname'] should be directly traced, not $var
          if($tokens[$i + $c +1] === '[')
          {
            $trace_par_var = $trace_par_var.'['.$tokens[$i + $c +2][1].']';
          }

          // trace back parameters and look for userinput
          if($this->in_function)
          {
            $userinput = $this->scan_parameter($this->file_name, $new_find, $new_find, 
            $trace_par_var, $this->var_declares_local, $i+$c, 
            $this->var_declares_global, $function_params, $function_obj, 
            false, $GLOBALS['F_SECURING_XSS']);
          } else 
          {
            $userinput = $this->scan_parameter($this->file_name, $new_find, $new_find, 
            $trace_par_var, $this->var_declares_global, $i+$c, 
            $this->var_declares_global, array(), null, false, $GLOBALS['F_SECURING_XSS']);
          }

          if($userinput && (!$this_one_is_secure || $GLOBALS['verbosity'] >= 3) )
          {
            $tainted_vars[] = $var_count;
            $parameter_has_userinput = true;
          }	
        } 
        if($c>50)break;
        $c++;
      }				

      // add find to output if function call has variable parameters (With userinput)
      if( ($has_vuln_parameters && $parameter_has_userinput) || $GLOBALS['verbosity'] == 4 ) 
      {
        $GLOBALS['count_xss']++;
        $new_find->value = highlightline($this->getmultiline($this->lines_pointer, $line_nr-1)."\t".$this->comment, 
                      $line_nr, $token_value, false, $tainted_vars);
        if($secured_by_start)
          $new_find->marker = 2;				

        $id = (isset($GLOBALS['output'][$this->file_name])) ? 
            count($GLOBALS['output'][$this->file_name]) : 0;
        $GLOBALS['output'][$this->file_name][$id] = $new_find;

        if($this->in_function)
        {
          $this->ignore_securing_function = true;
          // mark function in class as vuln
          if($this->in_class)
          {
            $this->vuln_classes[$class_name][] = $function_name;
          }	
        }
      }
    }
  }
  
  /**
   * switch_lines_pointer: Switch lines pointer back to original code if included tokens end
   */
  function switch_lines_pointer($i, $token_name, $token_value, $line_nr) {
    if( $token_name === T_INCLUDE_END)
    {
      array_pop($this->lines_stack);
      $this->lines_pointer =& end($this->lines_stack);			
      array_pop($this->inc_file_stack);
      $this->inc_file = end($this->inc_file_stack);
      $this->comment = '';
    }
  }
  
  /**
   * build_varibale_declaration_list: Build list of all variable declarations
   */
  function build_varibale_declaration_list($i, $token_name, $token_value, $line_nr) {
    if( $token_name === T_VARIABLE
      && ( $tokens[$i+1][0] === '=' || // normal assignment
      (in_array($tokens[$i+1][0], $this->T_ASSIGNMENT))  // mathematical assignment
      || ($tokens[$i-1][0] === T_AS // foreach($var as $key=>$value)
      || ($tokens[$i-1][0] === T_DOUBLE_ARROW
      && $tokens[$i-2][0] === T_VARIABLE)) 
      || ($tokens[$i+1] === '['  // $foo['a'], hard to check all keys and assignments
      // example: $a[0][$i+$k] &= $_GET['a'];
      // easier: the last token was an ending statement or beginning of the file
      && ($tokens[$i-1] === '}' || $tokens[$i-1] === '{' 
      || $tokens[$i-1] === ';' || !isset($tokens[$i-1][0])))) 
      )
    {	
    // add variable declaration to beginning of varlist
    $new_var = new VarDeclare($this->getmultiline($this->lines_pointer, $line_nr-1)."\t".$this->comment);
    $new_var->line = $line_nr;
    $new_var->id = $i;

    $new_token_value = $token_value;

    // add dependencies
    foreach($this->dependencies as $deplinenr=>$dependency)
    {
      $new_var->dependencies[$deplinenr] = $dependency;
    }

    // save $var['keyname'] not only $var
    if($tokens[$i+1] === '[' 
    && is_array($tokens[$i+2]) 
    && ($tokens[$i+2][0] === T_CONSTANT_ENCAPSED_STRING
     || $tokens[$i+2][0] === T_LNUMBER)
    && $tokens[$i+3] === ']')
    {		
      // first save array name
      // in global varlist or local (in function) varlist
      if($this->in_function)
      {
        if(!isset($this->var_declares_local[$new_token_value]))
          $this->var_declares_local[$new_token_value] = array($new_var);
        else
          array_unshift($this->var_declares_local[$new_token_value], $new_var);
      } else
      {
        if(!isset($this->var_declares_global[$new_token_value]))
          $this->var_declares_global[$new_token_value] = array($new_var);
        else
          array_unshift($this->var_declares_global[$new_token_value], $new_var);
      }

      $new_token_value = $token_value.'['.$tokens[$i+2][1].']';
    }

    // global varlist or local (in function) varlist
    if($this->in_function)
    {
      if(!isset($this->var_declares_local[$new_token_value]))
        $this->var_declares_local[$new_token_value] = array($new_var);
      else
        array_unshift($this->var_declares_local[$new_token_value], $new_var);

      // if variable was put in global scope, save assignments
      // later they will be pushed to the global var list when function is called
      if(in_array($new_token_value, $this->put_in_global_scope))
      {
        if(!isset($this->globals_from_function[$function_name][$new_token_value]))
          $this->globals_from_function[$function_name][$new_token_value] = array($new_var);
        else
          array_unshift($this->globals_from_function[$function_name][$new_token_value], $new_var);
      }
    } else
    {
      if(!isset($this->var_declares_global[$new_token_value]))
        $this->var_declares_global[$new_token_value] = array($new_var);
      else
        array_unshift($this->var_declares_global[$new_token_value], $new_var);
    }
    $i++;
    }
  }
  
  /**
   * add_user_input_vars: Add user input variables to global finding list
   */
  function add_user_input_vars($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_VARIABLE && in_array($token_value, $GLOBALS['V_USERINPUT'])) {
      $file_finding = (!empty($this->inc_file)) ? dirname($this->file_name) . '/' . $this->inc_file : $this->file_name;

      if($tokens[$i+1] === '[' && $tokens[$i+2][0] === T_CONSTANT_ENCAPSED_STRING)
        $GLOBALS['user_input'][$token_value.'['.$tokens[$i+2][1].']'][realpath($file_finding)][] = $line_nr;	
      else
        $GLOBALS['user_input'][$token_value][realpath($file_finding)][] = $line_nr;	

      if($this->in_function)
      {
        $GLOBALS['user_functions_offset'][$function_name][5]++;
      } else
      {
        $GLOBALS['user_functions_offset']['__main__'][5]++;
      }
    }
  }
  
  /**
   * dynamic_function_call: Manage dynamic function calls
   */
  function dynamic_function_call($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_VARIABLE && $tokens[$i+1][0] === '(')
    {
      // build new find					 
      $new_find = new VulnTreeNode();
      $new_find->name = '$variable';
      $new_find->title = 'Dynamic Function Call (Remote Code Execution)';
      $new_find->lines[] = $line_nr;

      // if in included code, set file name
      if(!empty($this->inc_file))
        $new_find->filename = dirname($this->file_name) . '/' . $this->inc_file;

      // add dependencies
      foreach($this->dependencies as $deplinenr=>$dependency)
      {
        $new_find->dependencies[$deplinenr] = $dependency;
      }

      // trace back parameters and look for userinput
      if($this->in_function)
      {
        $userinput = $this->scan_parameter($this->file_name, $new_find, $new_find, 
        $token_value, $this->var_declares_local, $i, 
        $this->var_declares_global, $function_params, $function_obj, 
        false, array());
      } else 
      {
        $userinput = $this->scan_parameter($this->file_name, $new_find, $new_find, 
        $token_value, $this->var_declares_global, $i, 
        null, array(), null, false, array());
      }

      // add find to output if function call has variable parameters (With userinput)
      if( $userinput || $GLOBALS['verbosity'] == 4 ) 
      {
        $GLOBALS['count_code']++;
        $new_find->value = highlightline($this->getmultiline($this->lines_pointer, $line_nr-1)."\t".$this->comment, 
                      $line_nr, $token_value, false, $tainted_vars);		

        $id = (isset($GLOBALS['output'][$this->file_name])) ? 
            count($GLOBALS['output'][$this->file_name]) : 0;
        $GLOBALS['output'][$this->file_name][$id] = $new_find;

        if($this->in_function)
        {
          $this->ignore_securing_function = true;
          // mark function in class as vuln
          if($this->in_class)
          {
            $this->vuln_classes[$class_name][] = $function_name;
          }	
        }
      }
    }
  }
  
  /**
   * add_global_vars: Add globaled variables (global $a, $b, $c;) to var list	
   */
  function add_global_vars($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_GLOBAL && $this->in_function)
    {
      $this->globals_from_function[$function_name] = array();

      // get all globaled variables 
      $b=1;
      while($tokens[$i + $b] !== ';')
      {
        if( $tokens[$i + $b][0] === T_VARIABLE )
        {
          $var_value = $tokens[$i + $b][1];
          // mark variable as global scope affecting
          $this->put_in_global_scope[] = $var_value;
          // add variable declaration to beginning of varlist
          $new_var = new VarDeclare("global $var_value;\t".$this->comment);
          $new_var->line = $line_nr;
          $new_var->id = $i;

          $this->var_declares_local[$var_value] = array($new_var);
        }
        if($b>50)break;
        $b++;
      }
    }
  }
  
  /**
   * define_vars: Define("FOO", $_GET['asd']);
   */
  function define_vars($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_STRING && $token_value === 'define' && $tokens[$i+1] === '(')
    {
      // add variable declaration to beginning of varlist
      $new_var = new VarDeclare($this->getmultiline($this->lines_pointer, $line_nr-1)."\t".$this->comment);
      $new_var->line = $line_nr;
      $new_var->id = $i;

      // add dependencies
      foreach($this->dependencies as $deplinenr=>$dependency)
      {
        $new_var->dependencies[$deplinenr] = $dependency;
      }

      $token_value = str_replace(array('"', "'"), '', $tokens[$i+2][1]);

      // global varlist
      if(!isset($this->var_declares_global[$token_value]))
        $this->var_declares_global[$token_value] = array($new_var);
      else
        array_unshift($this->var_declares_global[$token_value], $new_var);
    }
  }
  
  /**
   * compact_array: Compact $array = compact("event", "city");
   */
  function compact_array($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_STRING && $token_value === 'compact' 
    && $tokens[$i+1] === '(' && $tokens[$i-2][0] === T_VARIABLE)
    {
      $f=2;
      while( $tokens[$i+$f] !== ')' )
      {	
        // for all array keys save new variable declarations
        if($tokens[$i+$f][0] === T_CONSTANT_ENCAPSED_STRING)
        {
          $token_value = $tokens[$i-2][1].'['.$tokens[$i+$f][1].']';

          // add variable declaration to beginning of varlist
          $new_var = new VarDeclare($token_value.' = $'.
              str_replace(array('"', "'"), '', $tokens[$i+$f][1]).";\t //".
              $this->getmultiline($this->lines_pointer, $line_nr-1));
          $new_var->line = $line_nr;
          $new_var->id = $i;

          // add dependencies
          foreach($this->dependencies as $deplinenr=>$dependency)
          {
            $new_var->dependencies[$deplinenr] = $dependency;
          }

          // global varlist or local (in function) varlist
          if($this->in_function)
          {
            if(!isset($this->var_declares_local[$token_value]))
              $this->var_declares_local[$token_value] = array($new_var);
            else
              array_unshift($this->var_declares_local[$token_value], $new_var);
          } else
          {
            if(!isset($this->var_declares_global[$token_value]))
              $this->var_declares_global[$token_value] = array($new_var);
            else
              array_unshift($this->var_declares_global[$token_value], $new_var);
          }
        }
        if($f>50)break;
        $f++;
      }
    }	
  }
  
  /**
   * preg_match_helper: Manage preg_match
   */
  function preg_match_helper($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_STRING 
    && ($token_value === 'preg_match' || $token_value === 'preg_match_all')
    && $tokens[$i+1] === '(')
    {
      $c = 2;
      $parameter=1;
      $newbraceopen = ($tokens[$i+1] === '(') ? 1 : 0;

      while( !($newbraceopen === 0 || $tokens[$i + $c] === ';') )
      {
        if( is_array($tokens[$i + $c]) 
        && $tokens[$i + $c][0] === T_VARIABLE && $parameter == 3)
        {
          $token_value = $tokens[$i + $c][1];

          // add variable declaration to beginning of varlist
          $new_var = new VarDeclare($this->getmultiline($this->lines_pointer, $tokens[$i + $c][2]-1));
          $new_var->line = $tokens[$i + $c][2];
          $new_var->id = $i;

          // global varlist or local (in function) varlist
          if($this->in_function)
          {
            if(!isset($this->var_declares_local[$token_value]))
              $this->var_declares_local[$token_value] = array($new_var);
            else
              array_unshift($this->var_declares_local[$token_value], $new_var);
          } else
          {
            if(!isset($this->var_declares_global[$token_value]))
              $this->var_declares_global[$token_value] = array($new_var);
            else
              array_unshift($this->var_declares_global[$token_value], $new_var);
          }
        }
        // count parameters
        else if( $newbraceopen === 1 && $tokens[$i + $c] === ',' )
        {
          $parameter++;
        }
        // watch function calls in function call
        else if( $tokens[$i + $c] === '(' )
        {
          $newbraceopen++;
        }
        else if( $tokens[$i + $c] === ')' )
        {
          $newbraceopen--;
        }
        if($c>50)break;
        $c++;
      }
    }
  }
  
  /**
   * list_helper: Manage list
   */
  function list_helper($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_LIST) {			
      $c=2;
      while( $tokens[$i + $c] !== ')' )
      {
        if( is_array($tokens[$i + $c]) 
        && $tokens[$i + $c][0] === T_VARIABLE )
        {
          $token_value = $tokens[$i + $c][1];

          // add variable declaration to beginning of varlist
          $new_var = new VarDeclare($this->getmultiline($this->lines_pointer, $tokens[$i + $c][2]-1));
          $new_var->line = $tokens[$i + $c][2];
          $new_var->id = $i;

          // global varlist or local (in function) varlist
          if($this->in_function)
          {
            if(!isset($this->var_declares_local[$token_value]))
              $this->var_declares_local[$token_value] = array($new_var);
            else
              array_unshift($this->var_declares_local[$token_value], $new_var);
          } else
          {
            if(!isset($this->var_declares_global[$token_value]))
              $this->var_declares_global[$token_value] = array($new_var);
            else
              array_unshift($this->var_declares_global[$token_value], $new_var);
          }
        }
        if($c>50)break;
        $c++;
      }	
      $i=$i+$c+2;
    }	
  }
  
  /**
   * check_if_function_call: Check if token is a function call and a function to scan
   */
  function check_if_function_call($i, $token_name, $token_value, $line_nr) {
    if( in_array($token_name, $this->T_FUNCTIONS) 
    && $tokens[$i+1] === '(' && $GLOBALS['verbosity'] != 5 )
    {						
      // prevent alerts with wrong classes (same function name in different classes)
      // $classvar->func();
      if($tokens[$i-1][0] === T_OBJECT_OPERATOR)
      {
        $classvar = $tokens[$i-2][1];
        if(substr($classvar,0,1) !== '$')
          $classvar = '$'.$classvar;
        $class = $this->class_vars[$classvar];

        if(!($this->in_function && in_array($classvar, $function_params))
        && !@in_array($token_value, $this->vuln_classes[$class]) )
        {
          continue;					
        }
      }
      // check if function call is a standalone or not
      else if($tokens[$i-1] === '=' || $tokens[$i-1] === ')' || $tokens[$i-1] === ',')
      {
        $var_count = 1;
      } else
      {
        $var_count = 0;
      }

      // treat error handler as called function
      if($token_value === 'set_error_handler')
        $token_value = str_replace("'", '', $tokens[$i+2][1]);

      // add function call to user-defined function list
      $class = !empty($class) ? $class.'::' : '';
      if(isset($GLOBALS['user_functions_offset'][$class.$token_value]))
      {
        $GLOBALS['user_functions_offset'][$class.$token_value][3][] = array(
          (!empty($this->inc_file) ? dirname($this->file_name).'/'.$this->inc_file : $this->file_name), 
          $line_nr
        );
        // add userdefined function call to main or function
        if($this->in_function)
        {
          $GLOBALS['user_functions_offset'][$function_name][4][] = $token_value;
        } else
        {
          $GLOBALS['user_functions_offset']['__main__'][4][] = $token_value;
        }
      }

      // only scan functions that we want to scan
      if(isset($this->scan_functions[$token_value]))
      {	
        // build new find					 
        $new_find = new VulnTreeNode();
        $new_find->name = $token_value;
        $new_find->lines[] = $line_nr;

        if($this->in_function)
        {
          $GLOBALS['user_functions_offset'][$function_name][6]++;
        } else
        {
          $GLOBALS['user_functions_offset']['__main__'][6]++;
        }

        // if in included code, set file name, count PVF calls per file
        if(!empty($this->inc_file))
        {
          $new_find->filename = dirname($this->file_name) . '/' . $this->inc_file;
          $GLOBALS['file_sinks_count'][realpath($new_find->filename)]++;
        } else
        {
          $GLOBALS['file_sinks_count'][realpath($this->file_name)]++;
        }

        // add dependencies
        foreach($this->dependencies as $deplinenr=>$dependency)
        {
          $new_find->dependencies[$deplinenr] = $dependency;
        }

        $parameter=1;
        $has_vuln_parameters = false;
        $parameter_has_userinput = false;
        $secured_by_start = false;
        // function calls without quotes (require $inc;) --> no brace count
        $newbraceopen = ($tokens[$i+1] === '(') ? 1 : -1;
        $c = ($tokens[$i+1] === '(') ? 2 : 1; // important
        $tainted_vars = array();

        $reconstructstr = '';
        $GLOBALS['securedbyfunc'] = array();

        // get all variables in parameter list between (...)
        // not only until ';' because: system(get($a),$b,strstr($c));
        while( !($newbraceopen === 0 || $tokens[$i + $c] === ';') )
        {
          $this_one_is_secure = false;
          if( is_array($tokens[$i + $c]) )
          {	
            // scan variables
            if( $tokens[$i + $c][0] === T_VARIABLE 
            || ($tokens[$i + $c][0] === T_STRING && $tokens[$i + $c+1] !== '(') )
            {
              $var_count++;
              // scan only potential vulnerable parameters of function call
              if ( in_array($parameter, $this->scan_functions[$token_value][0]) 
              || (isset($this->scan_functions[$token_value][0][0])
                && $this->scan_functions[$token_value][0][0] === 0) ) // all parameters accepted
              {							
                if( (is_array($tokens[$i + $c -2]) 
                && (in_array($tokens[$i + $c -2][1], $GLOBALS['F_SECURING_STRING']) 
                || in_array($tokens[$i + $c -2][1], $this->scan_functions[$token_value][1])))
                || in_array($tokens[$i + $c -1][0], $GLOBALS['T_CASTS']) )
                {
                  $secured_by_start = true;
                  $this_one_is_secure = true;
                }
                $has_vuln_parameters = true;

                $trace_par_var = $tokens[$i + $c][1];

                // $var['keyname'] should be directly traced, not $var
                if($tokens[$i + $c +1] === '[')
                {
                  $trace_par_var = $trace_par_var.'['.$tokens[$i + $c +2][1].']';
                }		

                $secured = $this_one_is_secure ? 'function' : '';

                // trace back parameters and look for userinput, trace constants globally
                if($this->in_function && $tokens[$i + $c][1][0] === '$' )
                {
                  $userinput = $this->scan_parameter($this->file_name, $new_find, $new_find, 
                  $trace_par_var, $this->var_declares_local, $i+$c, 
                  $this->var_declares_global, $function_params, $function_obj, 
                  false, $this->scan_functions[$token_value][1], false, false, $secured);

                  $reconstructstr.= $this->get_var_value($trace_par_var, $this->var_declares_local, $this->var_declares_global, $i);
                } else 
                {
                  $userinput = $this->scan_parameter($this->file_name, $new_find, $new_find, 
                  $trace_par_var, $this->var_declares_global, $i+$c, 
                  $this->var_declares_global, array(), null, false, $this->scan_functions[$token_value][1], false, false, $secured);

                  $reconstructstr.= $this->get_var_value($trace_par_var, $this->var_declares_global, $this->var_declares_global, $i);
                }

                if($userinput && (!$this_one_is_secure || $GLOBALS['verbosity'] == 4) )
                {
                  $parameter_has_userinput = true;
                  $tainted_vars[] = $var_count;
                }	
              } 

              // mark userinput for quote analysis
              if(in_array($tokens[$i + $c][1], $GLOBALS['V_USERINPUT']))
              {
                $reconstructstr.='$_USERINPUT';
                if($tokens[$i+$c+1] === '[')
                  $c=$c+3;
              }
            }
            // userinput from return value of a function
            else if( $tokens[$i + $c][0] === T_STRING 
            && in_array($tokens[$i + $c][1], $GLOBALS['F_USERINPUT']) 
            // scan only potential vulnerable parameters of function call
            && ( in_array($parameter, $this->scan_functions[$token_value][0]) 
            || (isset($this->scan_functions[$token_value][0][0])
            && $this->scan_functions[$token_value][0][0] === 0) ) )// all parameters accepted
            {	
              $has_vuln_parameters = true;
              $parameter_has_userinput = true;
              $new_find->marker = 1; 
              $reconstructstr.='$_USERINPUT';
            }	
            // detect securing functions embedded into the PVF
            else if( ($tokens[$i + $c][0] === T_STRING 
            && (in_array($tokens[$i+$c][1], $this->scan_functions[$token_value][1])
            || in_array($tokens[$i+$c][1], $GLOBALS['F_SECURING_STRING']) ) ) )
            {
              $GLOBALS['securedbyfunc'][] = $tokens[$i+$c][1];
            }
            // add strings to reconstructed string for quotes analysis
            else if( $tokens[$i + $c][0] === T_CONSTANT_ENCAPSED_STRING )
            {
              $reconstructstr.= substr($tokens[$i + $c][1], 1, -1);
            }
            else if( $tokens[$i + $c][0] === T_ENCAPSED_AND_WHITESPACE )
            {
              $reconstructstr.= $tokens[$i + $c][1];
            }
          }	
          // count parameters
          else if( $newbraceopen === 1 && $tokens[$i + $c] === ',' )
          {
            $parameter++;
          }
          // watch function calls in function call
          else if( $tokens[$i + $c] === '(' )
          {
            $newbraceopen++;
          }
          else if( $tokens[$i + $c] === ')' )
          {
            $newbraceopen--;
          }
          if($c>50)break;
          $c++;
        }	

        $addtitle='';
        // quote analysis for securing functions that only protect when embedded into quotes
        if( count($GLOBALS['securedbyfunc']) == substr_count($reconstructstr, '$_USERINPUT')  > 0 )
        {
          $parts = explode('$_USERINPUT', $reconstructstr);
          foreach($GLOBALS['securedbyfunc'] as $var=>$securefunction)
          {
            if(in_array($securefunction, $GLOBALS['F_QUOTE_ANALYSIS']))
            {
              // extract the string before the userinput
              $checkstring = '';
              $c=0;
              foreach($parts as $part)
              {
                $checkstring.=$part;
                if($c>=$var)
                  break;
                $c++;	
              }

              // even amount of quotes (or none) in string 
              // --> no quotes around userinput
              // --> securing function is	useless
              if(substr_count($checkstring, "'") % 2 === 0
              && substr_count($checkstring, '"') % 2 === 0)
              {
                $has_vuln_parameters = true;
                $parameter_has_userinput = true;
                $addtitle = " (insecure usage of $securefunction() without quotes)";
              }
            }
          }	
        }

        // add find to output if function call has variable parameters (With userinput)
        if( ($has_vuln_parameters && $parameter_has_userinput) || $GLOBALS['verbosity'] == 4 
        || isset($this->scan_functions[$token_value][3]) ) 
        {
          if(isset($GLOBALS['user_functions'][$this->file_name][$token_value]))
          {
            $found_line = '<A NAME="'.$token_value.'_call"></A>';
            $found_line.= highlightline($this->getmultiline($this->lines_pointer, $line_nr-1)."\t".$this->comment, 
                        $line_nr, false, $token_value);
          } else
          {
            $found_line = highlightline($this->getmultiline($this->lines_pointer, $line_nr-1)."\t".$this->comment, 
                        $line_nr, $token_value, false, $tainted_vars);
          }
          $new_find->value = $found_line;

          if($secured_by_start)
            $new_find->marker = 2; 

          // only show vuln user defined functions 
          // if call with userinput has been found
          if( isset($GLOBALS['user_functions'][$this->file_name][$token_value]) )
            $GLOBALS['user_functions'][$this->file_name][$token_value]['called'] = true;

          if($this->in_function)
          {
            $this->ignore_securing_function = true;
            // mark function in class as vuln
            if($this->in_class)
            {
              $this->vuln_classes[$class_name][] = $function_name;
            }						
          }

          // add graph note about function call to user-defined function list
          if(isset($GLOBALS['user_functions_offset'][$class.$token_value]))
          {
            // add userdefined function call to main or function
            if($this->in_function)
            {
              $GLOBALS['user_functions_offset'][$function_name][4][$token_value] = true;
            } else
            {
              $GLOBALS['user_functions_offset']['__main__'][4][$token_value] = true;
            }
          }

          // putenv with userinput --> getenv is treated as userinput
          if($token_value == 'putenv')
          {
            $GLOBALS['F_USERINPUT'][] = 'getenv';
            $new_find->title = 'User can set PHP enviroment variables. Adding getenv() to tainting functions';
          }
          else if($token_value == 'apache_setenv')
          {
            $GLOBALS['F_USERINPUT'][] = 'apache_getenv';
            $new_find->title = 'User can set Apache enviroment variables. Adding apache_getenv() to tainting functions';
          }
          else
          {
            $new_find->title = getVulnNodeTitle($token_value).$addtitle;
          }

          // add to output
          $id = (isset($GLOBALS['output'][$this->file_name])) ? 
              count($GLOBALS['output'][$this->file_name]) : 0;
          $GLOBALS['output'][$this->file_name][$id] = $new_find;
        }

        // if classvar depends on function parameter, add this parameter to list
        if( isset($classvar) && $this->in_function && in_array($classvar, $function_params) ) 
        {
          $param = array_search($classvar, $function_params);
          $GLOBALS['user_functions'][$this->file_name][$function_name][0][$param] = $param+1;
        } 
      }
    }
  }
  
  /**
   * token_is_function_declaration: Check if token is a function declaration
   */
  function token_is_function_declaration($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_FUNCTION)
    {
      $this->in_function = true;

      // the next token is the "function name()"
      $i++;
      $function_name = isset($tokens[$i][1]) ? $tokens[$i][1] : $tokens[$i+1][1];
      $ref_name = ($this->in_class ? $class_name.'::' : '') . $function_name;

      // add POP gadgets to info
      if(isset($this->F_INTEREST[$function_name]))
      {
        $GLOBALS['info'][] = $ref_name;

        // add gadget to output
        $found_line = highlightline($this->getmultiline($this->lines_pointer, $line_nr-1)."\t".$this->comment, 
                      $line_nr, $function_name, false, $function_name);
        $new_find = new InfoTreeNode($found_line);
        $new_find->title = "POP gadget $ref_name"; 
        $new_find->lines[] = $line_nr;

        // if in included code, set file name
        if(!empty($last_inc_file))
          $new_find->filename = dirname($this->file_name) . '/' . $last_inc_file;

        $id = (isset($GLOBALS['output'][$this->file_name])) ? 
          count($GLOBALS['output'][$this->file_name]) : 0;
          $GLOBALS['output'][$this->file_name][$id] = $new_find;
      } 

      // write to user_functions offset list for referencing in output
      $GLOBALS['user_functions_offset'][$ref_name][0] = !empty($this->inc_file) ? dirname($this->file_name).'/'.$this->inc_file : $this->file_name;
      $GLOBALS['user_functions_offset'][$ref_name][1] = $line_nr-1;
      // save function as object
      $function_obj = new FunctionDeclare($this->getmultiline($this->lines_pointer, $line_nr-1));
      $function_obj->lines[] = $line_nr; 
      $function_obj->name = $function_name;

      // save all function parameters
      $function_params = array();
      $e=1;
      // until function test(...) {
      //  OR
      // interface test { public function test(...); }
      while( $tokens[$i+$e] !== '{' && $tokens[$i+$e] !== ';' )
      {	
        if( is_array($tokens[$i + $e]) && $tokens[$i + $e][0] === T_VARIABLE )
        {
          $function_params[] = $tokens[$i + $e][1];
        }
        if($e>50)break;
        $e++;
      }
      // now skip the params from rest of scan,
      // or function test($a=false, $b=false) will be detected as var declaration
      $i+=$e-1; // -1, because '{' must be evaluated again
    }
  }
  
  /**
   * watch_function_constructor: watch_function_constructor
   */
  function watch_function_constructor($i, $token_name, $token_value, $line_nr) {
    if( $token_name === T_STRING && $tokens[$i+1] === '(')
    {
      // $var = Classname($constructor_param);
      if( $tokens[$i-1][0] !== T_NEW && isset($this->vuln_classes[$token_value]) )
      {
        $this->class_vars[ $tokens[$i-2][1] ] = $token_value;
      }
      // add function call to user-defined function list
      else
      {
        $class='';
        // $classvar->bla()
        if($tokens[$i-1][0] === T_OBJECT_OPERATOR)
        {
          $classvar = $tokens[$i-2][1];
          if(substr($classvar,0,1) !== '$')
            $classvar = '$'.$classvar;
          $class = ($classvar === '$this' ? $class_name : $this->class_vars[$classvar]).'::';
        }	

        if(isset($GLOBALS['user_functions_offset'][$class.$token_value]))
        {				
          $GLOBALS['user_functions_offset'][$class.$token_value][3][] = array(
            (!empty($this->inc_file) ? dirname($this->file_name).'/'.$this->inc_file : $this->file_name), 
            $line_nr
          );
        }
      }
    }
  }
  
  /**
   * watch_returns_before_vuln_calls: Watch returns before vuln function gets called
   */
  function watch_returns_before_vuln_calls ($i, $token_name, $token_value, $line_nr){
    if($this->in_function && $token_name === T_RETURN)
    {
      $GLOBALS['userfunction_taints'] = false;
      $GLOBALS['userfunction_secures'] = false;
      $c = 1;
      // get all variables in parameter list
      while( $tokens[$i + $c] !== ';' && $c < 10)
      {
        if( is_array($tokens[$i + $c]) )
        {
          if( $tokens[$i + $c][0] === T_VARIABLE )
          {
            // check if returned var is secured --> securing function
            $new_find = new VulnTreeNode();
            $userinput = $this->scan_parameter($this->file_name, $new_find, $new_find, 
              $tokens[$i + $c][1],
              $this->var_declares_local, $i+$c, 
              $this->var_declares_global, array(), $function_obj, 
              false, $GLOBALS['F_SECURES_ALL'], TRUE);

            // add function to securing functions
            if($GLOBALS['userfunction_secures'] && !$this->ignore_securing_function)
            {
              $GLOBALS['F_SECURING_STRING'][] = $function_name;
            }

            // add function to userinput functions if userinput
            // is fetched in the function and then returned
            if($userinput || ($GLOBALS['userfunction_taints'] /*&& $GLOBALS['verbosity'] < 1*/) )
            {
              $GLOBALS['F_USERINPUT'][] = $function_name;
            }
          }
          // add function to securing functions if return value is secured
          else if( in_array($tokens[$i + $c][1], $GLOBALS['F_SECURING_STRING']) )
          {
            $GLOBALS['F_SECURING_STRING'][] = $function_name;
            break;
          }
        }
        if($c>50)break;
        $c++;
      }
    }
  }
  
  /**
   * include_tokens_from_included_files: Include tokens from included files
   */
  function include_tokens_from_included_files($i, $token_name, $token_value, $line_nr){
    if( in_array($token_name, $this->T_INCLUDES) && !$this->in_function)
    {	
      // save found				
      $found_line = trim($this->lines_pointer[$line_nr-1])."\t".$this->comment;
      $last_inc_file = $this->inc_file;	

      $GLOBALS['count_inc']++;
      // include('xxx')
      if ( (($tokens[$i+1] === '(' 
        && $tokens[$i+2][0] === T_CONSTANT_ENCAPSED_STRING
        && $tokens[$i+3] === ')')
      // include 'xxx'
      || (is_array($tokens[$i+1])
        && $tokens[$i+1][0] === T_CONSTANT_ENCAPSED_STRING
        && $tokens[$i+2] === ';' )) )
      {					
        // include('file')
        if($tokens[$i+1] === '(')
        {
          $this->inc_file = substr($tokens[$i+2][1], 1, -1);
          $skip = 5;
        }
        // include 'file'
        else
        {
          $this->inc_file = substr($tokens[$i+1][1], 1, -1);
          $skip = 3;
        }	
      }
      // dynamic include
      else
      {
        $this->inc_file = '';
        $c = 1;
        // check all tokens until include statement ends
        while( $tokens[$i +$c] !== ';' )
        {
          if( is_array($tokens[$i +$c]) )
          {		
            // trace variables for its values
            if( $tokens[$i +$c][0] === T_VARIABLE 
            || ($tokens[$i +$c][0] === T_STRING 
            && $tokens[$i +$c +1] !== '(' ) )
            {
              $var_trace = $tokens[$i +$c][1];
              // trace $var['keyname'] (if available) not only $var
              if($tokens[$i +$c +1] === '[')
              {
                $var_trace = $var_trace.'['.$tokens[$i +$c +2][1].']';
                $i=$i+2;
              }

              // CONSTANTS
              if($var_trace[0] !== '$')
                $var_trace = strtoupper($var_trace);

              // constant CONSTANTS
              if ($var_trace == 'DIRECTORY_SEPARATOR' || $var_trace == 'PATH_SEPARATOR')
              {
                $this->inc_file.='/';
              }	
              else if(!$this->in_function)
                $this->inc_file .= $this->get_var_value($var_trace, 
                $this->var_declares_global, $this->var_declares_global, $i);
              else
                $this->inc_file .= $this->get_var_value($var_trace, 
                $this->var_declares_local, $this->var_declares_global, $i);
            }
            // add strings to include file name
            else if( $tokens[$i + $c][0] === T_CONSTANT_ENCAPSED_STRING )
            {
              $this->inc_file .= substr($tokens[$i + $c][1], 1, -1); // delete quotes
            }
            else if( $tokens[$i + $c][0] === T_ENCAPSED_AND_WHITESPACE )
            {
              $this->inc_file .= $tokens[$i + $c][1];
            }
          }
          if($c>100)break;
          $c++;
        }	
        $skip = $c+1; // important to save $c+1 here
      }

      // if file name has not been included
      if( !in_array($this->inc_file, $this->inc_file_stack) )
      {
        $try_file = dirname($this->file_name). '/' . $this->inc_file;
        // in case the $this->get_var_value added several php files, take the first
        $several = explode('.php', $try_file);
        if(count($several) > 1)
          $try_file = $several[0] . '.php';

        // if still not a valid file, look a directory above
        if(!is_file($try_file))
        {
          $try_file = str_replace('\\', '/', $try_file);
          $pos = strlen($try_file);
          // replace each found / with /../, start from the end of file name
          for($c=1; $c<substr_count($try_file, '/'); $c++)
          {
            $pos = strripos(substr($try_file,1,$pos), '/');
            if(is_file(substr_replace($try_file, '/../', $pos+1, 1)))
            {
              $try_file = substr_replace($try_file, '/../', $pos+1, 1);
              break;
            }
          }
        }

        // if still not a valid file, guess it
        if(!is_file($try_file))
        {
          $searchfile = basename($try_file);
          foreach($GLOBALS['data'] as $cfile)
          {
            if(basename($cfile) == $searchfile)
            {
              $try_file = $cfile;
              break;
            }
          }
        }

        // try to open include file name
        if ( $inc_lines = @file( $try_file ) )
        {		
          $include = '// successfully analysed';
          $GLOBALS['counterlines']+=count($inc_lines);

          $inc_code = implode('',$inc_lines);
          $inc_tokens = token_get_all($inc_code);	
          $inc_tokens = prepare_tokens($inc_tokens, $this->T_IGNORE);
          $inc_tokens = fix_tokens($inc_tokens);

          // insert included tokens in current tokenlist and mark end
          $tokens = array_merge(
            array_slice($tokens, 0, $i), 					// before include
            $inc_tokens, 									// included tokens
            array(array(T_INCLUDE_END, 0, $this->inc_file)), 		// extra END-identifier
            array_slice($tokens, $i+$skip) 					// after include
          );

          $tokencount = count($tokens);

          // set lines pointer to included lines, save last pointer
          // (the following tokens will be the included ones)
          $this->lines_stack[] = $inc_lines;
          $this->lines_pointer =& end($this->lines_stack);

          $this->comment = '// '.basename($this->inc_file);

          $this->inc_file_stack[] = $this->inc_file;	

          // build include map for file list
          $inc_map[] = $try_file; // all basic includes

          // decrease token counter because we replaced the include with included tokens
          // and dont wont to miss the first token of these
          $i--;
        } 
        // included file name could not be reversed 
        // (probably dynamic with function calls)
        else
        {
          $include = "// could not analyse file, tried: $try_file";
          $GLOBALS['count_inc_fail']++;
          $this->inc_file = $last_inc_file;
        }
      }
      else
      {
        $include = "// $this->inc_file has already been included";
        $this->inc_file = $last_inc_file;
      }

      // add information about include success in debug mode
      if( $GLOBALS['verbosity'] == 5 )
      {
        // add include command to output
        $found_value = highlightline(trim($found_line)."\t".$include, $line_nr, $token_value);
        $new_find = new InfoTreeNode($found_value);
        $new_find->lines[] = $line_nr;

        // if in included code, set file name
        if(!empty($last_inc_file))
          $new_find->filename = dirname($this->file_name) . '/' . $last_inc_file;

        $id = (isset($GLOBALS['output'][$this->file_name])) ? 
          count($GLOBALS['output'][$this->file_name]) : 0;
          $GLOBALS['output'][$this->file_name][$id] = $new_find;
      }
    }	
  }
  
  /**
   * get_dependencies: Get current dependencies in program flow
   */
  function get_dependencies($i, $token_name, $token_value, $line_nr) {
    if($token === '{' 
    && ($tokens[$i-1] === ')' || $tokens[$i-1] === ':'
    || (is_array($tokens[$i-1])
    && ($tokens[$i-1][0] === T_DO  // do {
    || $tokens[$i-1][0] === T_ELSE // else {
    || $tokens[$i-1][0] === T_STRING)) ) ) // class bla {
    {
      // save brace amount at start of function
      if($this->in_function && $this->brace_save_func < 0) 
      {
        $this->brace_save_func = $this->braces_open;
      }	

      // save brace amount at start of class
      if($this->in_class && $this->brace_save_class < 0)
      {
        $this->brace_save_class = $this->braces_open;
      }

      if(empty($e))
      {
        $k=1;
        // line_nr of the token before '{'
        while( !is_numeric($line_nr) )
        {
          $line_nr = $tokens[$i-$k][2];
          if($k>50)break;
          $k++;
        }

        $dependency = '';

        if(!$this->ignore_requirement)
        {
          //$dependency = $this->getmultiline($this->lines_pointer, $line_nr-1);
          $dependency  = trim($this->lines_pointer[$line_nr-1]);
          // if dependency is 'else' we want the 'if'
          if( preg_match('/else\s*[^\w]*$/i', $dependency) ) 
            $dependency = trim($last_dependency).'else';
        } else
        {
          $this->ignore_requirement = false;
        }

        // add dependency (even push empty dependency on stack, it will get poped again)
        $this->dependencies[$line_nr] = $dependency;					
      } else
      {
        unset($e);
      }

      $this->braces_open++;
    }
  }
  
  /**
   * block_ending_evaluation: 
   */
  function block_ending_evaluation($i, $token_name, $token_value, $line_nr) {
    if( $token === '}' 
    && ($tokens[$i-1] === ';' || $tokens[$i-1] === '}' || $tokens[$i-1] === '{') )
    {
      $this->braces_open--;

      // delete current dependency
      $last_dependency = array_pop($this->dependencies);

      // end of function found if brace amount = amount before function start
      if($this->in_function && $this->brace_save_func === $this->braces_open)
      {
        // write ending to user_function list for referencing functions in output
        $GLOBALS['user_functions_offset'][$ref_name][2] = $line_nr;
        // reset vars for next function declaration
        $this->brace_save_func = -1;
        $this->in_function = false;
        $this->ignore_securing_function = false;
        $function_params = array();
        $this->var_declares_local = array();
        $this->put_in_global_scope = array();
        // load new found vulnerable user functions to current scanlist
        if(isset($GLOBALS['user_functions'][$this->file_name]))
        {
          $this->scan_functions = array_merge($this->scan_functions, 
                  $GLOBALS['user_functions'][$this->file_name]);				
        }
      }

      // end of class found
      if($this->in_class && $this->brace_save_class === $this->braces_open)
      {
        $this->brace_save_class = -1;
        $this->in_class = false;
      }
    }
  }
  
  /**
   * check_for_function_calls: Check if token is function call that affects variable scope (global)
   */
  function check_for_function_calls($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_STRING && $tokens[$i+1] === '(' && isset($this->globals_from_function[$token_value]) )
    {	
      // put all previously saved global var assignments to global scope
      foreach($this->globals_from_function[$token_value] as $var_name=>$new_vars)
      {
        foreach($new_vars as $new_var)
        {
          $new_var->value = $new_var->value . "// put in global scope by $token_value()";
          if(!isset($this->var_declares_global[$var_name]))
            $this->var_declares_global[$var_name] = array($new_var);
          else
            array_unshift($this->var_declares_global[$var_name], $new_var);
        }		
      }
    }
  }
  
  /**
   * add_interesting_function_calls: Add interesting function calls to info gathering	
   */
  function add_interesting_function_calls($i, $token_name, $token_value, $line_nr) {
		if( isset($this->F_INTEREST[$token_value]) && $tokens[$i+1] === '(' )
		{
  		$GLOBALS['info'][] = $this->F_INTEREST[$token_value];
		}	
  }
  
  /**
   * token_is_class_declaration: Check if token is a class declaration
   */
  function token_is_class_declaration($i, $token_name, $token_value, $line_nr) {
    if($token_name === T_CLASS)
    {
      $i++;
      $class_name = $tokens[$i][1];
      $this->vuln_classes[$class_name] = array();
      $this->in_class = true;
    }
  }
  
  /**
   * scan_parameter: Traces recursivly parameters and adds them as child to parent.
   * Returns true if a parameter is tainted by userinput.
   */
	function scan_parameter($mainparent, $parent, $var_name, $var_declares, $last_token_id, $var_declares_global=array(), $function_params, $function_obj, $userinput, $F_SECURES, $return_scan=false, $ignore_securing=false, $secured='')
	{	
		if($var_name[0] !== '$')
			$var_name = strtoupper($var_name);
			
		$vardependent = false;
		$ignore_var = '';

		$arrayname = explode('[', $var_name);
		
		// if $array[key] was not declared explicitly scan for $array
		if(isset($arrayname[1]))
		{
			if($arrayname[0] == '$GLOBALS' && !isset($var_declares[$var_name]) && !empty($arrayname[1]) ) 
			{
				$var_name = '$'. str_replace(array('"', "'", ']'), '', $arrayname[1]);
				// php $GLOBALS: ignore previous local vars and take only global vars
				$var_declares = $var_declares_global;
			}
			else if($arrayname[0] == '$_SESSION' && !isset($var_declares[$var_name]) && !empty($arrayname[1]) && !empty($var_declares_global))
			{
				// $_SESSION data is handled as global variables
				$var_declares = array_merge($var_declares_global, $var_declares);
			}
			// if array[key] was not defined, scan for array itself
			else if(!isset($var_declares[$var_name]) )
				$var_name = $arrayname[0]; 
		}

		// check if var declaration could be found for this var
		if( isset($var_declares[$var_name]) )
		{	
			foreach($var_declares[$var_name] as $var_declare)
			{	
				$line_nr = $var_declare->line;
				$line = $var_declare->value;
				$token_id = $var_declare->id;

				if( $token_id < $last_token_id )
				{	
					// add line to output
					if(count($mainparent->lines) < $GLOBALS['maxtrace'])				
					{
						$foundvalue = $line;
						if(	$mainparent->dependencies != $var_declare->dependencies )
						{							
							foreach($var_declare->dependencies as $deplinenr=>$dependency)
							{
								if( !isset($mainparent->dependencies[$deplinenr]) && $deplinenr != $line_nr )
								{
									$vardependent = true;
									$foundvalue = $foundvalue.' // '.trim($dependency);
								}
							}
						}

						$mainparent->lines[] = $line_nr;	
						$var_trace = new VarDeclare('');
						$parent->children[] = $var_trace;
					} else
					{	
						$stop = new VarDeclare('... Trace stopped.');
						$parent->children[] = $stop; 
						return $userinput;
					}
						
					// find other variables in this line
					$tokens = token_get_all('<?'.trim($line).'?>');
					$tokens = prepare_tokens($tokens, $GLOBALS['T_IGNORE']);
					$last_scanned = '';
					$last_userinput = false;
					$in_arithmetic = false;
					$in_securing = '';
					$parentheses_open = 0;
					$parentheses_save = -1;
					
					$tainted_vars = array();
					$var_count = 1;
					
					for($i=1, $maxtokens=count($tokens); $i<$maxtokens; $i++)
					{
						if( is_array($tokens[$i]) )
						{
							// if token is variable or constant
							if( ($tokens[$i][0] === T_VARIABLE && $tokens[$i][1] !== $ignore_var)
							|| ($tokens[$i][0] === T_STRING && $tokens[$i+1] !== '(') )
							{	
								$var_count++;
								$new_token_trace = $tokens[$i][1];

								// trace $var['keyname'] (if available) not only $var
								if($tokens[$i+1] === '['
								&& isset($tokens[$i+2][1])
								&& (isset($var_declares[$new_token_trace.'['.$tokens[$i+2][1].']'])
								|| in_array($new_token_trace, $GLOBALS['V_USERINPUT']) 
								|| $new_token_trace === '$GLOBALS' || $new_token_trace === '$_SESSION'))
								{
									$new_token_trace = $new_token_trace.'['.$tokens[$i+2][1].']';
								}	

								// check if typecast or securing function wrapped
								if((is_array($tokens[$i-1]) 
								&& in_array($tokens[$i-1][0], $GLOBALS['T_CASTS']))
								|| (is_array($tokens[$i+1]) 
								&& in_array($tokens[$i+1][0], $GLOBALS['T_CASTS'])) 
								|| !empty($in_securing) )
								{
									// mark user function as a securing user function
									$GLOBALS['userfunction_secures'] = true;
									if(!empty($in_securing))
										$secured = $in_securing;
									else
										$secured = 'typecast';
								
									$var_trace->marker = 2;
								} 
								
								// check for automatic typecasts by arithmetic
								if(in_array($tokens[$i-1], $GLOBALS['T_ARITHMETIC'])
								|| in_array($tokens[$i+1], $GLOBALS['T_ARITHMETIC'])
								|| $in_arithmetic)
								{
									// mark user function as a securing user function
									$GLOBALS['userfunction_secures'] = true;
									$secured = 'arithemetic';
									
									$in_arithmetic = true;
									
									$var_trace->marker = 2;
								}
								
								// global $varname
								if( (is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_GLOBAL) || $new_token_trace[0] !== '$' )
								{	
									// scan in global scope
									$userinput = $this->scan_parameter($this->file_name, $mainparent, $var_trace, 
								$new_token_trace, $var_declares_global, $token_id, 
								$var_declares_global, $function_params, $function_obj, $userinput,
								$F_SECURES, $return_scan, $ignore_securing, $secured);
								// scan in local scope
								} else
								{
									$userinput = $this->scan_parameter($this->file_name, $mainparent, $var_trace, 
								$new_token_trace, $var_declares, $token_id, 
								$var_declares_global, $function_params, $function_obj, $userinput,
								$F_SECURES, $return_scan, $ignore_securing, $secured);
								}
								
								if(!empty($secured) && $GLOBALS['verbosity'] < 3 && !$last_userinput) 
								{
									$userinput = false;
								}	
								
								// add tainted variable to the list to get them highlighted in output
								if($userinput && !$last_userinput)
								{
									$tainted_vars[] = $var_count;
								}
							}
							// if in foreach($bla as $key=>$value) dont trace $key, $value back
							else if( $tokens[$i][0] === T_AS )
							{
								break;
							}
							// if tokens is mathematical assignment like $a.=$b, trace $a again
							else if( in_array($tokens[$i][0], $GLOBALS['T_ASSIGNMENT']) )
							{
								$tokens = array_merge(
									array_slice($tokens, 0, $i), 
									array('='), array($tokens[$i-1]),
									array_slice($tokens, $i+1)
								);	
								$maxtokens = count($tokens);
							} 
							// also check for userinput from functions defined as userinput
							else if( in_array($tokens[$i][1], $GLOBALS['F_USERINPUT']) )
							{
								$userinput = true;
								$var_trace->marker = 4;
	
								if($return_scan)
								{
									$GLOBALS['userfunction_taints'] = true;
								}	
								// userinput received in function, just needs a trigger
								else if($function_obj !== null)
								{
									$this->addtriggerfunction($mainparent, $function_obj, $this->file_name);
								}	
								
								// we could return here to not scan all parameters of the tainting function
								// however we need to add the line manually to the output at this point
							}
							// detect securing functions
							else if(!$ignore_securing && (in_array($tokens[$i][1], $F_SECURES)
							|| (isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_SECURING_STRING'])) 
							|| (in_array($tokens[$i][0], $GLOBALS['T_CASTS']) && $tokens[$i+1] === '(') )  )
							{
								$parentheses_save = $parentheses_open;
								$in_securing = $tokens[$i][1];
							}
							//detect insecuring functions (functions that make previous securing useless)
							else if( isset($tokens[$i][1]) && in_array($tokens[$i][1], $GLOBALS['F_INSECURING_STRING']))
							{
								$parentheses_save = $parentheses_open;
								$ignore_securing = true;
							}
							// if this is a vuln line, it has already been scanned -> return
							else if( in_array($tokens[$i][0], $GLOBALS['T_FUNCTIONS']) 
							&& isset($GLOBALS['scan_functions'][$tokens[$i][1]]) 
							// ignore oftenly used preg_replace() and alike
							&& !isset($GLOBALS['F_CODE'][$tokens[$i][1]]) )
							{
								$var_trace->value = highlightline($foundvalue.' // stopped, already traced', $line_nr);
								$var_trace->line = $line_nr;
								return $userinput;
							}
						}
						// string concat disables arithmetic
						else if($tokens[$i] === '.')
						{
							$in_arithmetic = false;
						}
						// watch opening parentheses
						else if($tokens[$i] === '(')
						{
							$parentheses_open++;
						}
						// watch closing parentheses
						else if($tokens[$i] === ')')
						{
							$parentheses_open--;
							if($parentheses_open === $parentheses_save)
							{
								$parentheses_save = -1;
								$in_securing = '';
								$ignore_securing = false;
							}
						}						
						// special case for var declaration in constructs
						else if( is_array($tokens[$i-1]) )
						{
							// assignments in a if()/while() need to skip the var declaring name
							if( $tokens[$i-1][0] === T_IF || $tokens[$i-1][0] === T_WHILE)
							{
								// if($h = fopen($asd)) , $h should not be traced back
								$i+=2;
							}
							// ignore first variable in for($i=0;...)
							else if( $tokens[$i-1][0] === T_FOR )
							{
								$ignore_var = $tokens[$i+1][1];
							}
						}
						
						// break if several commands have been in one line
						if($tokens[$i] === ';')
						{
							break;
						}
											
						// save userinput (true|false) for vars in same line
						$last_userinput = $userinput;
					}

					// add highlighted line to output, mark tainted vars
					$var_trace->value = highlightline($foundvalue, $line_nr, false, false, $tainted_vars);
					$var_trace->line = $line_nr;
					
					// we only need the last var declaration, other declarations have been overwritten
					if( $userinput || !$vardependent ) 
						break;
				}
			}
		}

		// if var comes from function parameter AND has not been overwritten with static content before (else)
		else if( in_array($arrayname[0], $function_params) && ($GLOBALS['verbosity'] >= 3 || empty($secured)) )
		{
			// add child with function declaration
			$func_name = $function_obj->name;
			$mainparent->lines[] = $function_obj->lines[0];
			if($function_obj->marker !== 3)
			{
				$function_obj->value = makefunclink($function_obj->value, $function_obj->lines[0], $function_obj->name);
				// mark as potential userinput
				$function_obj->marker = 3;
			}
			$parent->children[] = $function_obj;
			$mainparent->title = $mainparent->title . " in user defined function <i>$func_name</i> (click declaration to jump to call)";
			
			// add function to scanlist
			$key = array_search($arrayname[0], $function_params);
			$mainparent->funcdepend = $func_name;
			// with potential parameters
			$GLOBALS['user_functions'][$this->file_name][$func_name][0][$key] = $key+1;
			// and with according securing functions from original find					
			$GLOBALS['user_functions'][$this->file_name][$func_name][1] = isset($GLOBALS['scan_functions'][$mainparent->name]) ? 
				$GLOBALS['scan_functions'][$mainparent->name][1] : $GLOBALS['user_functions'][$this->file_name][$mainparent->name][1];

			$userinput = true;
		}			
		// if var is userinput, return true directly	
		if( in_array($arrayname[0], $GLOBALS['V_USERINPUT']) && empty($secured) )
		{
			// check if userinput variable has been overwritten
			$overwritten = false;
			if(isset($var_declares[$arrayname[0].'['.$arrayname[1]]))
			{
				foreach($var_declares[$arrayname[0].'['.$arrayname[1]] as $var)
				{
					// if there is a var declare for this userinput !except the same line!: overwritten
					if($last_token_id != $var->id)
						$overwritten = true;
				}
			}	
			
			if(!$overwritten)
			{
				$GLOBALS['securedbyfunc'][] = $secured;
			
				// add userinput markers to mainparent object
				if(isset($arrayname[1]))
					$parameter_name = str_replace(array('"', "'", ']'), '', $arrayname[1]);
				
				// mark tainted, but only specific $_SERVER parameters
				if($arrayname[0] !== '$_SERVER'
				|| in_array($parameter_name, $GLOBALS['V_SERVER_PARAMS']) )
				{
					$userinput = true;
					$parent->marker = 1;			

					$this->addexploitparameter($mainparent, $arrayname[0], $parameter_name);
					
					// analyse depencies for userinput and add it for exploit creator
					if(!empty($mainparent->dependencies))
					{
						foreach($mainparent->dependencies as $dependency)
						{
							$tokens = token_get_all('<?php '.$dependency.' ?'.'>');
							$tokens = prepare_tokens($tokens, $GLOBALS['T_IGNORE']);
							$tokens = fix_tokens($tokens);
							for($t=0;$t<count($tokens);$t++)
							{
								if($tokens[$t][0] === T_VARIABLE && $tokens[$t+1] === '[' && in_array($tokens[$t][1], $GLOBALS['V_USERINPUT']) && ($tokens[$t][1] !== '$_SERVER' || in_array($tokens[$t+2][1], $GLOBALS['V_SERVER_PARAMS'])))
								{
									$this->addexploitparameter($mainparent, $tokens[$t][1], str_replace("'", '', $tokens[$t+2][1]));		
								}
							}
						}
					}
				}
							
				// userinput received in function, just needs a trigger
				if($function_obj !== null && !$return_scan)
				{
					$this->addtriggerfunction($mainparent, $function_obj, $this->file_name);
				}
			}
		} 
				
		return $userinput;
	}
  
  /**
   * read_recursiv: Get all php files from directory, including all subdirectories
   */
	function read_recursiv($path, $scan_subdirs)
	{  
		$result = array(); 

		$handle = opendir($path);  

		if ($handle)  
		{  
			while (false !== ($file = readdir($handle)))  
			{  
				if ($file !== '.' && $file !== '..')  
				{  
					$name = $path . '/' . $file; 
					if (is_dir($name) && $scan_subdirs) 
					{  
						$ar = $this->read_recursiv($name, true); 
						foreach ($ar as $value) 
						{ 
							if(in_array(substr($value, strrpos($value, '.')), $GLOBALS['filetypes']))
								$result[] = $value; 
						} 
					} else if(in_array(substr($name, strrpos($name, '.')), $GLOBALS['filetypes'])) 
					{  
						$result[] = $name; 
					}  
				}  
			}  
		}  
		closedir($handle); 
		return $result;  
	}  

	/**
   * addexploitparameter: Add exploit parameter to parent
   */
	function addexploitparameter($parent, $type, $parameter_name)
	{
		if(!empty($parameter_name))
		{
			switch($type)
			{
				case '$_GET': 				$parent->get[] = $parameter_name; break;
				case '$HTTP_GET_VARS': 		$parent->get[] = $parameter_name; break;
				case '$_REQUEST': 			$parent->get[] = $parameter_name; break;
				case '$HTTP_REQUEST_VARS':	$parent->get[] = $parameter_name; break;
				case '$_POST': 				$parent->post[] = $parameter_name; break;
				case '$HTTP_POST_VARS':		$parent->post[] = $parameter_name; break;
				case '$HTTP_RAW_POST_DATA':	$parent->post[] = $parameter_name; break;
				case '$_COOKIE': 			$parent->cookie[] = $parameter_name; break;
				case '$HTTP_COOKIE_VARS':	$parent->cookie[] = $parameter_name; break;
				case '$_FILES': 			$parent->files[] = $parameter_name; break;
				case '$HTTP_POST_FILES':	$parent->files[] = $parameter_name; break;
				case '$_SERVER':			$parent->server[] = $parameter_name; break;
			}
		}
	}
	
	/**
   * addtriggerfunction: Add function to output that triggers something by call
   */
	function addtriggerfunction($mainparent, $function_obj, $file_name)
	{
		// add dependency and mark this as interesting function
		$func_name = $function_obj->name;
		$mainparent->dependencies[$function_obj->lines[0]] = $function_obj->value;
		$mainparent->title = $mainparent->title . " (triggered by function call <i>$func_name()</i>)";
		
		// add function to scanlist
		$mainparent->funcdepend = $func_name;
		// with all parameters as valuable since userinput comes from inside the func
		$GLOBALS['user_functions'][$file_name][$func_name][0][0] = 0;
		// no securings				
		$GLOBALS['user_functions'][$file_name][$func_name][1] = array();
		// doesnt matter if with userinput called or not
		$GLOBALS['user_functions'][$file_name][$func_name][3] = true;
	}
	
	/**
   * get_var_value: Traces values of variables and reconstructs string for dynamic file includes
   */
	function get_var_value($var_name, $var_declares, $var_declares_global, $last_token_id)
	{
		$var_value = '';
		
		// CONSTANTS
		if($var_name[0] !== '$')
			$var_name = strtoupper($var_name);

		// check if var declaration could be found for this var
		if( isset($var_declares[$var_name]) )
		{
			foreach($var_declares[$var_name] as $var_declare)
			{
				$token_id = $var_declare->id;

				if( $token_id < $last_token_id )
				{
					$line = $var_declare->value;
															
					// find other variables in this line
					$tokens = token_get_all('<?'.trim($line).'?>');
					$tokens = prepare_tokens($tokens, $GLOBALS['T_IGNORE']);
					
					for($i=($tokens[1] === '[') ? 3:1, $max=count($tokens); $i<$max; $i++)
					{				
						if( is_array($tokens[$i]) )
						{
							$token_name = $tokens[$i][0];
							$token_value = $tokens[$i][1];

							// if token is variable trace again
							if( $token_name === T_VARIABLE 
							|| ($token_name === T_STRING && $tokens[$i+1] !== '(' ) )
							{	
								if(!in_array($token_value, $GLOBALS['V_USERINPUT']))
								{
									$var_trace = $token_value;
									// trace $var['keyname'] (if available) not only $var
									if($tokens[$i+1] === '['
									&& isset($var_declares[$var_trace.'['.$tokens[$i+2][1].']']) 
									|| $var_trace === '$GLOBALS' )
									{
										$var_trace = $var_trace.'['.$tokens[$i+2][1].']';
										$i=$i+2;
									}		
		
									// constant CONSTANTS
									if ($token_value == 'DIRECTORY_SEPARATOR' || $token_value == 'PATH_SEPARATOR')
									{
										$var_value.='/';
									}
									// global $varname -> global scope, CONSTANTS
									else if( (is_array($tokens[$i-1]) && $tokens[$i-1][0] === T_GLOBAL) || $token_value[0] !== '$' )
									{
										$var_value.= $this->get_var_value($var_trace, 
										$var_declares_global, $var_declares_global, $token_id);
									} 
									// local scope
									else
									{
										$var_value.= $this->get_var_value($var_trace, 
										$var_declares, $var_declares_global, $token_id);
									}
								}
								else
								{
									// mark userinput for quote analysis
									$var_value.='$_USERINPUT';
									if($tokens[$i+1] === '[')
										$i=$i+3;
								}
							}
							
							// if token is string add string to output 
							// except first string of define('var', 'value')
							else if($token_name === T_CONSTANT_ENCAPSED_STRING
							&& !($tokens[$i-2][0] === T_STRING
							&& $tokens[$i-2][1] === 'define'))
							{
								// delete quotes at beginning and end and add string
								$var_value.= substr($token_value, 1, -1);
							}
							else if($token_name === T_ENCAPSED_AND_WHITESPACE)
							{
								$var_value.= $token_value;
							}
						}
					}
				}
				if(!empty($var_trace))
					break;
			}
		}
		return $var_value;
	}
		
	/**
   * getmultiline: Fetches a line from the sourcecode and checks for commands written over several lines	
   */
	function getmultiline($linenr, $count=0)
	{
		$line = trim($this->lines_pointer[$linenr]);
		$i = strlen($line)-1;
		if($count < 10 && $i>0 && $line[$i] != ';' && $line[$i] != ')' /* && $line[$i] != '(' */
		&& $line[$i] != '{' && $line[$i] != '}' && !strpos($line, '?>'))
		{
			$line .= $this->getmultiline($this->$lines_pointer, $linenr+1, $count++);
		}
		return $line;
	}
}
