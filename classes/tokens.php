<?php

class token {
  
  // Store tokens
  public $tokens = array();
  
  /**
   * Constructor
   */
  public function __construct($code) {
    $this->tokens = token_get_all($code);
  }
  
  /**
   * Delete all tokens to ignore while scanning, mostly whitespaces	
   */
	function prepare_tokens($T_IGNORE)
	{	
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
	}	
	
	/**
   * Adds braces around offsets
   */
	function wrapbraces($start, $between, $end)
	{
		$this->tokens = array_merge(
			array_slice($this->tokens, 0, $start), array('{'), 
			array_slice($this->tokens, $start, $between), array('}'),
			array_slice($this->tokens, $end)
		);
	}
		
	/**
   *  Some tokenchains need to be fixed to scan correctly later	
   */
	function fix_tokens()
	{	
		for($i=0; $i<count($this->tokens); $i++)
		{
      $this->backticks($i);
      $this->rewrite_graphs($i);
      $this->token_process($i);
		}
		// return tokens with rearranged key index
    print_r($this->tokens);
		$this->tokens = array_values($this->tokens);
	}
  
  /**
   * Convert `backticks` to backticks()
   */
  function backticks ($i) {
    if( $this->tokens[$i] === '`' )
    {		
      $f=1;
      while( $this->tokens[$i+$f] !== '`' && $this->tokens[$i+$f] !== ';' )
      {		
        // get line_nr of any near token
        if( is_array($this->tokens[$i+$f]) )
          $line_nr = $this->tokens[$i+$f][2];

        if($f>50)break;

        $f++;
      }
      if(!empty($line_nr))
      { 
        $this->tokens[$i+$f] = ')';
        $this->tokens[$i] = array(T_STRING, 'backticks', $line_nr);

        // add element backticks() to array 			
        $this->tokens = array_merge(
          array_slice($this->tokens, 0, $i+1), array('('), 
          array_slice($this->tokens, $i+1)
        );	
      }
    }
  }
  
  /**
   * Rewrite $array{index} to $array[index]
   */
  function rewrite_graphs($i) {
    if( $this->tokens[$i] === '{'
    && ((is_array($this->tokens[$i-1]) && $this->tokens[$i-1][0] === T_VARIABLE)
    || $this->tokens[$i-1] === ']') )
    {
      $this->tokens[$i] = '[';
      $f=1;
      while($this->tokens[$i+$f] !== '}')
      {
        $f++;
      }
      $this->tokens[$i+$f] = ']';
    }
  }
  
  /**
   * Manage real tokens
   */
  function token_process($i) {
    if( is_array($this->tokens[$i]) )
    {
      $this->if_rebuild($i);
      $this->else_rebuild($i);
      $this->switch_rebuild($i);
      $this->switch_default_rebuild($i);
      
      // lowercase all function names because PHP doesn't care	
      if( $this->tokens[$i][0] === T_FUNCTION )
      {
        $this->tokens[$i+1][1] = strtolower($this->tokens[$i+1][1]);
      }	
      if( $this->tokens[$i][0] === T_STRING )
      {
        $this->tokens[$i][1] = strtolower($this->tokens[$i][1]);
      }	
    }	
  }
  
  
  /** 
   * Rebuild if-clauses without { }
   */
  function if_rebuild($i) {
    if ($this->tokens[$i][0] === T_IF || $this->tokens[$i][0] === T_ELSEIF )
    {				
      $f=4; $start=$end=0;
      while( $this->tokens[$i+$f] !== '{' )
      {		
        // idea: if there is a var or functioncall with a ')' infront 
        // it must be a if() without { }
        if( is_array($this->tokens[$i+$f])
        && $this->tokens[$i+$f-1] === ')' 
        && ($this->tokens[$i+$f][0] === T_VARIABLE
        || in_array($this->tokens[$i+$f][0], $GLOBALS['T_FUNCTIONS']) ) )
          $start = $i+$f;

        if ( $this->tokens[$i+$f] === ';' )
        {
          $end = $i+$f; break;
        }

        if($f>50)break;

        $f++;
      }

      if($start && $end)
      { 
        $this->tokens = wrapbraces($start, $end-$start+1, $end+1);
        $i = $start;
      }		
    } 
  }
  
  /** 
   * Rebuild else without { }
   */
  function else_rebuild($i) {
    if( $this->tokens[$i][0] === T_ELSE 
    && $this->tokens[$i+1][0] !== T_IF
    && $this->tokens[$i+1] !== '{')
    {	
      $f=2;
      while( $this->tokens[$i+$f] !== ';' )
      {		
        if($f>50)break;
        $f++;
      }
      $this->tokens = wrapbraces($i+1, $f, $i+$f+1);
    }
  }
  
  /**
   * Switch rebuild: without {}
   */
  function switch_rebuild($i) {
    if( $this->tokens[$i][0] === T_CASE
    && $this->tokens[$i+2] === ':'
    && $this->tokens[$i+3] !== '{' )
    {
      $f=3;
      while( isset($this->tokens[$i+$f]) 
      && !(is_array($this->tokens[$i+$f]) && $this->tokens[$i+$f][0] === T_BREAK ) )
      {		
        if($f>250)break;
        $f++;
      }
      $this->tokens = wrapbraces($i+3, $f-1, $i+$f+2);
      $i++;
    }
  }
  
  /**
   * Switch default value rebuild: without {}
   */
  function switch_default_rebuild($i) {	
    if( $this->tokens[$i][0] === T_DEFAULT
    && $this->tokens[$i+2] !== '{' )
    {
      $f=2;
      while( $this->tokens[$i+$f] !== ';' )
      {		
        if($f>250)break;
        $f++;
      }
      $this->tokens = wrapbraces($i+2, $f-1, $i+$f+1);
    }
  }
}
?>
