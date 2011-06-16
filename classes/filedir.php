<?php

/**
 * Filedir: a class to read files and to scan directories.
 *
 * @author Dario Ghilardi
 */
class FileDir
{
    
    public $location;
    public $subdirs;
    public $files;
    public $warnings;
  
    /**
     * Constructor function
     */
    function __construct($location, $subdirs, $warnings) 
    {
        $this->location = $location;
        $this->subdirs = $subdirs;
        $this->warnings = $warnings;
    }
    
    /**
     * Get the list of allowed files from the path provided
     */
    function getFiles()
    {   
        // Get the configuration instance
        $conf = Config::getInstance();
        
        $path = realpath($this->location);
        
        // If the submitted path is a directory
        if (is_dir($path)) {
            
            $scanSubdirs = isset($this->subdirs) ? $this->subdirs : false;
            $this->files = $this->readRecursiv($this->location, $scanSubdirs);
            
            if (
                count($this->files) > $conf->warnfiles 
                && !isset($this->warnings)
            )     
                die('warning:'.count($data));

        // If the submitted path is a file
        } elseif (
              is_file($this->location) && $this->extIsAllowed($this->location)
          ) {

            $this->files[0] = $this->location;
        
        // If the submitted path is empty
        } else {
            $this->files = array();
        }
    }
    
    /**
     * Get file extension
     */
    function getFileExtension($file) 
    {
        return substr($file, strrpos($file, '.'));
    }
    
    /**
     * Check if a file has an allowed extension
     */
    function extIsAllowed($file)
    {
        // Get the configuration instance
        $conf = Config::getInstance();
        
        $ext = $this->getFileExtension($file);
        return (in_array($ext, $conf->filetypes));
    }
  
    /**
     *  Read directories to get all php files, including all subdirectories
     */
    private function readRecursiv($path, $scanSubdirs)
    {  
        $result = array(); 
        $handle = opendir($path);  

        if ($handle) {
            
            // Scan all directories
            while (false !== ($file = readdir($handle))) {
                if ($file !== '.' && $file !== '..') {
                    $name = $path . '/' . $file;
                    
                    // If it's a directory
                    if (is_dir($name) && $scanSubdirs) {
                        // Use recursion to look inside
                        $ar = $this->readRecursiv($name, true); 
                        foreach ($ar as $value) {
                            if ($this->extIsAllowed($value))
                                $result[] = $value;
                        }
                    
                    // If it's a file with the correct extension add to results
                    } elseif ($this->extIsAllowed($name)) {
                        $result[] = $name;
                    }
                }
            }
        }
        closedir($handle);
        return $result;
    }
}