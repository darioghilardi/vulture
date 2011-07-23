<?php

/**
 * Scan Class: Find files and define parameters.
 */

namespace Vulture\MainBundle\Entity;
use Symfony\Component\Validator\Constraints as Assert;

class Scan {
    
    // Files array
    public $files;
    
    // Configuration array
    public $conf;
    
    // Path to the sources
    public $path;      
    
    /**
     * @Assert\True(message = "The provided path is not valid")
     */
    public function isValidPath()
    {        
        if (file_exists($this->path)) {
            $this->path = realpath($this->path);
            return true;
        }
        else {
            return false;
        }
    }
    
    /**
     * Get the list of allowed files from the path provided
     */
    public function getFiles()
    {   
        // If the submitted path is a directory
        if (is_dir($this->path)) {
            
            $scanSubdirs = $this->conf['subdirs'];
            $this->files = $this->readRecursiv($this->path, $scanSubdirs);

        // If the submitted path is a file
        } elseif (
              is_file($this->path) && $this->extIsAllowed($this->path)
          ) {

            $this->files[0] = $this->path;
        
        // If the submitted path is empty
        } else {
            $this->files = array();
        }
    }
    
    /**
     * Get file extension
     */
    private function getFileExtension($file) 
    {
        return substr($file, strrpos($file, '.'));
    }
    
    /**
     * Check if a file has an allowed extension
     */
    private function extIsAllowed($file)
    {        
        $ext = $this->getFileExtension($file);
        return (in_array($ext, $this->conf['filetypes']));
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