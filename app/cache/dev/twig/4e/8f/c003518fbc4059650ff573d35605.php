<?php

/* ::base.html.twig */
class __TwigTemplate_4e8fc003518fbc4059650ff573d35605 extends Twig_Template
{
    public function __construct(Twig_Environment $env)
    {
        parent::__construct($env);

        $this->blocks = array(
            'title' => array($this, 'block_title'),
            'stylesheets' => array($this, 'block_stylesheets'),
            'body' => array($this, 'block_body'),
            'javascripts' => array($this, 'block_javascripts'),
        );
    }

    protected function doDisplay(array $context, array $blocks = array())
    {
        $context = array_merge($this->env->getGlobals(), $context);

        // line 1
        echo "<!doctype html>
    <!--[if lt IE 7 ]> <html lang=\"en\" class=\"no-js ie6\"> <![endif]-->
    <!--[if IE 7 ]>    <html lang=\"en\" class=\"no-js ie7\"> <![endif]-->
    <!--[if IE 8 ]>    <html lang=\"en\" class=\"no-js ie8\"> <![endif]-->
    <!--[if IE 9 ]>    <html lang=\"en\" class=\"no-js ie9\"> <![endif]-->
    <!--[if (gt IE 9)|!(IE)]><!--> <html lang=\"en\" class=\"no-js\"> <!--<![endif]-->
    <head>
        <meta charset=\"UTF-8\">
        <meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge,chrome=1\">

        <title>";
        // line 11
        $this->displayBlock('title', $context, $blocks);
        echo "</title>
        <meta name=\"description\" content=\"\">
        <meta name=\"author\" content=\"\">

        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">

        <link rel=\"shortcut icon\" href=\"/favicon.ico\">
        <link rel=\"apple-touch-icon\" href=\"/apple-touch-icon.png\">
        
        ";
        // line 20
        $this->displayBlock('stylesheets', $context, $blocks);
        // line 23
        echo "    
        </head>
    <body>
        
        ";
        // line 27
        $this->displayBlock('body', $context, $blocks);
        // line 28
        echo "    
        <footer>
            <p>Vulture - &copy; 2011 Dario Ghilardi</p>
        </footer>

        ";
        // line 33
        $this->displayBlock('javascripts', $context, $blocks);
        // line 44
        echo "    </body>
</html>";
    }

    // line 11
    public function block_title($context, array $blocks = array())
    {
        echo "Vulture - Static source code analyzer for PHP vulnerabilities.";
    }

    // line 20
    public function block_stylesheets($context, array $blocks = array())
    {
        // line 21
        echo "            <link rel=\"stylesheet\" href=\"";
        echo twig_escape_filter($this->env, $this->env->getExtension('assets')->getAssetUrl("bundles/vulturemain/css/style.css"), "html");
        echo "\">
        ";
    }

    // line 27
    public function block_body($context, array $blocks = array())
    {
    }

    // line 33
    public function block_javascripts($context, array $blocks = array())
    {
        // line 34
        echo "            <script src=\"js/libs/modernizr-1.7.min.js\"></script>    
            <script src=\"//ajax.googleapis.com/ajax/libs/jquery/1.5.1/jquery.min.js\"></script>
            <script>!window.jQuery && document.write(unescape('%3Cscript src=\"js/libs/jquery-1.5.1.min.js\"%3E%3C/script%3E'))</script>
            <script src=\"js/plugins.js\"></script>
            <script src=\"js/script.js\"></script>
            <!--[if lt IE 7 ]>
            <script src=\"js/libs/dd_belatedpng.js\"></script>
            <script> DD_belatedPNG.fix('img, .png_bg');</script>
            <![endif]-->
        ";
    }

    public function getTemplateName()
    {
        return "::base.html.twig";
    }

    public function isTraitable()
    {
        return false;
    }
}
