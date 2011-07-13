<?php

/* VultureMainBundle:Default:results.html.twig */
class __TwigTemplate_11776a69af7343838ca6faa6784751e8 extends Twig_Template
{
    protected $parent;

    public function __construct(Twig_Environment $env)
    {
        parent::__construct($env);

        $this->blocks = array(
            'body' => array($this, 'block_body'),
        );
    }

    public function getParent(array $context)
    {
        if (null === $this->parent) {
            $this->parent = $this->env->loadTemplate("::base.html.twig");
        }

        return $this->parent;
    }

    protected function doDisplay(array $context, array $blocks = array())
    {
        $context = array_merge($this->env->getGlobals(), $context);

        $this->getParent($context)->display($context, array_merge($this->blocks, $blocks));
    }

    // line 3
    public function block_body($context, array $blocks = array())
    {
        // line 4
        echo "    <div id=\"container\">
        <header>

            <h1><a href=\"";
        // line 7
        echo twig_escape_filter($this->env, $this->env->getExtension('routing')->getPath("VultureMainBundle_homepage"), "html");
        echo "\">Vulture</a></h1>
            <h5>Static source code analyzer for PHP vulnerabilities.</h5>

        </header>

        <div id=\"main\" role=\"main\">

            <div id=\"output\">
                <h3>Results:</h3>
                <p>Results</p>

            </div>

        </div>
    </div>
";
    }

    public function getTemplateName()
    {
        return "VultureMainBundle:Default:results.html.twig";
    }

    public function isTraitable()
    {
        return false;
    }
}
