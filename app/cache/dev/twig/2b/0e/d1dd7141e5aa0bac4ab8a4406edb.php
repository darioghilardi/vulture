<?php

/* VultureMainBundle:Default:index.html.twig */
class __TwigTemplate_2b0ed1dd7141e5aa0bac4ab8a4406edb extends Twig_Template
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
            ";
        // line 13
        if (array_key_exists("form", $context)) {
            // line 14
            echo "            
                <form action=\"";
            // line 15
            echo twig_escape_filter($this->env, $this->env->getExtension('routing')->getPath("VultureMainBundle_homepage"), "html");
            echo "\" method=\"post\" ";
            echo $this->env->getExtension('form')->renderEnctype($this->getContext($context, 'form'));
            echo ">
                    ";
            // line 16
            echo $this->env->getExtension('form')->renderWidget($this->getContext($context, 'form'));
            echo "

                    <input id=\"submit\" type=\"submit\" />
                </form>
            
            ";
        } elseif ($this->getContext($context, 'results')) {
            // line 22
            echo "            
                <h2>Scanned files</h5>
                <ul>
                    ";
            // line 25
            $context['_parent'] = (array) $context;
            $context['_seq'] = twig_ensure_traversable($this->getContext($context, 'files'));
            foreach ($context['_seq'] as $context['_key'] => $context['file']) {
                // line 26
                echo "                        <li>";
                echo twig_escape_filter($this->env, $this->getContext($context, 'file'), "html");
                echo "</li>
                    ";
            }
            $_parent = $context['_parent'];
            unset($context['_seq'], $context['_iterated'], $context['_key'], $context['file'], $context['_parent'], $context['loop']);
            $context = array_merge($_parent, array_intersect_key($context, $_parent));
            // line 28
            echo "                </ul>
                    
            ";
        }
        // line 31
        echo "
            <div id=\"output\">
                <h3>Help:</h3>
                <p>Locate the path to the PHP files you would like to scan and click the launch button. You can also submit a directory 
                    that Vulture will recursively scan.</p>
                <p>Note that scanning too many large files may exceed the time limit.</p>

            </div>

        </div>
    </div>
";
    }

    public function getTemplateName()
    {
        return "VultureMainBundle:Default:index.html.twig";
    }

    public function isTraitable()
    {
        return false;
    }
}
