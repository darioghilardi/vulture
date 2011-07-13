<?php

namespace Vulture\MainBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Vulture\MainBundle\Entity\Scan;

class DefaultController extends Controller
{
    
    public function indexAction()
    {
        $scan = new Scan();
        $form = $this->createFormBuilder($scan)
            ->add('path', 'text', array('label' => 'File o Directory'))
            ->getForm();

        $request = $this->get('request');
        if ($request->getMethod() == 'POST') {
            $form->bindRequest($request);

            if ($form->isValid()) {
                
                // Execute the scan process
                
                // Get the configuration
                $scan->conf = $this->container->getParameter('vulture_main');
                
                // Search for files to scan into the directory
                $scan->getFiles();
                
                // Output the results                
                return $this->render('VultureMainBundle:Default:index.html.twig', array(
                    'results' => true,
                    'files' => $scan->files,
                ));
                
                //return $this->redirect($this->generateUrl('VultureMainBundle_results'));
            }
        }
        
        return $this->render('VultureMainBundle:Default:index.html.twig', array(
            'form' => $form->createView(),
        ));
    }
    
    
    public function resultsAction()
    {
        return $this->render('VultureMainBundle:Default:results.html.twig');
        
    }
    
}
