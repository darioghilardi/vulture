-- phpMyAdmin SQL Dump
-- version 3.3.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generato il: 27 mag, 2011 at 06:46 PM
-- Versione MySQL: 5.1.54
-- Versione PHP: 5.3.5-1ubuntu7.2

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `rips`
--

-- --------------------------------------------------------

--
-- Struttura della tabella `csrf_01`
--

DROP TABLE IF EXISTS `csrf_01`;
CREATE TABLE IF NOT EXISTS `csrf_01` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `date` date NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

--
-- Dump dei dati per la tabella `csrf_01`
--


-- --------------------------------------------------------

--
-- Struttura della tabella `sql_injection_01`
--

DROP TABLE IF EXISTS `sql_injection_01`;
CREATE TABLE IF NOT EXISTS `sql_injection_01` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(100) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- Dump dei dati per la tabella `sql_injection_01`
--

INSERT INTO `sql_injection_01` (`id`, `username`, `password`) VALUES
(1, 'admin', 'logmein');

-- --------------------------------------------------------

--
-- Struttura della tabella `xss_stored_01`
--

DROP TABLE IF EXISTS `xss_stored_01`;
CREATE TABLE IF NOT EXISTS `xss_stored_01` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `date` date NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

--
-- Dump dei dati per la tabella `xss_stored_01`
--


-- --------------------------------------------------------

--
-- Struttura della tabella `xss_stored_02`
--

DROP TABLE IF EXISTS `xss_stored_02`;
CREATE TABLE IF NOT EXISTS `xss_stored_02` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `title` varchar(255) NOT NULL,
  `message` text NOT NULL,
  `date` date NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- Dump dei dati per la tabella `xss_stored_02`
--

INSERT INTO `xss_stored_02` (`id`, `title`, `message`, `date`) VALUES
(1, 'test', '<script>alert("xss");</script>', '2011-05-27');
