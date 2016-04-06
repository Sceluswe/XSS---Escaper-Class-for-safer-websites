<?php
class Escaper
{
	private $CHARSET;
	
	public function __construct()
	{
		isset($_SESSION['escaper_charset']) 
			? $this->CHARSET = $_SESSION['escaper_charset'] 
			: $_SESSION['escaper_charset'] = 'utf-8';
			
		$this->CHARSET = $_SESSION['escaper_charset'];
	}
	
	public function setCharset($string)
	{
		$_SESSION['escaper_charset'] = strip_tags($string);
		$this->CHARSET = $_SESSION['escaper_charset'];
	}
	
	public function escapeHTML($string)
	{
		$result = htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE, $this->CHARSET);
		$result = str_replace('/', '&#x2F;', $result);
		
		return $result;
	}
	
	public function escapeHTMLattr($string)
	{
		$result = preg_replace_callback("/[\W]/", function ($matches){
			return "&#x" . bin2hex($matches[0]) . ";";
		}, 
		$string);

		return $result;
	}
	
	public function escapeJs($string)
	{
		$result = preg_replace_callback("/[\W]/", function ($matches){
			return "\\x" . bin2hex($matches[0]);
		}, 
		$string);

		return $result;
	}
}
