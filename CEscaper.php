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
	
	public function escape_HTML($string)
	{
		$result = htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE, $this->CHARSET);
		$result = str_replace('/', '&#x2F;', $result);
		
		return $result;
	}
}

$maliciousHTML = '></title><script>alert(1)</script>&"/()<?php$var=attack?> %*+,-/;<=>^and|';

$escaper = new Escaper();

$result = $escaper->escape_HTML($maliciousHTML);

echo $result;