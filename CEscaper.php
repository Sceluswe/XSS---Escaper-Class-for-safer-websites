<?php

/*
* All functions are based on the recommendations in the 
* XSS (Cross Site Scripting) Prevention Cheat Sheet:
* https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet
* 
*/

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
	
	/** Sets the used charset for the esacpeHTML and escapeXML function.
	*
	* @param $string, the string to escape.
	*
	*/
	public function setCharset($string)
	{
		$_SESSION['escaper_charset'] = strip_tags($string);
		$this->CHARSET = $_SESSION['escaper_charset'];
	}
	
	/** Escapes HTML string using htmlspecialchars().
	*
	* @param $string, the untrusted string to escape.
	*
	* @return $result, escaped string.
	*/
	public function escapeHTML($string)
	{
		$result = htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE, $this->CHARSET);
		$result = str_replace('/', '&#x2F;', $result);
		
		return $result;
	}
	
	/** Escapes non-alphanumeric characters in an untrusted string for HTML attribute values.
	*
	* @param $string, the untrusted string to escape.
	*
	* @return $result, escaped string.
	*/
	public function escapeHTMLattr($string)
	{
		$result = preg_replace_callback("/[\W]/", function ($matches){
			return "&#x" . bin2hex($matches[0]) . ";";
		}, 
		$string);

		return $result;
	}
	
	/** Escapes non-alphanumeric characters in an untrusted string for JS input values.
	*
	* @param $string, the untrusted string to escape.
	*
	* @return $result, escaped string.
	*/
	public function escapeJs($string)
	{
		$result = preg_replace_callback("/[\W]/", function ($matches){
			return "\\x" . bin2hex($matches[0]);
		}, 
		$string);

		return $result;
	}
	
	/** Escapes non-alphanumeric characters in an untrusted string for CSS input values.
	*
	* @param $string, the untrusted string to escape.
	*
	* @return $result, escaped string.
	*/
	public function escapeCSS($string)
	{
		$result = preg_replace_callback("/[\W]/", function ($matches){
			return "\\" . bin2hex($matches[0]) . " ";
		}, 
		$string);

		return $result;
	}
	
	/** Escapes data that is to be inserted in a URL not the whole URL itself.
	* 
	* @param $string, the untrusted string to escape.
	*
	* @return, escaped string.
	*/
	public function escapeUrl($string)
	{
		return rawurlencode($string);
	}
	
	/**
	* Aliases to HTML functions for semantic value.
	* XML escaping is identical to HTML escaping.
	*/
	public function escapeXml($string)
	{
		return $this->escapeHTML($string);
	}

	public function escapeXmlAttr($string)
	{
		return $this->escapeHTMLattr($string);
	}
}