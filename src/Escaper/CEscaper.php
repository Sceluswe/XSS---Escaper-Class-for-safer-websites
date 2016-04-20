<?php

namespace Scelus\Escaper;

/*
* All functions are based on the recommendations in the 
* XSS (Cross Site Scripting) Prevention Cheat Sheet:
* https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet
* 
*/
class CEscaper
{
	private $CHARSET;
	
	public function __construct($encoding = 'UTF-8') {
		isset($_SESSION['escaper_charset']) 
			? $this->CHARSET = $_SESSION['escaper_charset'] 
			: $_SESSION['escaper_charset'] = $encoding;
			
		$this->CHARSET = $_SESSION['escaper_charset'];
	}
	
	/** Sets the used charset for the esacpeHTML and escapeXML function.
	*
	* @param $value, the string/value to escape.
	*
	*/
	public function setEncoding($value) {
		$_SESSION['escaper_charset'] = strip_tags($value);
		$this->CHARSET = $_SESSION['escaper_charset'];
	}
	
	/** Returns the used charset for the esacpeHTML and escapeXML function.
	*
	* @return the current charset as a string.
	*/
	public function getEncoding() {
		return $this->CHARSET;
	}
	
	/** Escapes HTML string using htmlspecialchars().
	*
	* @param $string, the untrusted string to escape.
	*
	* @return $result, escaped string.
	*/
	public function escapeHTML($value) {
		$result = htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, $this->CHARSET);
		$result = preg_replace('/[\/]/', '&#x2F;', $result);
		
		return $result;
	}
	
	/** Escapes non-alphanumeric characters in an untrusted string for HTML attribute values.
	*
	* @param $string, the untrusted string to escape.
	*
	* @return $result, escaped string.
	*/
	public function escapeHTMLattr($value) {
		$result = preg_replace_callback("/[\W]/", function ($matches){
			return "&#x" . bin2hex($matches[0]) . ";";
		}, 
		$value);

		return $result;
	}
	
	/** Escapes non-alphanumeric characters in an untrusted string for JS input values.
	*
	* @param $string, the untrusted string to escape.
	*
	* @return $result, escaped string.
	*/
	public function escapeJs($value) {
		$result = preg_replace_callback("/[\W]/", function ($matches){
			return "\\x" . bin2hex($matches[0]);
		}, 
		$value);

		return $result;
	}
	
	/** Escapes non-alphanumeric characters in an untrusted string for CSS input values.
	*
	* @param $string, the untrusted string to escape.
	*
	* @return $result, escaped string.
	*/
	public function escapeCSS($value) {
		$result = preg_replace_callback("/[\W]/", function ($matches){
			return "\\" . bin2hex($matches[0]) . " ";
		}, 
		$value);

		return $result;
	}
	
	/** Escapes data that is to be inserted in a URL not the whole URL itself.
	* 
	* @param $string, the untrusted string to escape.
	*
	* @return, escaped string.
	*/
	public function escapeUrl($value) {
		return rawurlencode($value);
	}
	
	/**
	* Aliases to HTML functions for semantic value.
	* XML escaping is identical to HTML escaping.
	*/
	public function escapeXml($value) {
		return $this->escapeHTML($value);
	}

	public function escapeXmlAttr($value) {
		return $this->escapeHTMLattr($value);
	}
}
