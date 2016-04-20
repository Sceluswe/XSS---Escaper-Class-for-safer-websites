<?php

namespace Scelus\Escaper;

/*
* All functions are based on the recommendations in the 
* XSS (Cross Site Scripting) Prevention Cheat Sheet:
* https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet
* 
*/
class CEscaperTest extends \PHPUnit_Framework_TestCase
{
	/**
     * Test 
     *
     * @return void
     */
	public function testConstructorSuccess() {
		$el = new \Scelus\Escaper\CEscaper();

        $res = $el->getEncoding();
        $exp = 'UTF-8';
        $this->assertEquals($res, $exp, "Created element name missmatch.");
	}
	
	/**
     * Test 
     *
     * @return void
     */
	public function testSetAndGetEncoding() {
		$el = new \Scelus\Escaper\CEscaper('ASCII');
		
		$res = $el->getEncoding();
		$exp = 'ASCII';
		$this->assertEquals($res, $exp, "Created element argument missmatch");
		
		$el->setEncoding('UTF-8');
		$res = $el->getEncoding();
		$exp = 'UTF-8';
		$this->assertEquals($res, $exp, "setEncoding() produced missmatch");
	}
	
	/**
     * Test 
     *
     * @return void
     */
	public function testEscapeHTML() {
		$el = new \Scelus\Escaper\CEscaper();
		
		$argument = '></div><h1>myattack</h1>';
		$res = $el->escapeHTML($argument);
		$exp = '&gt;&lt;&#x2F;div&gt;&lt;h1&gt;myattack&lt;&#x2F;h1&gt;';
		$this->assertEquals($res, $exp, "escapeHTML() produced missmatch");
	}
	
	/**
     * Test 
     *
     * @return void
     */
	public function testEscapeHTMLattr() {
		$el = new \Scelus\Escaper\CEscaper();
		
		$argument = '"><h1>Hello</table';
		$res = $el->escapeHTMLattr($argument);
		$exp = "&#x22;&#x3e;&#x3c;h1&#x3e;Hello&#x3c;&#x2f;table";
		$this->assertEquals($res, $exp, "escapeHTMLattr() produced missmatch");
	}
	
	/**
     * Test 
     *
     * @return void
     */
	public function testEscapeUrl() {
		$el = new \Scelus\Escaper\CEscaper();
		
		$argument = '"><script>alert(1)</script><a href="#';
		$res = $el->escapeUrl($argument);
		$exp = "%22%3E%3Cscript%3Ealert%281%29%3C%2Fscript%3E%3Ca%20href%3D%22%23";
		$this->assertEquals($res, $exp, "escapeUrl() produced missmatch");
	}
	
	/**
     * Test 
     *
     * @return void
     */
	public function testEscapeCSS() {
		$el = new \Scelus\Escaper\CEscaper();
		
		$argument = '"><script>alert(1)</script><a href="#';
		$res = $el->escapeCSS($argument);
		$exp = '\22 \3e \3c script\3e alert\28 1\29 \3c \2f script\3e \3c a\20 href\3d \22 \23 ';
		$this->assertEquals($res, $exp, "escapeCSS() produced missmatch");
	}
	
	/**
     * Test 
     *
     * @return void
     */
	public function testEscapeJs() {
		$el = new \Scelus\Escaper\CEscaper();
		$argument = "'; alert(100); var x='";
		$res = $el->escapeJs($argument);
		$exp = '\x27\x3b\x20alert\x28100\x29\x3b\x20var\x20x\x3d\x27';
		$this->assertEquals($res, $exp, "escapeJs() produced missmatch");
	}
	
	/**
     * Test 
     *
     * @return void
     */
	public function testEscapeXML() {
		$el = new \Scelus\Escaper\CEscaper();
		$argument = '></div><h1>myattack</h1>';
		$res = $el->escapeXml($argument);
		$exp = '&gt;&lt;&#x2F;div&gt;&lt;h1&gt;myattack&lt;&#x2F;h1&gt;';
		$this->assertEquals($res, $exp, "escapeHTML() produced missmatch");
	}
	
	/**
     * Test 
     *
     * @return void
     */
	public function testEscapeXmlattr() {
		$el = new \Scelus\Escaper\CEscaper();
		$argument = '"><h1>Hello</table';
		$res = $el->escapeXmlattr($argument);
		$exp = "&#x22;&#x3e;&#x3c;h1&#x3e;Hello&#x3c;&#x2f;table";
		$this->assertEquals($res, $exp, "escapeHTMLattr() produced missmatch");
	}
}