rule md5_6bf4910b01aa4f296e590b75a3d25642 {
    strings: $ = "base64_decode('b25lcGFnZXxnY19hZG1pbg==')"
    condition: any of them
}

rule fopo_webshell {
    strings: 
        $ = "DNEcHdQbWtXU3dSMDA1VmZ1c29WUVFXdUhPT0xYb0k3ZDJyWmFVZlF5Y0ZEeHV4K2FnVmY0OUtjbzhnc0"
        $ = "U3hkTVVibSt2MTgyRjY0VmZlQWo3d1VlaFJVNVNnSGZUVUhKZXdEbGxJUTlXWWlqWSt0cEtacUZOSXF4c"
        $ = "rb2JHaTJVdURMNlhQZ1ZlTGVjVnFobVdnMk5nbDlvbEdBQVZKRzJ1WmZUSjdVOWNwWURZYlZ0L1BtNCt"
    condition: any of them
}

rule eval_post {
    strings:
        $ = "eval(base64_decode($_POST"
        $ = "eval($undecode($tongji))"
        $ = "eval($_POST"
    condition: any of them
}

rule md5_0b1bfb0bdc7e017baccd05c6af6943ea {
	/*
		eval(hnsqqh($llmkuhieq, $dbnlftqgr));?>
		eval(vW91692($v7U7N9K, $v5N9NGE));?>
    */
    strings: $ = /eval\([\w\d]+\(\$[\w\d]+, \$[\w\d]+\)\);/
    condition: any of them
}

rule md5_2c37d90dd2c9c743c273cb955dd83ef6 {
    strings: $ = "@$_($_REQUEST['"
    condition: any of them
}

rule md5_3ccdd51fe616c08daafd601589182d38 {
    strings: $ = "eval(xxtea_decrypt"
    condition: any of them
}

rule md5_71a7c769e644d8cf3cf32419239212c7 {
	/*
    // $GLOBALS['ywanc2']($GLOBALS['ggbdg61']
    */
    strings: $ = /\$GLOBALS\['[\w\d]+'\]\(\$GLOBALS\['[\w\d]+'\]/
    condition: any of them
}

rule md5_825a3b2a6abbe6abcdeda64a73416b3d {
	/*
    // $ooooo00oo0000oo0oo0oo00ooo0ooo0o0o0 = gethostbyname($_SERVER["SERVER_NAME"]);
    // if(!oo00o0OOo0o00O("fsockopen"))
    // strings: $ = "$ooooo00oo0000oo0"
    */
    strings: $ = /[o0O]{3}\("fsockopen"\)/
    condition: any of them
}

rule md5_87cf8209494eedd936b28ff620e28780 {
    strings: $ = "curl_close($cu);eval($o);}

rule md5_8e5f7f6523891a5dcefcbb1a79e5bbe9 {
    strings: $ = "if(@copy($_FILES['file']['tmp_name'],$_FILES['file']['name'])) {echo '<b>up!!!</b><br><br>';}}

rule eval_base64_decode_a {
    strings: $ = "eval(base64_decode($a));"
    condition: any of them
}

rule obfuscated_eval {
    strings: 
	$ = /\\x65\s*\\x76\s*\\x61\s*\\x6C/
	$ = "\"/.*/e\""
    condition: any of them
}

rule md5_50be694a82a8653fa8b31d049aac721a {
    strings: $ = "(preg_match('/\\/admin\\/Cms_Wysiwyg\\/directive\\/index\\//', $_SERVER['REQUEST_URI']))"
    condition: any of them
}

rule md5_ab63230ee24a988a4a9245c2456e4874 {
    strings: $ = "eval(gzinflate(base64_decode(str_rot13(strrev("
    condition: any of them
}

rule md5_b579bff90970ec58862ea8c26014d643 {
    /* forces php execution of image files, dropped in an .htaccess file under media */
    strings: $ = /<Files [^>]+.(jpg|png|gif)>\s*ForceType application\/x-httpd-php/
    condition: any of them
}

rule base64_hidden_in_image {
    strings: $ = /JPEG-1\.1[a-zA-Z0-9\-\/]{32}/
    condition: any of them
}

rule hidden_file_upload_in_503 {
    strings: $ = /error_reporting\(0\);\$f=\$_FILES\[\w+\];copy\(\$f\[tmp_name\],\$f\[name\]\);error_reporting\(E_ALL\);/
    condition: any of them
}

rule md5_39ca2651740c2cef91eb82161575348b {
    strings: $ = /if\(md5\(@\$_COOKIE\[..\]\)=='.{32}'\) \(\$_=@\$_REQUEST\[.\]\).@\$_\(\$_REQUEST\[.\]\);/
    condition: any of them
}

rule md5_6eb201737a6ef3c4880ae0b8983398a9 {
    strings:
        $ = "if(md5(@$_COOKIE[qz])=="
        $ = "($_=@$_REQUEST[q]).@$_($_REQUEST[z]);"
    condition: all of them
}

rule md5_d201d61510f7889f1a47257d52b15fa2 {
    strings: $ = "@eval(stripslashes($_REQUEST[q]));"
    condition: any of them
}

rule md5_28690a72362e021f65bb74eecc54255e {
    strings: $ = "curl_setopt($ch, CURLOPT_POSTFIELDS,http_build_query(array('data'=>$data,'utmp'=>$id)));"
    condition: any of them
}

rule overwrite_globals_hack {
    strings: $ = /\$GLOBALS\['[^']{,20}'\]=Array\(/
    condition: any of them
}

rule md5_4adef02197f50b9cc6918aa06132b2f6 {
    /* { eval($cco37(${ $kasd1}[ 'n46b398' ] ) );} */
    strings: $ = /\{\s*eval\s*\(\s*\$.{1,5}\s*\(\$\{\s*\$.{1,5}\s*\}\[\s*'.{1,10}'\s*\]\s*\)\s*\);\}/
    condition: any of them
}

rule obfuscated_globals {
    /* $GLOBALS['y63581'] = "\x43 */
    strings: $ = /\$GLOBALS\['.{1,10}'\] = "\\x/
    condition: any of them
}

rule md5_b3ee7ea209d2ff0d920dfb870bad8ce5 {
    strings:
        $ = /\$mysql_key\s*=\s*@?base64_decode/
        $ = /eval\(\s*\$mysql_key\s*\)/
    condition: all of them
}

rule md5_023a80d10d10d911989e115b477e42b5 {
    strings: $ = /chr\(\d{,3}\)\.\"\"\.chr\(\d{,3}\)/
    condition: any of them
}