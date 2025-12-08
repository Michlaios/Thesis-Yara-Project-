rule credit_card_regex {
    strings: $ = "RegExp(\"[0-9]{13,16}\")"
    condition: any of them
}

rule Trafficanalyzer_js {
    strings: $ = "z=x['length'];for(i=0;i<z;i++){y+=String['fromCharCode'](x['charCodeAt'](i)-10) }w=this['unescape'](y);this['eval'](w);"
    condition: any of them
}

rule atob_js {
    strings: $ = "this['eval'](this['atob']('"
    condition: any of them
}

rule thetech_org_js {
    strings: $ = "|RegExp|onepage|checkout|"
    condition: any of them
}