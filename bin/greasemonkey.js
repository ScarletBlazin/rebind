// ==UserScript==
// @name           ActionTec POST2GET
// @namespace      http://gremlin.googlecode.com
// @description    Converts form POSTs into form GETs
// @include        *
// ==/UserScript==

for(var i=0; i<document.forms.length; i++)
{
    document.forms[i].method = "GET";
}
