var headers={};
var secureheaders={};

chrome.webRequest.onHeadersReceived.addListener(function(details){
console.log(details)
headers[details.tabId]=details.responseHeaders;
headers[details.tabId].csp=headers[details.tabId].hsts=headers[details.tabId].xss=headers[details.tabId].xfo=headers[details.tabId].xct=headers[details.tabId].rp.headers[details.tabId].fp=headers[details.tabId].ect=0;

for(i=0;i<headers[details.tabId].length;i++)
{
    if(headers[details.tabId][i].name==="content-security-policy") //all conditions aren't checked this is a sample
    {
        headers[details.tabId].csp=1;
        if(headers[details.tabId][i].value.includes("default-src 'none'"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td>Content-Security-Policy:</td><td> default-src none </td><td><i class=\"fa fa-check\"></i></td></tr>"
        if(headers[details.tabId][i].value.includes("default-src 'self'"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td>Content-Security-Policy:</td><td> default-src self </td><td> <i class=\"fa fa-check\"></i></td></tr>"
        if(headers[details.tabId][i].value.includes("default-src *"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td> default-src * </td> <td> <i class=\"fa fa-exclamation\"></i></td></tr>"
        if(!headers[details.tabId][i].value.includes("default-src"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td> default-src missing </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>";
    }  

    if(headers[details.tabId][i].name==="strict-transport-security")
    {
        headers[details.tabId].hsts=1;
        if(headers[details.tabId][i].value.includes("max-age=0"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td>Strict-Transport-Security:</td><td> max-age=0 </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>"
        if(!headers[details.tabId][i].value.includes("max-age"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td>Strict-Transport-Security:</td><td> max-age missing </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>"
        else{
            var newstr=headers[details.tabId][i].value.substring('max-age='.length);
            //newstr=newstr.substring('max-age='.length);
            var num=parseInt(newstr);
            secureheaders[details.tabId]+="<tr class=\"strong\"><td>Strict-Transport-Security:</td><td> max-age is "+num+"</td></tr>";
        }
        if(headers[details.tabId][i].value.includes("includeSubDomains"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td>Strict-Transport-Security:</td><td> includeSubDomains </td><td><i class=\"fa fa-check\"></i></td></tr>"
        else
        secureheaders[details.tabId]+="<tr class=\"weak\"><td>Strict-Transport-Security:</td><td> Missing includeSubDomains </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>";
    }

    if(headers[details.tabId][i].name==="x-xss-protection")
    {
        headers[details.tabId].xss=1;
        if(headers[details.tabId][i].value.includes("0"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> x-xss-protection </td><td> zero </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>";
        if(headers[details.tabId][i].value.includes("1; mode=block"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-xss-protection </td><td> one and mode is block </td><td><i class=\"fa fa-check\"></i></td></tr>";
        if(headers[details.tabId][i].value.includes("1; report=".urls))// fill this to get http/https 

        secureheaders[details.tabId]+="<tr class=\"weak\"><td> x-xss-protection </td><td> URI is HTTP </td><td><i class=\"fa fa-exclamation\"></i></td></tr>";
        else
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-xss-protection </td><td> URI is HTTPs </td><td><i class=\"fa fa-check\"></i></td></tr>";

    }

    if(headers[details.tabId][i].name==="x-frame-options")
    {
        headers[details.tabId].xfo=1;
        if(headers[details.tabId][i].value.includes("allow-from"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> x-frame-options </td><td> allow-from </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>";
        if(headers[details.tabId][i].value.includes("sameorigin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-frame-options </td><td> sameorigin </td><td><i class=\"fa fa-check\"></i></td></tr>";
        if(headers[details.tabId][i].value.includes("deny"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-frame-options </td><td> deny </td><td><i class=\"fa fa-check\"></i></td></tr>";
    }

    if(headers[details.tabId][i].name==="x-content-type-options")
    {
        headers[details.tabId].xct=1;
        if(headers[details.tabId][i].value.includes("nosniff"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-content-type-options </td><td> nosniff </td><td><i class=\"fa fa-check\"></i> </td></tr>";
        else
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-content-type-options </td><td> not nosniff </td><td><i class=\"fa fa-check\"></i></td></tr>";
    }

    if(headers[details.tabId][i].name==="referrer-policy")
    {
        headers[details.tabId].rp=1;
        if(headers[details.tabId][i].value.includes("origin-when-cross-origin"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> referrer-policy </td><td> origin-when-cross-origin </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("unsafe-url"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> referrer-policy</td><td>unsafe-url</td><td> <i class=\"fa fa-exclamation\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("no-referrer"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>no-referrer</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("no-referrer-when-downgrade"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>no-referrer-when-downgrade</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("origin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>origin</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("same-origin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>same-origin</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("strict-origin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>strict-origin</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("strict-origin-when-cross-origin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>strict-origin-when-cross-origin</td><td><i class=\"fa fa-check\"></i></td></tr>";
    }
    
    if(headers[details.tabId][i].name==="feature-policy")
    {
        headers[details.tabId].fp=1;
        if(headers[details.tabId][i].value.includes("camera *"))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> feature-policy </td><td> camera * </td></tr>";
        if(headers[details.tabId][i].value.includes("none"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> feature-policy </td><td> none </td></tr>";
        if(headers[details.tabId][i].value.includes("self"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> feature-policy </td><td> self </td></tr>";
    }

    if(headers[details.tabId][i].name==="expect-ct")
    {
        headers[details.tabId].ect=1;
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> expect-ct </td><td> exist </td></tr>";
    }
}
if(headers[details.tabId].csp===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td> non-existent </td></tr>";
if(headers[details.tabId].hsts===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>Strict-Transport-Security:</td><td> non-existent </td></tr>";
if(headers[details.tabId].xss===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>x-xss-protection:</td><td> non-existent </td></tr>";
if(headers[details.tabId].xfo===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>x-frame-options:</td><td> non-existent </td></tr>";
if(headers[details.tabId].xct===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>x-content-type-options:</td><td> non-existent </td></tr>";
if(headers[details.tabId].rp===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>referrer-policy:</td><td> non-existent </td></tr>";
if(headers[details.tabId].fp===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>feature-policy:</td><td> non-existent </td></tr>";
if(headers[details.tabId].ect===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>expect-ct:</td><td> non-existent </td></tr>";

},{urls: ["<all_urls>"],types: ["main_frame"]},["responseHeaders"]);

chrome.tabs.onRemoved.addListener(function(tabId,removeInfo)
{
delete headers[tabId];
});
