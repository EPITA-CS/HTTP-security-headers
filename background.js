var headers={};
var secureheaders={};
chrome.webRequest.onHeadersReceived.addListener(function(details){
headers[details.tabId]=details;
console.log(details);

if(headers[details.tabId].responseHeaders.find(a=>a.name.toLowerCase()==='content-security-policy'))
{
if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes('default-src none')))) //this check works
{ 
secureheaders[details.tabId]+="<tr class=\"strong\"><td>Content-Security-Policy:</td><td>default-src 'none'</td></tr>"}
else if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes('default-src *'))))
{
secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td> default-src * </td></tr>"
}
else if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes("default-src 'self'"))))
{
secureheaders[details.tabId]+="<tr class=\"strong\"><td>Content-Security-Policy:</td><td> default-src 'self' </td></tr>"
}
else if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes("script-src 'self'"))))
{
secureheaders[details.tabId]+="<tr class=\"strong\"><td>Content-Security-Policy:</td><td> script-src 'self' </td></tr>"
}
else if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes("script-src '*'"))))
{
secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td> script-src '*' </td></tr>"
}
}
else
secureheaders[details.tabId]+="<td> Content-Security-Policy </td><td>missing</td>";

if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-xss-protection' )))
{if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-xss-protection')&&(a=>a.value.includes("0"))))
secureheaders[details.tabId]+="<tr class=\"weak\"><td> x-xss-protection </td><td> zero </td></tr>";
else {
secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-xss-protection </td><td> 1</td></tr>";} 
if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-xss-protection')&&(a=>a.value.includes("mode=block"))))
secureheaders[details.tabId]+="<tr class=\"strong\"><td>x-xss-protection </td><td> block </td></tr>";    
}
secureheaders[details.tabId]+="<tr class = \"weak\"><td> x-xss-protection </td><td>missing</td></tr>";

if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-frame-options' )))
{if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-frame-options')&&(a=>a.value.includes("ALLOW-FROM"))))
secureheaders[details.tabId]+="<tr class=\"weak\"><td> x-frame-options </td><td> ALLOW-FROM </td></tr>";
else  if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-frame-options')&&(a=>a.value.includes("DENY"))))
secureheaders[details.tabId]+="<tr class=\"strong\"><td>x-frame-options </td><td> DENY </td></tr>";  
if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-frame-options')&&(a=>a.value.includes("SAMEORIGIN"))))
secureheaders[details.tabId]+="<tr class=\"strong\"><td>x-frame-options </td><td> SAMEORIGIN </td></tr>";
}
else
secureheaders[details.tabId]+="<tr class = \"weak\"><td> x-frame-options </td><td>missing</td></tr>";  

if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='expect-ct' )))
secureheaders[details.tabId]+="<tr class=\"strong\"><td>expect-ct </td><td> Present </td></tr>";
else
secureheaders[details.tabId]+="<tr class = \"weak\"><td> expect-ct </td><td>absent</td></tr>";  

if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='strict-transport-security')))
{if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='strict-transport-security')&&(a=>a.value.includes("max-age=0"))))
secureheaders[details.tabId]+="<tr class=\"weak\"><td> strict-transport-security </td><td> max-age is zero </td></tr>"; 
else {
secureheaders[details.tabId]+="<tr class=\"strong\"><td> strict-transport-security </td><td> max-age not zero</td></tr>";} 
if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='strict-transport-security')&&(a=>a.value.includes("includeSubDomains"))))
secureheaders[details.tabId]+="<tr class=\"strong\"><td>strict-transport-security </td><td> includeSubdomains </td></tr>"; 
}
else
secureheaders[details.tabId]+="<td> strict-transport-security </td><td>missing</td>";

if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-content-type-options')))
{
    if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='x-content-type-options')&&(a=>a.value.includes("nosniff"))))
    secureheaders[details.tabId]+="<tr class=\"strong\" ><td> x-content-type-options </td><td> nosniff</td></tr>";
    else 
    secureheaders[details.tabId]+="<tr class=\"weak\" ><td> x-content-type-options </td><td> none</td></tr>";
}
else
secureheaders[details.tabId]+="<tr class=\"weak\" ><td> x-content-type-options </td><td> missing </td></tr>"

if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='referrer-policy')))
{
    if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='referrer-policy')&&(a=>a.value.includes("unsafe-url"))))
    secureheaders[details.tabId]+="<tr class=\"weak\" ><td> referrer-policy </td><td> unsafe-url </td></tr>";
    else (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='referrer-policy')&&(a=>a.value.includes("origin-when-cross-origin")))) 
    secureheaders[details.tabId]+="<tr class=\"weak\" ><td> referrer-policy </td><td> origin-when-cross-origin </td></tr>";
}
else
secureheaders[details.tabId]+="<tr class=\"weak\" ><td> referrer-policy </td><td> missing </td></tr>"

if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='feature-policy')))
{
    if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='feature-policy')&&(a=>a.value.includes("camera *"))))
    secureheaders[details.tabId]+="<tr class=\"weak\" ><td> feature-policy </td><td> camera*  </td></tr>";
    else if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='feature-policy')&&(a=>a.value.includes("microphone *"))))
    secureheaders[details.tabId]+="<tr class=\"weak\" ><td> feature-policy </td><td> microphone *  </td></tr>";
    else if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='feature-policy')&&(a=>a.value.includes("self"))))
    secureheaders[details.tabId]+="<tr class=\"strong\" ><td> feature-policy </td><td> self  </td></tr>";
}
else
secureheaders[details.tabId]+="<tr class=\"weak\" ><td> feature-policy </td><td> missing </td></tr>"

if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='access-control-allow-origin')))
{
    if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='access-control-allow-origin')&&(a=>a.value.includes("*"))))
    secureheaders[details.tabId]+="<tr class=\"weak\" ><td> access-control-allow-origin </td><td> * </td></tr>"
    else if (headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='access-control-allow-origin')&&(a=>a.value.includes("null"))))
    {
    if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='access-control-allow-credentials')&&(a=>a.value.includes("true"))))
    secureheaders[details.tabId]+="<tr class=\"weak\" ><td> access-control-allow-origin and access-control-allow-credentials </td><td> null and true </td></tr>"
    else 
    secureheaders[details.tabId]+="<tr class=\"strong\" ><td> CORS </td><td> null </td></tr>"
    }
}
else
secureheaders[details.tabId]+="<tr class=\"weak\" ><td> access-control-allow-origin </td><td> missing </td></tr>"
},{urls: ["<all_urls>"],types:["main_frame"]},["responseHeaders"]);

chrome.tabs.onRemoved.addListener(function(tabId,removeInfo)
{
delete headers[tabId];
});