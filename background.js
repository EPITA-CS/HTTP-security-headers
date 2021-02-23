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
}
else
secureheaders[details.tabId]+="<td> Content-Security-Policy </td><td>missing</td>";
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


},{urls: ["<all_urls>"],types:["main_frame"]},["responseHeaders"]);

chrome.tabs.onRemoved.addListener(function(tabId,removeInfo)
{
delete headers[tabId];
});