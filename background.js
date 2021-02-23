var headers={};
var secureheaders={};

chrome.webRequest.onHeadersReceived.addListener(function(details){
headers[details.tabId]=details;
console.log(details);
if(headers[details.tabId].responseHeaders.find(a=>a.name.toLowerCase()==='content-security-policy'))
{
if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes('default-src none')))) //this check works
{ 
    secureheaders[details.tabId]+="<tr><td>Content-Security-Policy:</td><td> default-src none </td></tr>"
}
if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes('default-src *'))))
{
    secureheaders[details.tabId]+="<tr><td>Content-Security-Policy:</td><td> default-src * </td></tr>"
}
if(headers[details.tabId].responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes("default-src 'self'"))))
{
    secureheaders[details.tabId]+="<tr><td>Content-Security-Policy:</td><td> default-src self </td></tr>"
}
}
else
secureheaders[details.tabId]+="<td> Content-Security-Policy </td><td>missing </td>";
console.log(secureheaders);
},{urls: ["<all_urls>"],types: ["main_frame"]},["responseHeaders"]);

chrome.tabs.onRemoved.addListener(function(tabId,removeInfo)
{
delete headers[tabId];
});
