var headers={};
var secureheaders={};

chrome.webRequest.onHeadersReceived.addListener(function(details){
headers[details.tabId]=details;
},{urls: ["<all_urls>"],types: ["main_frame"]},["responseHeaders"]);

chrome.tabs.onRemoved.addListener(function(tabId,removeInfo)
{
delete headers[tabId];
});
