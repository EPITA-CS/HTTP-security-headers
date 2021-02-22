
/* var currentSettings; */

var headers = {};

var filters = {
  urls: ["<all_urls>"],
  /* types: ["main_frame"] */
};

/* headers received */
chrome.webRequest.onHeadersReceived.addListener(function(details) {
headers[details.tabId] = headers[details.tabId] || {};
headers[details.tabId] = details;
}, filters, ["responseHeaders"]);

/* remove tab data from headers object when tab is onRemoved */
chrome.tabs.onRemoved.addListener(function(tabId, removeInfo) {
	delete headers[tabId];
});

/*function get_options() {
  chrome.storage.sync.get(
 		function (settings) {
 			currentSettings = settings;
 		}
 	);
}
get_options();*/