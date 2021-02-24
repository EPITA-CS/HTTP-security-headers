var url=window.location.href;
var tabid=url.split('#')[1];
console.log(tabid);
var grabber=chrome.extension.getBackgroundPage();
document.getElementById("urlhere").innerHTML=grabber.headers[tabid].url;
document.getElementById("fill").innerHTML=grabber.expheaders[tabid];
