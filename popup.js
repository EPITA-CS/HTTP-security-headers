chrome.tabs.query({active: true, currentWindow: true},function(tab){
    var grabheader=chrome.extension.getBackgroundPage();
recHeaders=grabheader.secureheaders[tab[0].id];
console.log(recHeaders);
main.innerHTML=recHeaders;
});
