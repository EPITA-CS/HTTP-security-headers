chrome.tabs.query({active: true, currentWindow: true},function(tab){
    var grabheader=chrome.extension.getBackgroundPage();
recHeaders=grabheader.headers[tab[0].id];
console.log(recHeaders);
document.getElementById("headerid").innerHTML+=recHeaders;
});