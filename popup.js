chrome.tabs.query({active: true, currentWindow: true},function(tab){
    var grabheader=chrome.extension.getBackgroundPage();
recHeaders=grabheader.headers[tab[0].id];
console.log(recHeaders);
if(recHeaders.responseHeaders.find(a=>a.name.toLowerCase()==='content-security-policy'))
document.getElementById("headerid").innerHTML+="CSP exists";
else
document.getElementById("headerid").innerHTML+="CSP missing";
if(recHeaders.responseHeaders.find(a=>a.name.toLowerCase()==='strict-transport-security'))
document.getElementById("headerid").innerHTML+="HSTS exists";
else
document.getElementById("headerid").innerHTML+="HSTS missing";
});
