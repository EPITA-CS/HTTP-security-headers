chrome.tabs.query({active: true, currentWindow: true},function(tab){
    var grabheader=chrome.extension.getBackgroundPage();
recHeaders=grabheader.headers[tab[0].id];
console.log(recHeaders);
if(recHeaders.responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes('default-src none'))))
{ 
    main.innerHTML+="<tr><td>Content-Security-Policy</td><td> insecure </td></tr>"
    //if((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes('default-src self')))
    //main.innerHTML+="<tr><td>Content-Security-Policy</td><td> star </td></tr>"
//document.getElementById("headerid").innerHTML+="CSP exists";

