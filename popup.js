chrome.tabs.query({active: true, currentWindow: true},function(tab){
    var grabheader=chrome.extension.getBackgroundPage();
recHeaders=grabheader.headers[tab[0].id];
console.log(recHeaders);
if(recHeaders.responseHeaders.find(a=>a.name.toLowerCase()==='content-security-policy'))
{ 
 if(recHeaders.responseHeaders.find(a=>a.value.toLowerCase()==='default-src'))
       {main.innerHTML+="<td> Not a strong CSP </td>"
           if(recHeaders.responseHeaders.find(a=>a.value.toLowerCase()==='default-src *'))
           main.innerHTML+="<td> Not a strong CSP </td>";}
}
else
main.innerHTML+="<td> Content-Security-Policy missing </td>"
//document.getElementById("headerid").innerHTML+="CSP missing";
if(recHeaders.responseHeaders.find(a=>a.name.toLowerCase()==='strict-transport-security'))
main.innerHTML+="<td> HSTS exists </td>"
//document.getElementById("headerid").innerHTML+="HSTS exists";
else
main.innerHTML+="<td> HSTS doesn't exists </td>"
//document.getElementById("headerid").innerHTML+="HSTS missing";
if(recHeaders.responseHeaders.find(a=>a.name.toLowerCase()==='x-frame-options'))
{
 if(recHeaders.responseHeaders.find(a=>a.value.toUpperCase()==='DENY'))
 main.innerHTML+="<td> x-frame-options is strong </td>"
}
else
main.innerHTML+="<td> x-frame-options doesn't exist </td>"
if(recHeaders.responseHeaders.find(a=>a.name.toLowerCase()==='x-xss-protection'))
main.innerHTML+="<td> x-xss-protection exists </td>"
else
main.innerHTML+="<td> x-xss-protection doesn't exist </td>"





});