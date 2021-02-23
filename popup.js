chrome.tabs.query({active: true, currentWindow: true},function(tab){
var grabheader=chrome.extension.getBackgroundPage();
recHeaders=grabheader.headers[tab[0].id];
console.log(recHeaders);
if(recHeaders.responseHeaders.find((a=>a.name.toLowerCase()==='content-security-policy')&&(a=>a.value.includes('default-src *'))))
       {
           main.innerHTML+="<td>Content security policy is insecure</td>";}
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
{
    if(recHeaders.responseHeaders.find(a=>a.value ==='1'))
    main.innerHTML+="<td> x-xss-protection is strong </td>"
}
else
main.innerHTML+="<td> x-xss-protection doesn't exist </td>"
if(recHeaders.responseHeaders.find(a=>a.name.toLowerCase()==='x-content-type-options'))
{
   if(recHeaders.responseHeaders.find(a=>a.value.toLowerCase()==='nosniff'))
   main.innerHTML+="<td> x-content-type-options is strong</td>"
}
else
main.innerHTML+="<td> x-content-type-options doesn't exist </td>"
});
