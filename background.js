var headers={};
var secureheaders={};

chrome.webRequest.onHeadersReceived.addListener(function(details){
console.log(details)
headers[details.tabId]=details.responseHeaders;
//headers[details.tabId].csp=headers[details.tabId].hsts=headers[details.tabId].xss=headers[details.tabId].xfo=headers[details.tabId].xct=headers[details.tabId].rp=headers[details.tabId].fp=headers[details.tabId].ect=0;
headers[details.tabId].url=details.url;
headers[details.tabId].csp=headers[details.tabId].hsts=headers[details.tabId].xss=headers[details.tabId].xfo=headers[details.tabId].xct=headers[details.tabId].rp=headers[details.tabId].fp=headers[details.tabId].ect=headers[details.tabId].acao=headers[details.tabId].acma=0;
var cspmisscount=trigger=0;
function stringstripper(str,check)
{
    var start=str.indexOf(check);
    if(str.includes(";",start))
    var end=str.indexOf(";",start);
    else
    var end=str.length;
    if (start !=-1 && end !=-1 &&  end  > start)
    return scriptstr= str.substring(start , end );
}
function cspchecker(str,dir)
{   
    headers[details.tabId]["csp"][dir]["none"]=headers[details.tabId]["csp"][dir]["self"]=headers[details.tabId]["csp"][dir]["star"]=headers[details.tabId]["csp"][dir]["inline"]=headers[details.tabId]["csp"][dir]["eval"]=headers[details.tabId]["csp"][dir]["hashes"]=headers[details.tabId]["csp"][dir]["data"]=headers[details.tabId]["csp"][dir]["blob"]=headers[details.tabId]["csp"][dir]["local"]=0;
    //headers[details.tabId]["csp"][dir].none=headers[details.tabId]["csp"][dir].self=headers[details.tabId]["csp"][dir].star=headers[details.tabId]["csp"][dir].inline=headers[details.tabId]["csp"][dir].eval=headers[details.tabId]["csp"][dir].hashes=headers[details.tabId]["csp"][dir].data=headers[details.tabId]["csp"][dir]["local"]=0;
    if(str.includes("'none'"))
    {secureheaders[details.tabId]+="<tr class=\"strong\"><td>Content-Security-Policy:</td><td>"+ dir+ " none </td><td><i class=\"fa fa-check\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].none=1;}
    if(str.includes("'self'"))
    {secureheaders[details.tabId]+="<tr class=\"strong\"><td>Content-Security-Policy:</td><td>"+ dir+ " self </td><td><i class=\"fa fa-check\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].self=1;}
    if(str.includes("*"))
    {secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td>"+ dir+ " * </td><td><i class=\"fa fa-times\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].star=1;}
    if(str.includes('unsafe-inline'))
    {secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td>"+ dir+ " unsafe-inline </td><td><i class=\"fa fa-times\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].inline=1;}
    if(str.includes('unsafe-eval'))
    {secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td>"+ dir+ " unsafe-eval </td><td><i class=\"fa fa-times\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].eval=1;}
    if(str.includes('unsafe-hashes'))
    {secureheaders[details.tabId]+="<tr class=\"medium\"><td>Content-Security-Policy:</td><td>"+ dir+ " unsafe-hashes </td><td><i class=\"fa fa-exclamation\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].hashes=1;}
    if(str.includes('data:'))
    {secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td>"+ dir+ " data scheme source </td><td><i class=\"fa fa-times\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].data=1;}
    if(str.includes('blob:'))
    {secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td>"+ dir+ " blob scheme source </td><td><i class=\"fa fa-times\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].blob=1;}
    if(str.includes('127.0.0.1'))
    {secureheaders[details.tabId]+="<tr class=\"medium\"><td>Content-Security-Policy:</td><td>"+ dir+ " source is local host </td><td><i class=\"fa fa-exclamation\"></i></td></tr>";
    headers[details.tabId]["csp"][dir].local=1;}
}
function callcsp(indexnum){
    var cspdirs=["default-src","script-src","child-src","connect-src","font-src","frame-src","img-src","manifest-src","media-src","object-src","prefect-src","script-src-elem","script-src-attr","style-src","style-src-elem","style-src-attr","worker-src","base-uri","plugin-types","sandbox","form-action","frame-ancestors","navigate-to"];
    headers[details.tabId]["csp"]={"default-src":{},"script-src":{},"child-src":{},"connect-src":{},"font-src":{},"frame-src":{},"img-src":{},"manifest-src":{},"media-src":{},"object-src":{},"prefect-src":{},"script-src-elem":{},"script-src-attr":{},"style-src":{},"style-src-elem":{},"style-src-attr":{},"worker-src":{},"base-uri":{},"plugin-types":{},"sandbox":{},"form-action":{},"frame-ancestors":{},"navigate-to":{}};       //idk if this empties the object
    for(x=0;x<cspdirs.length;x++)
    {
        if(headers[details.tabId][indexnum].value.includes(cspdirs[x]))
        {
            cspstr=stringstripper(headers[details.tabId][indexnum].value,cspdirs[x]);
            cspchecker(cspstr,cspdirs[x]);
        }
        if(!headers[details.tabId][indexnum].value.includes(cspdirs[x]))
        cspmisscount++;
    }
    secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td> missing "+cspmisscount+" CSP directives </td><td> <i class=\"fa fa-times\"></i></td></tr>"
}
for(i=0;i<headers[details.tabId].length;i++)
{
    if(headers[details.tabId][i].name==="content-security-policy")
    {
        if(!headers[details.tabId][i].value.includes("default-src"))
        trigger=1;
        headers[details.tabId].csp=1;
        callcsp(i);
    if(headers[details.tabId][i].value.includes("report-uri"))
    secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td> deprecated report-uri is used </td><td><i class=\"fa fa-times\"></i></td></tr>";
    }

    if(headers[details.tabId][i].name==="strict-transport-security")
    {
        headers[details.tabId].hsts=1;
        if(headers[details.tabId][i].value.includes("max-age=0"))
        {
            headers[details.tabId].hsts.maxage=0;
        secureheaders[details.tabId]+="<tr class=\"weak\"><td>Strict-Transport-Security:</td><td> max-age=0 </td><td> <i class=\"fa fa-times\"></i></td></tr>"}
        if(!headers[details.tabId][i].value.includes("max-age"))
        {headers[details.tabId].hsts.maxage=1;
        secureheaders[details.tabId]+="<tr class=\"weak\"><td>Strict-Transport-Security:</td><td> max-age missing </td><td> <i class=\"fa fa-times\"></i></td></tr>";}
        else{
            var newstr=headers[details.tabId][i].value.substring('max-age='.length);
            var num=parseInt(newstr);
            secureheaders[details.tabId]+="<tr class=\"strong\"><td>Strict-Transport-Security:</td><td> max-age is "+num+"</td><td><i class=\"fa fa-check\"></i></td></tr>";
            headers[details.tabId].hsts.maxage=2;
        }
        if(headers[details.tabId][i].value.includes("includeSubDomains"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td>Strict-Transport-Security:</td><td> includeSubDomains </td><td><i class=\"fa fa-check\"></i></td></tr>"
        else
        secureheaders[details.tabId]+="<tr class=\"medium\"><td>Strict-Transport-Security:</td><td> Missing includeSubDomains </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>";
    }

    if(headers[details.tabId][i].name==="x-xss-protection")
    {
        headers[details.tabId].xss=1;
        if(headers[details.tabId][i].value.includes("0"))
        {headers[details.tabId].xss.filteroff=1;
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> x-xss-protection </td><td> zero </td><td> <i class=\"fa fa-times\"></i></td></tr>";}
        else if(headers[details.tabId][i].value.includes("1; mode=block"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-xss-protection </td><td> one and mode is block </td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("1; report=http://"))
        secureheaders[details.tabId]+="<tr class=\"medium\"><td> x-xss-protection </td><td> URI is HTTP </td><td><i class=\"fa fa-exclamation\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("1; report=https://"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-xss-protection </td><td> URI is HTTPs </td><td><i class=\"fa fa-check\"></i></td></tr>";
    }

    if(headers[details.tabId][i].name==="x-frame-options")
    {
        headers[details.tabId].xfo=1;
        if(headers[details.tabId][i].value.includes("ALLOW-FROM"))
        secureheaders[details.tabId]+="<tr class=\"medium\"><td> x-frame-options </td><td> allow-from </td><td> <i class=\"fa fa-exclamation\"></i></td></tr>";
        if(headers[details.tabId][i].value.includes("SAMEORIGIN"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-frame-options </td><td> sameorigin </td><td><i class=\"fa fa-check\"></i></td></tr>";
        if(headers[details.tabId][i].value.includes("DENY"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-frame-options </td><td> deny </td><td><i class=\"fa fa-check\"></i></td></tr>";
    }

    if(headers[details.tabId][i].name==="x-content-type-options")
    {
        headers[details.tabId].xct=1;
        if(headers[details.tabId][i].value.includes("nosniff"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> x-content-type-options </td><td> nosniff </td><td><i class=\"fa fa-check\"></i> </td></tr>";
        else
        {
            headers[details.tabId].xct.sniff=1;
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> x-content-type-options </td><td> not nosniff </td><td><i class=\"fa fa-times\"></i></td></tr>";
        trigger=1;
    }
    }

    if(headers[details.tabId][i].name==="referrer-policy")
    {
        headers[details.tabId].rp=1;
        if(headers[details.tabId][i].value.includes("origin-when-cross-origin"))
        {headers[details.tabId].rp.owco=1;
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> referrer-policy </td><td> origin-when-cross-origin </td><td> <i class=\"fa fa-times\"></i></td></tr>";}
        else if(headers[details.tabId][i].value.includes("unsafe-url"))
        {headers[details.tabId].rp.unsafeurl=1;
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> referrer-policy</td><td>unsafe-url</td><td> <i class=\"fa fa-times\"></i></td></tr>";}
        else if(headers[details.tabId][i].value.includes("no-referrer"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>no-referrer</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("no-referrer-when-downgrade"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>no-referrer-when-downgrade</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes(" origin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>origin</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("same-origin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>same-origin</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("strict-origin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>strict-origin</td><td><i class=\"fa fa-check\"></i></td></tr>";
        else if(headers[details.tabId][i].value.includes("strict-origin-when-cross-origin"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> referrer-policy</td><td>strict-origin-when-cross-origin</td><td><i class=\"fa fa-check\"></i></td></tr>";
    }
    if(headers[details.tabId][i].name==="feature-policy")
    {
        headers[details.tabId].fp=1;
        if(headers[details.tabId][i].value.includes("*"))
        {secureheaders[details.tabId]+="<tr class=\"weak\"><td> feature-policy </td><td> * </td><td><i class=\"fa fa-times\"></i></td></tr>";
        trigger=1;
        headers[details.tabId].fp.star=1;}
        if(headers[details.tabId][i].value.includes("none"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> feature-policy </td><td> none </td><td><i class=\"fa fa-check\"></i></td></tr>";
        if(headers[details.tabId][i].value.includes("self"))
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> feature-policy </td><td> self </td><td><i class=\"fa fa-check\"></i></td></tr>";
    }
    
    if(headers[details.tabId][i].name==="expect-ct")
    {
        headers[details.tabId].ect=1;
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> expect-ct </td><td> exist </td><td><i class=\"fa fa-check\"></i></td></tr>";
    }

    if(headers[details.tabId][i].name==="access-control-allow-origin")
    {
       headers[details.tabId].acao=1;
       if(headers[details.tabId][i].value.includes("*"))
       secureheaders[details.tabId]+="<tr class=\"weak\"><td> access-control-allow-origin </td><td> * </td><td><i class=\"fa fa-times\"></i></td></tr>";
       if(headers[details.tabId][i].value.includes("null"))
       {
        if((headers[details.tabId][i].name==="access-control-allow-credentials") && (headers[details.tabId][i].value.includes("true")))
        secureheaders[details.tabId]+="<tr class=\"weak\"><td> access-control-allow-origin and access-control-allow-credentials</td><td> null and true </td><td><i class=\"fa fa-times\"></i></td></tr>";
        else
        secureheaders[details.tabId]+="<tr class=\"strong\"><td> access-control-allow-origin </td><td> null </td><td><i class=\"fa fa-check\"></i></td></tr>";
        }
       if(headers[details.tabId][i].value.includes("http://"))
       {
       if((headers[details.tabId][i].name==="access-control-allow-credentials") && (headers[details.tabId][i].value.includes("true")))
       secureheaders[details.tabId]+="<tr class=\"weak\"><td> access-control-allow-origin and access-control-allow-credentials</td><td> true </td><td><i class=\"fa fa-times\"></i></td></tr>";
       }

    }
    if(headers[details.tabId][i].name==="access-control-max-age")
    {   
        headers[details.tabId].acma=1
        if(headers[details.tabId][i].value.includes.substring('max-age='.length));
        newstr=newstr.substring('max-age='.length);
        var num=parseInt(newstr);
        if(num>1800)
        {headers[details.tabId].acma.long=1;
        secureheaders[details.tabId]+="<tr class=\"weak\"><td>access-control-max-age:</td><td> max-age is "+num+"</td><td><i class=\"fa fa-times\"></i></td></tr>";}
        else
        secureheaders[details.tabId]+="<tr class=\"strong\"><td>access-control-max-age:</td><td> max-age is "+num+"</td><td><i class=\"fa fa-check\"></i></td></tr>";
    }



}
if(headers[details.tabId].csp===0)
{trigger=1;
secureheaders[details.tabId]+="<tr class=\"weak\"><td>Content-Security-Policy:</td><td> non-existent </td><td> <i class=\"fa fa-times\"></i></td></tr>";}
if(headers[details.tabId].hsts===0)
{trigger=1;
secureheaders[details.tabId]+="<tr class=\"weak\"><td>Strict-Transport-Security:</td><td> non-existent </td><td> <i class=\"fa fa-times\"></i></td></tr>";}
if(headers[details.tabId].xss===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>x-xss-protection:</td><td> non-existent </td><td> <i class=\"fa fa-times\"></i></td></tr>";
if(headers[details.tabId].xfo===0)
{trigger=1;
secureheaders[details.tabId]+="<tr class=\"weak\"><td>x-frame-options:</td><td> non-existent </td><td> <i class=\"fa fa-times\"></i></td></tr>";}
if(headers[details.tabId].xct===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>x-content-type-options:</td><td> non-existent </td><td> <i class=\"fa fa-times\"></i></td></tr>";
if(headers[details.tabId].rp===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>referrer-policy:</td><td> non-existent </td><td> <i class=\"fa fa-times\"></i></td></tr>";
if(headers[details.tabId].fp===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>feature-policy:</td><td> non-existent </td><td> <i class=\"fa fa-times\"></i></td></tr>";
if(headers[details.tabId].ect===0)
secureheaders[details.tabId]+="<tr class=\"weak\"><td>Expect-ct:</td><td> non-existent </td><td> <i class=\"fa fa-times\"></i></td></tr>";

if(trigger===1)
{
    var opt = {
        type: 'basic',
        title: 'Security Headers Warning',
        message: 'Insecure or Misconfigured Headers Present.',
        iconUrl: "48.png"
      };
      chrome.notifications.create('notify', opt);
}

},{urls: ["<all_urls>"],types: ["main_frame"]},["responseHeaders"]);

chrome.tabs.onRemoved.addListener(function(tabId,removeInfo)
{
delete headers[tabId];
});
