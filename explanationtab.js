var url=window.location.href;
var tabid=url.split('#')[1];
var pagedata="";
var grabber=chrome.extension.getBackgroundPage();
var urlname=grabber.headers[tabid].url;
document.getElementById("urlhere").innerHTML=urlname;
console.log(grabber.headers[tabid].url);
document.getElementById("title").innerHTML="<h2>Results for:</h2>";
var cspdirs=["default-src"]//,"script-src","child-src","connect-src","font-src","frame-src","img-src","manifest-src","media-src","object-src","prefect-src","script-src-elem","script-src-attr","style-src","style-src-elem","style-src-attr","worker-src","base-uri","plugin-types","sandbox","form-action","frame-ancestors","navigate-to"];
var params=["none","self","star","inline","eval","hashes","data","blob","local"];    
if(grabber.headers[tabid].csp===0)
{
    document.getElementById("cspmiss").className ="show";
}
for(x=0;x<cspdirs.length;x++)
    {
        for(y=0;y<params.length;y++)
        {
        if(grabber.headers[tabid]["csp"][cspdirs[x]])
        {
            if(grabber.headers[tabid]["csp"][cspdirs[x]][params[y]])
            {
            //grabber.headers[tabid]["csp"][cspdirs[x]]={}; 
        if(grabber.headers[tabid]["csp"][cspdirs[x]][params[y]]===1)
        {
            console.log(grabber.headers[tabid]["csp"][cspdirs[x]][params[y]])
            if(cspdirs[x]==="default-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("defaultstar").className ="show";
                    break;
                    case "inline":document.getElementById("defaultinline").className ="show";
                    break;
                    case "eval":document.getElementById("defaulteval").className ="show";
                    break;
                    case "hashes":document.getElementById("defaulthashes").className ="show";
                    break;
                    case "data":document.getElementById("defaultdata").className ="show";
                    break;
                    case "blob":document.getElementById("defaultblob").className ="show";
                    break;
                    case "local":document.getElementById("defaultlocal").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="script-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("scriptstar").className ="show";
                    break;
                    case "inline":document.getElementById("scriptinline").className ="show";
                    break;
                    case "eval":document.getElementById("scripteval").className ="show";
                    break;
                    case "hashes":document.getElementById("scripthashes").className ="show";
                    break;
                    case "data":document.getElementById("scriptdata").className ="show";
                    break;
                    case "blob":document.getElementById("scriptblob").className ="show";
                    break;
                    case "local":document.getElementById("scriptlocal").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="frame-ancestors")
            {
                switch(params[y])
                {
                    case "none":pagedata+="<div class=\"divider\"></div><p>This is a FA strong configuration as the default-src directive is used when any specific fetch directive is missing. This means that if any type of resource does not have specified sources for fetching then the resource will not be fetched at all.</p>";
                                break;
                    case "self":pagedata+="<div class=\"divider\"></div><p>This is a FA strong configuration as it means that if any type of resource does not have specified sources for fetching then the resource can only be fetched from the same domain.</p>";
                    break;
                    case "star":pagedata+="<div class=\"divider\"></div><p>This is a FA weak configuration just because.</p>";
                    break;
                    default: pagedata+="<div class=\"divider\"></div><p>No switch match</p>";
                }
            }
            
        }
    }}}
}
if(grabber.headers[tabid].hsts===0)
{
    document.getElementById("hstsmiss").className ="show";
}
if(grabber.headers[tabid].hsts.maxage===0){
    document.getElementById("hstsmax0").className ="show";   
}
if(grabber.headers[tabid].hsts.maxage===1){
    document.getElementById("hstsmax1").className ="show";   
}
if(grabber.headers[tabid].xss===0)
{
    document.getElementById("xssmiss").className ="show";
}
if(grabber.headers[tabid].xss.filteroff===1){
    document.getElementById("xsspro").className="show";
}
if(grabber.headers[tabid].xfo===0){
    document.getElementById("xframe").className="show";
}
if(grabber.headers[tabid].xct.sniff===1){
    document.getElementById("xcontent").className="show";   
}
if(grabber.headers[tabid].rp.owco===1){
    document.getElementById("owco").className="show";   
}
if(grabber.headers[tabid].rp.unsafeurl===1){
    document.getElementById("referrerurl").className="show";   
}
if(grabber.headers[tabid].fp.star===1){
    document.getElementById("featurepol").className="show";   
}
if(grabber.headers[tabid].acma.long===1){
    document.getElementById("acma").className="show";   
}
console.log(pagedata);
//document.getElementById("fill").innerHTML=pagedata;
