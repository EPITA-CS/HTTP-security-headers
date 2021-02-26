var url=window.location.href;
var tabid=url.split('#')[1];
var pagedata="";
var numb=0;
var grabber=chrome.extension.getBackgroundPage();
var urlname=grabber.headers[tabid].url;
document.getElementById("urlhere").innerHTML=urlname;
console.log(grabber.headers[tabid].url);
document.getElementById("title").innerHTML="<h2>Results for:</h2>";
var cspdirs=["default-src","script-src","child-src","connect-src","font-src","frame-src","img-src","manifest-src","media-src","object-src","prefect-src","script-src-elem","script-src-attr","style-src","style-src-elem","style-src-attr","worker-src","base-uri","plugin-types","sandbox","form-action","frame-ancestors","navigate-to"];
var params=["star","inline","eval","hashes","data","blob"];    
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
        {   numb++;
            cspheader=1;
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
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="child-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("childstar").className ="show";
                    break;
                    case "inline":document.getElementById("childinline").className ="show";
                    break;
                    case "eval":document.getElementById("childeval").className ="show";
                    break;
                    case "hashes":document.getElementById("childhashes").className ="show";
                    break;
                    case "data":document.getElementById("childdata").className ="show";
                    break;
                    case "blob":document.getElementById("childblob").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="connect-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("connectstar").className ="show";
                    break;
                    case "inline":document.getElementById("connectinline").className ="show";
                    break;
                    case "eval":document.getElementById("connecteval").className ="show";
                    break;
                    case "hashes":document.getElementById("connecthashes").className ="show";
                    break;
                    case "data":document.getElementById("connectdata").className ="show";
                    break;
                    case "blob":document.getElementById("connectblob").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="font-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("fontstar").className ="show";
                    break;
                    case "inline":document.getElementById("fontinline").className ="show";
                    break;
                    case "eval":document.getElementById("fonteval").className ="show";
                    break;
                    case "hashes":document.getElementById("fonthashes").className ="show";
                    break;
                    case "data":document.getElementById("fontdata").className ="show";
                    break;
                    case "blob":document.getElementById("fontblob").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="frame-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("framestar").className ="show";
                    break;
                    case "inline":document.getElementById("frameinline").className ="show";
                    break;
                    case "eval":document.getElementById("frameeval").className ="show";
                    break;
                    case "hashes":document.getElementById("framehashes").className ="show";
                    break;
                    case "data":document.getElementById("framedata").className ="show";
                    break;
                    case "blob":document.getElementById("frameblob").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="img-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("imagestar").className ="show";
                    break;
                    case "inline":document.getElementById("imageinline").className ="show";
                    break;
                    case "eval":document.getElementById("imageeval").className ="show";
                    break;
                    case "hashes":document.getElementById("imagehashes").className ="show";
                    break;
                    case "data":document.getElementById("imagedata").className ="show";
                    break;
                    case "blob":document.getElementById("imageblob").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="manifest-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("manifeststar").className ="show";
                    break;
                    case "inline":document.getElementById("manifestinline").className ="show";
                    break;
                    case "eval":document.getElementById("manifesteval").className ="show";
                    break;
                    case "hashes":document.getElementById("manifesthashes").className ="show";
                    break;
                    case "data":document.getElementById("manifestdata").className ="show";
                    break;
                    case "blob":document.getElementById("manifestblob").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="media-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("mediastar").className ="show";
                    break;
                    case "inline":document.getElementById("mediainline").className ="show";
                    break;
                    case "eval":document.getElementById("mediaeval").className ="show";
                    break;
                    case "hashes":document.getElementById("mediahashes").className ="show";
                    break;
                    case "data":document.getElementById("mediadata").className ="show";
                    break;
                    case "blob":document.getElementById("mediablob").className ="show";
                    break;
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="object-src")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("objectstar").className ="show";
                    break;
                    case "inline":document.getElementById("objectinline").className ="show";
                    break;
                    case "eval":document.getElementById("objecteval").className ="show";
                    break;
                    case "hashes":document.getElementById("objecthashes").className ="show";
                    break;
                    case "data":document.getElementById("objectdata").className ="show";
                    break;
                    case "blob":document.getElementById("objectblob").className ="show";
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
                    default:
                    break;
                }
            }
            if(cspdirs[x]==="frame-ancestors")
            {
                switch(params[y])
                {
                    case "star":document.getElementById("frame-ancestorsstar").className ="show";
                    break;
                    case "inline":document.getElementById("frame-ancestorsinline").className ="show";
                    break;
                    case "eval":document.getElementById("frame-ancestorseval").className ="show";
                    break;
                    case "hashes":document.getElementById("frame-ancestorshashes").className ="show";
                    break;
                    case "data":document.getElementById("frame-ancestorsdata").className ="show";
                    break;
                    case "blob":document.getElementById("frame-ancestorsblob").className ="show";
                    break;
                    default:
                    break;
                }
            }
        }
    }}}
}
if(cspheader===1){
document.getElementById("cspheader").className="show";
}
if(grabber.headers[tabid].hsts===0)
{
    numb++;
    document.getElementById("hstsheader").className="show";
    document.getElementById("hstsmiss").className ="show";
}
if(grabber.headers[tabid].hsts.maxage===0){
    numb++;
    document.getElementById("hstsheader").className ="show";
    document.getElementById("hstsmax0").className ="show";   
}
if(grabber.headers[tabid].hsts.maxage===1){
    numb++;
    document.getElementById("hstsheader").className ="show";
    document.getElementById("hstsmax1").className ="show";   
}
if(grabber.headers[tabid].xss===0)
{
    numb++;
    document.getElementById("xssheader").className ="show";
    document.getElementById("xssmiss").className ="show";
}
if(grabber.headers[tabid].xss.filteroff===1){
    numb++;
    document.getElementById("xssheader").className ="show";
    document.getElementById("xsspro").className="show";
}
if(grabber.headers[tabid].xfo===0){
    numb++;
    document.getElementById("xframeheader").className ="show";
    document.getElementById("xframe").className="show";
}
if(grabber.headers[tabid].xct.sniff===1){
    numb++;
    document.getElementById("xcontentheader").className ="show";
    document.getElementById("xcontent").className="show";   
}
if(grabber.headers[tabid].rp.owco===1){
    numb++;
    document.getElementById("refferheader").className ="show";
    document.getElementById("owco").className="show";   
}
if(grabber.headers[tabid].rp.unsafeurl===1){
    numb++;
    document.getElementById("refferheader").className ="show";
    document.getElementById("referrerurl").className="show";   
}
if(grabber.headers[tabid].fp.star===1){
    numb++;
    document.getElementById("featureheader").className ="show";
    document.getElementById("featurepol").className="show";   
}
if(grabber.headers[tabid].acma.long===1){
    numb++;
    document.getElementById("acmaheader").className ="show";
    document.getElementById("acma").className="show";   
}
console.log(pagedata);
var b = document.querySelector("button");
b.setAttribute("data-share-text",grabber.headers[tabid].url+" has "+numb+" weak security headers. Report this to the website administrator. You can find the security of the headers of any website you visit using the open source browser extension: HTTP Security Headers");
