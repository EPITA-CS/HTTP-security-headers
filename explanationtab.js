var url=window.location.href;
var tabid=url.split('#')[1];
console.log(tabid);
var pagedata="";
var grabber=chrome.extension.getBackgroundPage();
var urlname=grabber.headers[tabid].url;
document.getElementById("urlhere").innerHTML=urlname;
console.log(grabber.headers[tabid].url);
document.getElementById("title").innerHTML="<h2>Heading this is:</h2>";
var cspdirs=["default-src","script-src","child-src","connect-src","font-src","frame-src","img-src","manifest-src","media-src","object-src","prefect-src","script-src-elem","script-src-attr","style-src","style-src-elem","style-src-attr","worker-src","base-uri","plugin-types","sandbox","form-action","frame-ancestors","navigate-to"];
var params=["none","self","star","inline","eval","hashes","data","local"];    
for(x=0;x<cspdirs.length;x++)
    {
        for(y=0;y<params.length;y++)
        {
            //grabber.headers[tabid]["csp"][cspdirs[x]]={}; 
        if(grabber.headers[tabid]["csp"][cspdirs[x]][params[y]]===1)
        {
            console.log(grabber.headers[tabid]["csp"][cspdirs[x]][params[y]])
            if(cspdirs[x]==="default-src")
            {
                switch(params[y])
                {
                    case "none":pagedata+="<p>This is a strong configuration as the default-src directive is used when any specific fetch directive is missing. This means that if any type of resource does not have specified sources for fetching then the resource will not be fetched at all.</p>";
                                break;
                    case "self":pagedata+="<p>This is a strong configuration as it means that if any type of resource does not have specified sources for fetching then the resource can only be fetched from the same domain.</p>";
                    break;
                    case "star":pagedata+="<p>This is a weak configuration just because.</p>";
                    break;
                    default: pagedata+="<p>No switch match</p>";
                }
            }
            
        }
    }
}
console.log(pagedata);
document.getElementById("fill").innerHTML=pagedata;
