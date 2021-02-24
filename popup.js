var chrometabs;
chrome.tabs.query({active: true, currentWindow: true},function(tab){
    chrometabs=tab[0].id;
    var grabheader=chrome.extension.getBackgroundPage();
    console.log(grabheader.secureheaders[tab[0].id]);
    if(typeof grabheader.secureheaders[tab[0].id] == "undefined")
    errorbody.innerHTML= "Header not captured, please refresh the page or clear cache with CTRL+F5.";
else{
    main.innerHTML="<colgroup><col span=\"1\"><col span=\"1\"><col span=\"1\" style=\"width:15%\"></colgroup><tr><th>Header</th><th>Value</th><th>Config</tr>";
    recHeaders=grabheader.secureheaders[tab[0].id];
if(recHeaders.includes("undefined"))
recHeaders=recHeaders.replace("undefined", "");
logs=grabheader.headers[tab[0].id];
console.log(logs);
console.log(recHeaders);
main.innerHTML+=recHeaders;
}
});
window.onload=function(){
document.getElementById('opentab').addEventListener('click', tabopener, false);

function tabopener (e) {
  e.preventDefault();
  
  chrome.tabs.create(
    {
      url: chrome.extension.getURL("explanationtab.html#"+chrometabs)
    }
  );
}
}
