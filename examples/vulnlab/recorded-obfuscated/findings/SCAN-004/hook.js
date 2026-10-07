function hex(b){var s='';for(var i=0;i<b.length;i++){s+=('0'+(b[i]&0xff).toString(16)).slice(-2);}return s;}
Java.perform(function () {
  var C = Java.use("b");
  C.a.overload('java.lang.String').implementation = function () {
    console.log("HS|" + JSON.stringify({event: "call"}));
    try { for (var i = 0; i < arguments.length; i++) { var a = arguments[i]; if (a !== null && a !== undefined) { var s = String(a); if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) { console.log("HS|" + JSON.stringify({event: "url", url: s})); } } } } catch (e) {}
    var r = this.a.apply(this, arguments);
    try { if (r !== null && r !== undefined) { var rs = String(r); if (/^[a-z][a-z0-9+.-]*:\/\//i.test(rs)) { console.log("HS|" + JSON.stringify({event: "url", url: rs})); } } } catch (e) {}
    return r;
  };
  console.log("HS|" + JSON.stringify({event: "ready"}));
});
