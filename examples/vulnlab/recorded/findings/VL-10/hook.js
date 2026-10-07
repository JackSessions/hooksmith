function hostMatch(pat, host) {
  pat = String(pat).toLowerCase(); host = String(host).toLowerCase();
  if (pat === host) return true;
  if (pat.indexOf("*.") === 0) { return host.slice(host.indexOf(".")) === pat.slice(1) && host.split(".").length === pat.split(".").length; }
  return false;
}
function certCoversHost(session, host) {
  try {
    var leaf = Java.cast(session.getPeerCertificates()[0], Java.use("java.security.cert.X509Certificate"));
    var sans = leaf.getSubjectAlternativeNames();
    if (sans !== null) {
      var it = sans.iterator();
      while (it.hasNext()) {
        var e = Java.cast(it.next(), Java.use("java.util.List"));
        if (hostMatch(e.get(1), host)) return true;
      }
    }
    var m = /CN=([^,]+)/.exec(String(leaf.getSubjectDN().getName()));
    return !!(m && hostMatch(m[1], host));
  } catch (e) { return null; }
}
function hex(b){var s='';for(var i=0;i<b.length;i++){s+=('0'+(b[i]&0xff).toString(16)).slice(-2);}return s;}
Java.perform(function () {
  var C = Java.use("com.hooksmith.vulnlab.AllowAllVerifier");
  C.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function () {
    console.log("HS|" + JSON.stringify({event: "call"}));
    var r = this.verify.apply(this, arguments);
    var cm = null;
    try { cm = certCoversHost(arguments[1], arguments[0]); } catch (e) {}
    try { console.log("HS|" + JSON.stringify({event: "hostname", host: String(arguments[0]), result: !!r, cert_matches: cm})); } catch (e) {}
    return r;
  };
  console.log("HS|" + JSON.stringify({event: "ready"}));
});
