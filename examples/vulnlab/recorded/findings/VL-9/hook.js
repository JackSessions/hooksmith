function tlsInfo(chain, accepted) {
  var o = {event: "tls_chain", accepted: accepted};
  try {
    var leaf = Java.cast(chain[0], Java.use("java.security.cert.X509Certificate"));
    o.subject = String(leaf.getSubjectDN().getName()).slice(0, 120);
    o.issuer = String(leaf.getIssuerDN().getName()).slice(0, 120);
    o.self_signed = o.subject === o.issuer;
    try { leaf.checkValidity(); o.expired = false; } catch (e) { o.expired = true; }
    o.chain_len = chain.length;
  } catch (e) { o.err = String(e).slice(0, 120); }
  return o;
}
function hex(b){var s='';for(var i=0;i<b.length;i++){s+=('0'+(b[i]&0xff).toString(16)).slice(-2);}return s;}
Java.perform(function () {
  var C = Java.use("com.hooksmith.vulnlab.StrictTrustManager");
  C.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String').implementation = function () {
    console.log("HS|" + JSON.stringify({event: "call"}));
    var r;
    try {
      r = this.checkServerTrusted.apply(this, arguments);
    } catch (e) {
      try { console.log("HS|" + JSON.stringify(tlsInfo(arguments[0], false))); } catch (x) {}
      throw e;
    }
    try { console.log("HS|" + JSON.stringify(tlsInfo(arguments[0], true))); } catch (x) {}
    return r;
  };
  console.log("HS|" + JSON.stringify({event: "ready"}));
});
