function hex(b){var s='';for(var i=0;i<b.length;i++){s+=('0'+(b[i]&0xff).toString(16)).slice(-2);}return s;}
Java.perform(function () {
  var C = Java.use("com.hooksmith.vulnlab.DeadCode");
  var inTarget = 0;
  var KS = Java.use("javax.crypto.spec.SecretKeySpec");
  KS.$init.overload('[B', 'java.lang.String').implementation = function (k, alg) {
    if (inTarget > 0) { try { console.log("HS|" + JSON.stringify({event: "key", hex: hex(k), algorithm: String(alg)})); } catch (e) {} }
    return this.$init(k, alg);
  };
  C.hiddenKey.overload().implementation = function () {
    inTarget++;
    try {
      console.log("HS|" + JSON.stringify({event: "call"}));
      try { for (var i = 0; i < arguments.length; i++) { var a = arguments[i]; if (a && a.length !== undefined && typeof a !== 'string' && a.length > 0 && typeof a[0] === 'number') { console.log("HS|" + JSON.stringify({event: "key", hex: hex(a), via: "argument"})); } } } catch (e) {}
      var r = this.hiddenKey.apply(this, arguments);
      return r;
    } finally { inTarget--; }
  };
  console.log("HS|" + JSON.stringify({event: "ready"}));
});
