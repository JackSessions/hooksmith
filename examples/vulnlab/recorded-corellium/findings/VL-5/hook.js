function hex(b){var s='';for(var i=0;i<b.length;i++){s+=('0'+(b[i]&0xff).toString(16)).slice(-2);}return s;}
Java.perform(function () {
  var C = Java.use("com.hooksmith.vulnlab.Cosmetics");
  var inTarget = 0;
  var R = Java.use("java.util.Random");
  ['nextInt', 'nextLong', 'nextBytes', 'nextDouble'].forEach(function (n) {
    if (!R[n]) return;
    R[n].overloads.forEach(function (ov2) {
      ov2.implementation = function () {
        if (inTarget > 0) { try { var impl = (String(this.getClass().getName()).indexOf('SecureRandom') !== -1) ? 'java.security.SecureRandom' : 'java.util.Random'; console.log("HS|" + JSON.stringify({event: "random", impl: impl, context: "pickConfettiColor"})); } catch (e) {} }
        return ov2.apply(this, arguments);
      };
    });
  });
  C.pickConfettiColor.overload().implementation = function () {
    inTarget++;
    try {
      console.log("HS|" + JSON.stringify({event: "call"}));
      var r = this.pickConfettiColor.apply(this, arguments);
      return r;
    } finally { inTarget--; }
  };
  console.log("HS|" + JSON.stringify({event: "ready"}));
});
