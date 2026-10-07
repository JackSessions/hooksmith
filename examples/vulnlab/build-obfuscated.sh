#!/usr/bin/env bash
# Builds vulnlab-obfuscated.apk: the same app, run through R8 in release/minify mode, so every class and method
# except MainActivity (which the manifest must be able to find) gets renamed to short synthetic names -- the same
# thing a real release build's R8/ProGuard pass does. Used to test HookSmith against obfuscated code.
# Needs: ./build.sh has been run at least once (reuses its compiled .class files) and R8 (ships with the SDK
# cmdline-tools, no separate download: $ANDROID_SDK_ROOT/cmdline-tools/latest/lib/r8.jar).
set -euo pipefail
cd "$(dirname "$0")"
SDK="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
JAR="$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar"
R8="$SDK/cmdline-tools/latest/lib/r8.jar"
[ -f "$R8" ] || { echo "r8.jar not found at $R8 -- run 'hooksmith avd setup' first"; exit 1; }
[ -d build/classes ] || { echo "run ./build.sh first"; exit 1; }

OUT=build-obf
rm -rf "$OUT" && mkdir -p "$OUT/dex"

cat > "$OUT/rules.pro" <<'PRO'
-keep class com.hooksmith.vulnlab.MainActivity { *; }
-keepattributes *Annotation*
-dontwarn **
-repackageclasses ''
PRO

java -cp "$R8" com.android.tools.r8.R8 --release --min-api 26 \
  --lib "$JAR" \
  --pg-conf "$OUT/rules.pro" \
  --pg-map-output "$OUT/mapping.txt" \
  --output "$OUT/dex" \
  $(find build/classes -name '*.class')

aapt2 () { "$BT/aapt2" "$@"; }
aapt2 link -o "$OUT/base.apk" -I "$JAR" --manifest AndroidManifest.xml --min-sdk-version 26 --target-sdk-version 33
(cd "$OUT/dex" && zip -qr ../base.apk classes.dex)
"$BT/zipalign" -f 4 "$OUT/base.apk" "$OUT/aligned.apk"
[ -f debug.keystore ] || keytool -genkeypair -keystore debug.keystore -storepass android -keypass android \
  -alias debug -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=HookSmith VulnLab" >/dev/null 2>&1
"$BT/apksigner" sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android --out vulnlab-obfuscated.apk "$OUT/aligned.apk"
echo "built $(pwd)/vulnlab-obfuscated.apk"
echo "name mapping: $(pwd)/$OUT/mapping.txt"
