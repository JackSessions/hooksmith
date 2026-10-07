#!/usr/bin/env bash
# Builds vulnlab.apk with nothing but the Android SDK build tools and a JDK. Usage: ./build.sh
set -euo pipefail
cd "$(dirname "$0")"
SDK="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
BT="$(ls -d "$SDK"/build-tools/* | sort -V | tail -1)"
JAR="$(ls -d "$SDK"/platforms/android-* | sort -V | tail -1)/android.jar"
OUT=build
rm -rf "$OUT" && mkdir -p "$OUT/classes" "$OUT/dex"
"$BT/aapt2" link -o "$OUT/base.apk" -I "$JAR" --manifest AndroidManifest.xml --min-sdk-version 26 --target-sdk-version 33
javac --release 8 -Xlint:-options -cp "$JAR" -d "$OUT/classes" $(find src -name '*.java')
"$BT/d8" --lib "$JAR" --min-api 26 --output "$OUT/dex" $(find "$OUT/classes" -name '*.class')
(cd "$OUT/dex" && zip -q ../base.apk classes.dex)
"$BT/zipalign" -f 4 "$OUT/base.apk" "$OUT/aligned.apk"
[ -f debug.keystore ] || keytool -genkeypair -keystore debug.keystore -storepass android -keypass android \
  -alias debug -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=HookSmith VulnLab" >/dev/null 2>&1
"$BT/apksigner" sign --ks debug.keystore --ks-pass pass:android --key-pass pass:android --out vulnlab.apk "$OUT/aligned.apk"
echo "built $(pwd)/vulnlab.apk"
