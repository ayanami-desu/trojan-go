#!/usr/bin/env bash

mkdir -p release

rm -f ./release/*
v=$1
if [ -z "$v" ]; then
  echo "Version number cannot be null. Run with v=[version] release.sh"
  exit 1
fi

output="{{.Dir}}-{{.OS}}-{{.Arch}}-v$v"

echo "Compiling:"

os="windows linux"
arch="amd64 arm64"

CGO_ENABLED=0 gox -tags "custom" -ldflags="-s -w -buildid=" -os="$os" -arch="$arch" -output="$output"
mv trojan-go-* ./release
cd ./release
FILES=$(find . -type f)
for file in $FILES; do
  filename=$(basename "$file")
  extension="${filename##*.}"
  if [ "$extension" != "zip" ]; then
    zip_name=$(basename "$file" ".$extension")
    if [ "$extension" == "exe" ]; then
      upx -o "trojan.exe" "$file"
      zip -q "$zip_name.zip" "trojan.exe"
    else
      upx -o "trojan" "$file"
      zip -q "$zip_name.zip" "trojan"
    fi
    rm -rf "$file"
  fi
done
