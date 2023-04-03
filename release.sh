#!/usr/bin/env bash

mkdir -p build

rm -f ./build/*

output="{{.Dir}}-{{.OS}}-{{.Arch}}"

echo "Compiling:"
export GOFLAGS="-trimpath"

os="linux"
arch="amd64 arm64"
CGO_ENABLED=0 gox -tags "server" -ldflags="-s -w -buildid=" -os="$os" -arch="$arch" -output="$output-server"

os="windows linux"
arch="amd64 arm64"
CGO_ENABLED=0 gox -tags "client" -ldflags="-s -w -buildid=" -os="$os" -arch="$arch" -output="$output-client"

mv trojan-go-* ./build
cd ./build
FILES=$(find . -type f)
for file in $FILES; do
  filename=$(basename "$file")
  extension="${filename##*.}"
  if [ "$extension" != "zip" ]; then
    zip_name=$(basename "$file" ".$extension")
    if [ "$extension" == "exe" ]; then
      upx -o "trojan.exe" "$file"
      zip -q "$zip_name.zip" "trojan.exe"
      rm -f trojan.exe
    else
      upx -o "trojan" "$file"
      zip -q "$zip_name.zip" "trojan"
      rm -f trojan
    fi
    rm -f "$file"
  fi
done
