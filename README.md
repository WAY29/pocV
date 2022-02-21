# pocV
一个兼容xray V2 http poc和nuclei的poc扫描框架，某知识星球作业
A compatible with xray and nuclei poc framework

## Feature
- 支持请求缓存，加快请求速度 (Support request caching to speed up requests)
- 支持ceye.io和dnslog.cn作为反连平台 (Support ceye.io and dnslog.cn as dns platform)
- 支持tag子命令为xray/nuclei的poc添加/删除tag，tag可用于筛选poc (supports tag subcommand to add/remove tags for the xray/nucleis poc, and tag can be used to filter poc)
- 支持update子命令实现自我更新 (Support update subcommand to self-update)

## Short
- 支持大部分xray的函数，但不支持冷门函数: `faviconHash`，`toUintString` (Most xray functions are supported, but not the less popular ones: `faviconHash()`，`toUintString()`)
- 代码未经过大量测试，仅供学习 (The code is not heavily tested, just for learning)
## TODO
- [x] xrayV2 http poc
- [x] nuclei
- [x] 使用tag筛选poc (Filter the poc through tags)
## Reference
- [jjf012/gopoc](https://github.com/jjf012/gopoc)
- [jweny/pocassist](https://github.com/jweny/pocassist)
- [boyhack/w14scan](https://github.com/boy-hack)
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

## Usage
### github
```bash
# install pocV
git clone --recurse-submodules https://github.com/WAY29/pocV
go build  -ldflags "-w -s" ./cmd/pocV/
# update all pocs
git submodule update --remote --recursive
```
### release
```bash
```

## Example
run
```bash
# run single poc
pocV run -t http://example.com -p ./pocs/test/xray/rule_test.yml
# run multiple pocs
pocV run -t http://example.com -P ./pocs/test/nuclei/*
pocV run -t http://example.com -P ./pocs/nuclei/*
pocV run -t http://example.com -P ./pocs/xray/pocs/*
# Specify multiple targets
pocV run -T target.txt -p ./pocs/test/xray/rule_test.yml
# Filter the poc through tags
pocV run -T target.txt --tag test -p ./pocs/test/xray/*
```
tag
```bash
# add tag
pocV tag -p ./pocs/test/nuclei/tag_test.yml newtag
# remove tag
pocV tag -p ./pocs/test/nuclei/tag_test.yml -r newtag
```