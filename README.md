# pocV
一个兼容xray V1和nuclei的poc扫描框架，某知识星球作业

## Feature
- 支持请求缓存，加快请求速度
- 支持ceye.io和dnslog.cn作为反连平台
- 支持tag子命令为xray/nuclei的poc添加/删除tag，tag可用于筛选poc
## TODO
- [x] xrayV1
- [x] nuclei
- [x] 使用tag筛选poc
## Reference
- [jjf012/gopoc](https://github.com/jjf012/gopoc)
- [jweny/pocassist](https://github.com/jweny/pocassist)
- [boyhack/w14scan](https://github.com/boy-hack)
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

## Usage
```bash
# 安装pocV
git clone --recurse-submodules https://github.com/WAY29/pocV
go build  -ldflags "-w -s" cmd/pocV/pocV.go
# 更新所有的poc
git submodule update --remote --recursive
```

## Example
run
```bash
# 运行单个poc
pocV run -t http://example.com -p ./pocs/test/xray/rule_test.yml
# 运行文件夹下多个poc
pocV run -t http://example.com -P ./pocs/test/nuclei/*
pocV run -t http://example.com -P ./pocs/nuclei/*
pocV run -t http://example.com -P ./pocs/xray/pocs/*
# 指定多个目标
pocV run -T target.txt -p ./pocs/test/xray/rule_test.yml
# 通过tag过滤目标
pocV run -T target.txt --tag test -p ./pocs/test/xray/*
```
tag
```bash
# 添加tag
pocV tag -p ./pocs/test/nuclei/tag_test.yml newtag
# 删除tag
pocV tag -p ./pocs/test/nuclei/tag_test.yml -r newtag
```