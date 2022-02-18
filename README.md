# pocV
一个兼容xray和nuclei的poc扫描框架，某知识星球作业

## Feature
- 支持请求缓存，加快请求速度
- 支持ceye.io和dnslog.cn作为反连平台
- 支持tag子命令为xray/nuclei的poc添加/删除tag，tag可用于筛选poc
## TODO
- [x] xray
- [x] nuclei
- [x] 使用tag筛选poc
## Reference
- [jjf012/gopoc](https://github.com/jjf012/gopoc)
- [jweny/pocassist](https://github.com/jweny/pocassist)
- [boyhack/w14scan](https://github.com/boy-hack)
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

## Build
```
go build  -ldflags "-w -s" cmd/pocV/pocV.go
```

## Example
run
```bash
# 运行单个poc
pocV run -t http://example.com -p ./test_pocs/xray/rule_test.yml
# 运行文件夹下多个poc
pocV run -t http://example.com -P ./test_pocs/nuclei/*
# 指定多个目标
pocV run -T target.txt -p ./test_pocs/xray/rule_test.yml
# 通过tag过滤目标
pocV run -T target.txt --tag test -p ./test_pocs/xray/*
```
tag
```bash
# 添加tag
pocV tag -p ./test_pocs/nuclei/tag_test.yml newtag
# 删除tag
pocV tag -p ./test_pocs/nuclei/tag_test.yml -r newtag
```