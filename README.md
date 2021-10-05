# pocV
尝试打造一个兼容xray和nuclei的poc扫描框架，某知识星球作业

## Feature
- 支持ceye.io和dnslog.cn作为反连平台
## TODO
- [x] xray
- [ ] nuclei

## Reference
- [jjf012/gopoc](https://github.com/jjf012/gopoc)
- [projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei)

## Build
```
go build  -ldflags "-w -s" cmd/pocV/pocV.go
```

## Example
xray
```
pocV run --debug -t http://example.com -p ./tests/xray/rule_test.yml
pocV run --debug -t http://example.com -P ./tests/xray/*
pocV run --debug -T target.txt -p ./tests/xray/rule_test.yml
pocV run --debug -T target.txt -P ./tests/xray/*
```
nuclei
```
TODO
```