package utils

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

// 判断所给路径是否为文件夹
func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

// 判断所给路径是否为文件
func IsFile(path string) bool {
	return !IsDir(path)
}

// 读取文件并返回一个字符串切片
func ReadFileAsLine(path string) ([]string, error) {
	lineSlice := make([]string, 0)

	if !IsFile(path) {
		return nil, os.ErrNotExist
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}

	buf := bufio.NewReader(file)
	for {
		line, err := buf.ReadString('\n')
		line = strings.TrimSpace(line)
		lineSlice = append(lineSlice, line)
		if err != nil {
			if err == io.EOF {
				break
			} else {
				return nil, err
			}
		}
	}

	return lineSlice, nil
}

// 读取文件的前n个字节
func ReadFileN(path string, n int) ([]byte, error) {
	data := make([]byte, n)

	if !IsFile(path) {
		return nil, os.ErrNotExist
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0666)
	if err != nil {
		return nil, err
	}

	file.Read(data)

	return data, nil
}
